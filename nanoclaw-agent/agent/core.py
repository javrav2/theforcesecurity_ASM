"""
ReACT Agent Loop for NanoClaw Agent Framework

The core reasoning engine. Implements the Reason-Act-Observe cycle:
  1. Send context + tool schemas to LLM
  2. LLM reasons and selects tool(s) to call
  3. Execute tools (with guardrails)
  4. Feed results back to LLM
  5. Repeat until LLM decides it's done or hands off to another agent

Supports multi-agent handoffs: an agent can transfer control to a
specialized sub-agent, passing accumulated context.
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import anthropic

from agent.tools import ToolDef, ToolRegistry
from agent.guardrails import GuardrailEngine
from agent.tracing import Tracer, TokenUsage

logger = logging.getLogger("agent.core")


@dataclass
class Agent:
    """A specialized security agent with its own instructions, tools, and handoffs."""
    name: str
    instructions: str
    tool_names: Optional[List[str]] = None  # None = all tools
    model: str = ""
    handoffs: List["Agent"] = field(default_factory=list)
    max_turns: int = 50
    temperature: float = 0.0

    def available_tools(self, registry: ToolRegistry) -> List[ToolDef]:
        if self.tool_names is None:
            return registry.all_tools()
        return [t for t in registry.all_tools() if t.name in self.tool_names]


@dataclass
class RunResult:
    """Result of an agent run."""
    agent_name: str
    messages: List[dict]
    final_text: str
    tool_calls_made: int
    turns_used: int
    handoff_to: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)


class AgentRunner:
    """Executes the ReACT loop for one or more agents."""

    def __init__(
        self,
        guardrails: Optional[GuardrailEngine] = None,
        tracer: Optional[Tracer] = None,
        default_model: str = "",
    ):
        self.registry = ToolRegistry()
        self.guardrails = guardrails or GuardrailEngine()
        self.tracer = tracer or Tracer(enabled=False)
        self.default_model = default_model or os.environ.get(
            "NANOCLAW_MODEL", "claude-sonnet-4-20250514"
        )
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            logger.warning("ANTHROPIC_API_KEY not set - agent loop will fail")
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else None

    def run(
        self,
        agent: Agent,
        task: str,
        context: Optional[Dict[str, Any]] = None,
        messages: Optional[List[dict]] = None,
    ) -> RunResult:
        """Execute the ReACT loop for an agent.

        Args:
            agent: The agent to run
            task: The initial task/prompt
            context: Shared context dict (findings, state, etc.)
            messages: Pre-existing message history (for handoffs)
        """
        if not self.client:
            raise RuntimeError("ANTHROPIC_API_KEY not set")

        ctx = context or {}
        model = agent.model or self.default_model

        if messages is None:
            messages = [{"role": "user", "content": task}]

        tools_schemas = self._build_tool_schemas(agent)
        system_prompt = self._build_system_prompt(agent, ctx)

        total_tool_calls = 0
        final_text = ""

        for turn in range(agent.max_turns):
            with self.tracer.span(
                f"turn_{turn}", "agent_turn", agent_name=agent.name, turn=turn,
            ):
                logger.info(f"[{agent.name}] Turn {turn + 1}/{agent.max_turns}")

                try:
                    response = self.client.messages.create(
                        model=model,
                        max_tokens=8192,
                        temperature=agent.temperature,
                        system=system_prompt,
                        tools=tools_schemas,
                        messages=messages,
                    )
                except anthropic.APIError as e:
                    logger.error(f"API error: {e}")
                    break

                self.tracer.record_tokens(
                    TokenUsage(
                        input_tokens=response.usage.input_tokens,
                        output_tokens=response.usage.output_tokens,
                        cache_read_tokens=getattr(response.usage, "cache_read_input_tokens", 0) or 0,
                    ),
                    model=model,
                )

                assistant_content = response.content
                messages.append({"role": "assistant", "content": assistant_content})

                tool_uses = [b for b in assistant_content if b.type == "tool_use"]
                text_blocks = [b for b in assistant_content if b.type == "text"]

                if text_blocks:
                    final_text = text_blocks[-1].text
                    logger.info(f"[{agent.name}] Thinking: {final_text[:200]}...")

                if not tool_uses:
                    logger.info(f"[{agent.name}] No more tool calls - done")
                    break

                tool_results = []
                for tool_use in tool_uses:
                    result_content = self._execute_tool(
                        agent, tool_use.name, tool_use.input, tool_use.id,
                    )
                    total_tool_calls += 1
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use.id,
                        "content": result_content,
                    })

                    if tool_use.name.startswith("handoff_to_"):
                        target_name = tool_use.name.replace("handoff_to_", "")
                        return RunResult(
                            agent_name=agent.name,
                            messages=messages,
                            final_text=final_text,
                            tool_calls_made=total_tool_calls,
                            turns_used=turn + 1,
                            handoff_to=target_name,
                            context=ctx,
                        )

                messages.append({"role": "user", "content": tool_results})

                if response.stop_reason == "end_turn":
                    break

        return RunResult(
            agent_name=agent.name,
            messages=messages,
            final_text=final_text,
            tool_calls_made=total_tool_calls,
            turns_used=min(turn + 1, agent.max_turns),
            context=ctx,
        )

    def run_multi(
        self,
        agents: Dict[str, Agent],
        entry_agent: str,
        task: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> RunResult:
        """Run a multi-agent pipeline with handoffs.

        Starts with entry_agent, follows handoffs until an agent completes
        without handing off or max chain depth is reached.
        """
        ctx = context or {}
        current_agent = agents[entry_agent]
        messages = [{"role": "user", "content": task}]
        max_chain = 10

        for chain_step in range(max_chain):
            logger.info(f"=== Agent: {current_agent.name} (chain step {chain_step + 1}) ===")

            with self.tracer.span(
                f"agent_{current_agent.name}", "handoff",
                agent_name=current_agent.name, chain_step=chain_step,
            ):
                result = self.run(current_agent, task="", context=ctx, messages=messages)

            if not result.handoff_to:
                return result

            target_name = result.handoff_to
            if target_name not in agents:
                logger.warning(f"Handoff target '{target_name}' not found, ending chain")
                return result

            logger.info(f"Handoff: {current_agent.name} -> {target_name}")
            self.tracer._handoffs += 1
            current_agent = agents[target_name]
            messages = result.messages

        return result

    def _build_system_prompt(self, agent: Agent, context: Dict[str, Any]) -> str:
        parts = [agent.instructions]

        if context:
            ctx_summary = json.dumps(
                {k: v for k, v in context.items()
                 if not isinstance(v, (list, dict)) or len(str(v)) < 2000},
                indent=2, default=str,
            )
            parts.append(f"\n\n## Current Context\n```json\n{ctx_summary}\n```")

        if agent.handoffs:
            handoff_list = ", ".join(a.name for a in agent.handoffs)
            parts.append(
                f"\n\n## Available Handoffs\n"
                f"You can transfer control to: {handoff_list}\n"
                f"Use the handoff_to_<agent_name> tool when appropriate."
            )

        return "\n".join(parts)

    def _build_tool_schemas(self, agent: Agent) -> List[dict]:
        tools = agent.available_tools(self.registry)
        schemas = [t.to_anthropic_schema() for t in tools]

        for handoff_agent in agent.handoffs:
            safe_name = handoff_agent.name.lower().replace(" ", "_")
            schemas.append({
                "name": f"handoff_to_{safe_name}",
                "description": (
                    f"Transfer control to {handoff_agent.name}. "
                    f"Use this when: {handoff_agent.instructions[:200]}"
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "reason": {
                            "type": "string",
                            "description": "Why you are handing off to this agent",
                        },
                        "findings_summary": {
                            "type": "string",
                            "description": "Summary of findings so far for the next agent",
                        },
                    },
                    "required": ["reason"],
                },
            })

        return schemas

    def _execute_tool(
        self, agent: Agent, tool_name: str, arguments: dict, tool_use_id: str,
    ) -> str:
        """Execute a tool call with guardrails and tracing."""

        if tool_name.startswith("handoff_to_"):
            return json.dumps({"status": "handoff_initiated", "target": tool_name})

        tool_def = self.registry.get(tool_name)
        if not tool_def:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

        violation = self.guardrails.check_tool_call(
            tool_name, arguments, tool_def.risk_level,
        )
        if violation:
            self.tracer.record_guardrail_block(violation.rule, tool_name)
            logger.warning(f"BLOCKED by guardrail: {violation.description}")
            return json.dumps({
                "error": "blocked_by_guardrail",
                "rule": violation.rule,
                "description": violation.description,
            })

        with self.tracer.span(
            tool_name, "tool_call",
            agent_name=agent.name,
            arguments=arguments,
            risk_level=tool_def.risk_level,
            category=tool_def.category,
        ) as span:
            logger.info(f"[{agent.name}] Calling: {tool_name}({json.dumps(arguments)[:200]})")
            start = time.time()
            result = self.registry.execute(tool_name, arguments)
            elapsed = time.time() - start
            if span:
                span.attributes["duration_sec"] = round(elapsed, 1)
                span.attributes["result_length"] = len(result)
            logger.info(f"[{agent.name}] {tool_name} completed in {elapsed:.1f}s ({len(result)} chars)")

        if len(result) > 50_000:
            result = result[:50_000] + "\n...[truncated]"

        return result
