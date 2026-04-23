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

# Aegis Praetorium — shared guard layer (Lictor / Censor / Augur). Imported
# lazily-tolerantly so a missing install does not break the agent on dev
# machines that haven't pip-installed the package.
try:
    from aegis_praetorium import (
        HookContext as LictorHookContext,
        PostHookContext as LictorPostHookContext,
        get_augur,
        get_censor,
        get_config as get_praetorium_config,
        get_lictor,
    )
    _AEGIS_AVAILABLE = True
except Exception as _aegis_err:  # noqa: F841
    _AEGIS_AVAILABLE = False

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
            "AEGIS_MODEL", os.environ.get("NANOCLAW_MODEL", "claude-sonnet-4-20250514")
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
        """Execute a tool call with guardrails (legacy + Aegis Praetorium) and tracing."""

        if tool_name.startswith("handoff_to_"):
            return json.dumps({"status": "handoff_initiated", "target": tool_name})

        tool_def = self.registry.get(tool_name)
        if not tool_def:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

        # Legacy guardrail engine (kept as defense in depth; covers reverse-shell
        # and base64-encoded payload patterns that Aegis Lictor doesn't model).
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

        # ── Aegis Praetorium: Censor (input validation) ────────────────────
        org_id_env = os.environ.get("ASM_ORGANIZATION_ID")
        org_id = int(org_id_env) if (org_id_env or "").isdigit() else None
        if _AEGIS_AVAILABLE and get_praetorium_config().censor_enabled:
            verdict = get_censor().validate(tool_name, arguments)
            if not verdict.ok:
                self.tracer.record_guardrail_block("aegis_censor", tool_name)
                logger.warning(f"AEGIS CENSOR BLOCK: {verdict.error}")
                return json.dumps({
                    "error": "blocked_by_aegis_censor",
                    "description": verdict.error,
                })

        # ── Aegis Praetorium: Lictor pre-hooks (SSRF, scope, rate limit, …) ─
        if _AEGIS_AVAILABLE and get_praetorium_config().lictor_enabled:
            string_values = [str(v) for v in arguments.values() if isinstance(v, str)]
            ctx = LictorHookContext(
                tool_name=tool_name,
                args="",
                parsed_args=string_values,
                command=[tool_name, *string_values],
                inspectable_text=json.dumps(arguments, default=str),
                org_id=org_id,
                user_id=None,
                session_id=os.environ.get("ASM_AGENT_ID"),
            )
            pre = get_lictor().run_pre(ctx)
            if not pre.allowed:
                self.tracer.record_guardrail_block("aegis_lictor", tool_name)
                logger.warning(f"AEGIS LICTOR BLOCK: {pre.reason}")
                return json.dumps({
                    "error": "blocked_by_aegis_lictor",
                    "description": pre.reason,
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

        # ── Aegis Praetorium: Lictor post-hooks (audit log, hard-cap clip) ──
        if _AEGIS_AVAILABLE and get_praetorium_config().lictor_enabled:
            post_ctx = LictorPostHookContext(
                tool_name=tool_name,
                args="",
                command=[tool_name],
                result={"success": True, "output": result, "error": None, "exit_code": 0},
                duration_ms=elapsed * 1000.0,
                org_id=org_id,
                session_id=os.environ.get("ASM_AGENT_ID"),
            )
            post = get_lictor().run_post(post_ctx)
            if post.modified_result is not None:
                result = post.modified_result.get("output", result)

        # ── Aegis Praetorium: Augur (semantic output filter + next-step pivots) ─
        if _AEGIS_AVAILABLE and get_praetorium_config().augur_enabled and result:
            try:
                cap = get_praetorium_config().tool_output_max_chars
                reading = get_augur().interpret(tool_name, result, max_chars=cap)
            except Exception as e:
                logger.warning(f"Augur interpret failed for {tool_name}: {e}")
                reading = None
            if reading is not None:
                next_steps = [ns.to_dict() for ns in reading.next_steps]
                if next_steps:
                    logger.info(
                        "Augur produced %d next-step pivot(s) for %s: %s",
                        len(next_steps), tool_name,
                        ", ".join(ns["tool_name"] for ns in next_steps),
                    )
                augur_payload = {
                    "summary": reading.summary,
                    "kept": reading.kept,
                    "dropped": reading.dropped,
                    "actionable_signals": reading.actionable_signals,
                    "next_steps": next_steps,
                    "filtered_output": reading.to_text(),
                }
                # Return a JSON envelope so the LLM sees both the filtered text
                # AND the structured next_steps it can choose to follow up on.
                return json.dumps({"output": reading.to_text(), "augur": augur_payload})

        if len(result) > 50_000:
            result = result[:50_000] + "\n...[truncated]"

        return result
