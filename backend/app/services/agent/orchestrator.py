"""
Agent Orchestrator

ReAct-style agent orchestrator for security analysis and autonomous assessment.
Uses LangGraph for state management and LangChain for LLM interactions.
"""

import json
import logging
import re
from datetime import datetime
from typing import Optional, List, Dict, Any

from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

# Conditionally import Anthropic
try:
    from langchain_anthropic import ChatAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    ChatAnthropic = None

from app.core.config import settings
from app.services.agent.state import (
    AgentState,
    InvokeResponse,
    ExecutionStep,
    TargetInfo,
    PhaseTransitionRequest,
    PhaseHistoryEntry,
    LLMDecision,
    OutputAnalysis,
    ExtractedTargetInfo,
    UserQuestionRequest,
    QAHistoryEntry,
    ConversationObjective,
    ObjectiveOutcome,
    TodoItem,
    format_todo_list,
    format_execution_trace,
    format_qa_history,
    format_objective_history,
    summarize_trace_for_response,
    migrate_legacy_objective,
    utc_now,
)
from app.services.agent.prompts import (
    REACT_SYSTEM_PROMPT,
    OUTPUT_ANALYSIS_PROMPT,
    PHASE_TRANSITION_MESSAGE,
    USER_QUESTION_MESSAGE,
    FINAL_REPORT_PROMPT,
    get_phase_tools,
    is_tool_allowed_in_phase,
)
from app.services.agent.tools import ASMToolsManager, set_tenant_context
from app.services.agent.knowledge import retrieve_knowledge

logger = logging.getLogger(__name__)

# Global checkpointer for session persistence
checkpointer = MemorySaver()


class DateTimeEncoder(json.JSONEncoder):
    """JSON encoder that handles datetime objects."""
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def json_dumps_safe(obj, **kwargs):
    """JSON dumps with datetime support."""
    return json.dumps(obj, cls=DateTimeEncoder, **kwargs)


class AgentOrchestrator:
    """
    ReAct-style agent orchestrator for security analysis.
    
    Implements the Thought-Tool-Output pattern with:
    - Phase tracking (Informational → Exploitation → Post-Exploitation)
    - LLM-managed todo lists
    - Checkpoint-based approval for phase transitions
    - Full execution trace in memory
    
    Supports multiple LLM providers:
    - OpenAI (GPT-4, GPT-4o, etc.)
    - Anthropic (Claude 3.5 Sonnet, Claude 3 Opus, etc.)
    """
    
    def __init__(self):
        """Initialize the orchestrator."""
        self.llm: Optional[BaseChatModel] = None
        self.tool_manager: Optional[ASMToolsManager] = None
        self.graph = None
        self._initialized = False
        self._provider = None
    
    async def initialize(self) -> None:
        """Initialize all components asynchronously."""
        if self._initialized:
            logger.warning("Orchestrator already initialized")
            return
        
        logger.info("Initializing AgentOrchestrator...")
        
        # Check for available API keys
        has_openai = bool(settings.OPENAI_API_KEY)
        has_anthropic = bool(settings.ANTHROPIC_API_KEY)
        
        if not has_openai and not has_anthropic:
            logger.warning("No AI API key configured (OPENAI_API_KEY or ANTHROPIC_API_KEY) - AI agent will not function")
            return
        
        self._setup_llm()
        self._setup_tools()
        self._build_graph()
        self._initialized = True
        
        logger.info(f"AgentOrchestrator initialized successfully with {self._provider} provider")
    
    def _setup_llm(self) -> None:
        """Initialize the LLM based on configuration."""
        provider = settings.AI_PROVIDER.lower()
        
        # Auto-detect provider if not explicitly set or if configured provider is unavailable
        if provider == "anthropic" and settings.ANTHROPIC_API_KEY:
            self._setup_anthropic()
        elif provider == "openai" and settings.OPENAI_API_KEY:
            self._setup_openai()
        elif settings.ANTHROPIC_API_KEY:
            # Fallback to Anthropic if available
            self._setup_anthropic()
        elif settings.OPENAI_API_KEY:
            # Fallback to OpenAI if available
            self._setup_openai()
        else:
            raise ValueError("No valid AI provider configuration found")
    
    def _setup_openai(self) -> None:
        """Initialize OpenAI LLM."""
        logger.info(f"Setting up OpenAI LLM: {settings.OPENAI_MODEL}")
        self.llm = ChatOpenAI(
            model=settings.OPENAI_MODEL,
            api_key=settings.OPENAI_API_KEY,
            temperature=0
        )
        self._provider = "openai"
    
    def _setup_anthropic(self) -> None:
        """Initialize Anthropic/Claude LLM. Uses ANTHROPIC_API_KEY from env so the SDK sends it unchanged."""
        import os
        if not ANTHROPIC_AVAILABLE:
            raise ImportError("langchain-anthropic is not installed. Run: pip install langchain-anthropic")
        
        key = settings.ANTHROPIC_API_KEY or ""
        key = (key.strip() if isinstance(key, str) else "").strip()
        if not key:
            raise ValueError("ANTHROPIC_API_KEY is empty. Set it in .env with a key from https://console.anthropic.com (API Keys), not a Cursor/Claude Code key.")
        if not key.startswith("sk-ant-"):
            logger.warning(
                "ANTHROPIC_API_KEY does not start with 'sk-ant-'. "
                "Use an API key from https://console.anthropic.com (API Keys); "
                "keys from Cursor/Claude Code are not valid for this API."
            )
        # Let the SDK read the key from env (avoids any encoding/quoting issues from passing it in code)
        os.environ["ANTHROPIC_API_KEY"] = key
        logger.info(f"Setting up Anthropic LLM: {settings.ANTHROPIC_MODEL}")
        self.llm = ChatAnthropic(
            model=settings.ANTHROPIC_MODEL,
            temperature=0,
            max_tokens=4096,
        )
        self._provider = "anthropic"
    
    def _setup_tools(self) -> None:
        """Set up ASM tools for the agent."""
        self.tool_manager = ASMToolsManager()
        logger.info(f"Tools initialized: {len(self.tool_manager.get_all_tools())} available")
    
    def _build_graph(self) -> None:
        """Build the ReAct LangGraph."""
        logger.info("Building ReAct LangGraph...")
        
        builder = StateGraph(AgentState)
        
        # Add nodes
        builder.add_node("initialize", self._initialize_node)
        builder.add_node("think", self._think_node)
        builder.add_node("execute_tool", self._execute_tool_node)
        builder.add_node("analyze_output", self._analyze_output_node)
        builder.add_node("await_approval", self._await_approval_node)
        builder.add_node("process_approval", self._process_approval_node)
        builder.add_node("await_question", self._await_question_node)
        builder.add_node("process_answer", self._process_answer_node)
        builder.add_node("generate_response", self._generate_response_node)
        
        # Entry point
        builder.add_edge(START, "initialize")
        
        # Route after initialize
        builder.add_conditional_edges(
            "initialize",
            self._route_after_initialize,
            {
                "process_approval": "process_approval",
                "process_answer": "process_answer",
                "think": "think",
            }
        )
        
        # Main routing from think node
        builder.add_conditional_edges(
            "think",
            self._route_after_think,
            {
                "execute_tool": "execute_tool",
                "await_approval": "await_approval",
                "await_question": "await_question",
                "generate_response": "generate_response",
            }
        )
        
        # Tool execution flow
        builder.add_edge("execute_tool", "analyze_output")
        
        # After analysis, continue or end
        builder.add_conditional_edges(
            "analyze_output",
            self._route_after_analyze,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )
        
        # Approval flow
        builder.add_edge("await_approval", END)
        builder.add_conditional_edges(
            "process_approval",
            self._route_after_approval,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )
        
        # Q&A flow
        builder.add_edge("await_question", END)
        builder.add_conditional_edges(
            "process_answer",
            self._route_after_answer,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )
        
        # Final response ends
        builder.add_edge("generate_response", END)
        
        self.graph = builder.compile(checkpointer=checkpointer)
        logger.info("ReAct LangGraph compiled")
    
    # =========================================================================
    # LANGGRAPH NODES
    # =========================================================================
    
    async def _initialize_node(self, state: AgentState, config=None) -> dict:
        """Initialize state for new conversation."""
        user_id = state.get("user_id", "unknown")
        org_id = state.get("organization_id")
        session_id = state.get("session_id", "unknown")
        
        logger.info(f"[{user_id}/{session_id}] Initializing state...")
        
        # Migrate legacy state if needed
        state = migrate_legacy_objective(state)
        
        # If resuming after approval/answer, preserve state
        if state.get("user_approval_response") and state.get("phase_transition_pending"):
            return {}
        
        if state.get("user_question_answer") and state.get("pending_question"):
            return {}
        
        # Extract latest user message
        messages = state.get("messages", [])
        latest_message = ""
        for msg in reversed(messages):
            if isinstance(msg, HumanMessage):
                latest_message = msg.content
                break
        
        # Initialize conversation objectives
        objectives = state.get("conversation_objectives", [])
        if not objectives and latest_message:
            objectives = [ConversationObjective(content=latest_message).model_dump()]
        
        todo_list = state.get("initial_todos") if state.get("initial_todos") else []
        mode = state.get("mode") or "assist"
        
        return {
            "current_iteration": 0,
            "max_iterations": settings.AGENT_MAX_ITERATIONS,
            "task_complete": False,
            "current_phase": "informational",
            "phase_history": [PhaseHistoryEntry(phase="informational").model_dump()],
            "execution_trace": [],
            "todo_list": todo_list,
            "conversation_objectives": objectives,
            "current_objective_index": 0,
            "objective_history": [],
            "original_objective": latest_message,
            "target_info": TargetInfo().model_dump(),
            "awaiting_user_approval": False,
            "phase_transition_pending": None,
            "qa_history": [],
            "mode": mode,
        }
    
    async def _think_node(self, state: AgentState, config=None) -> dict:
        """Core ReAct reasoning node."""
        user_id = state.get("user_id", "unknown")
        org_id = state.get("organization_id")
        
        iteration = state.get("current_iteration", 0) + 1
        phase = state.get("current_phase", "informational")
        
        logger.info(f"[{user_id}] Think node - iteration {iteration}, phase: {phase}")
        
        # Set tenant context for tools (including session_id for save_note/get_notes)
        session_id = state.get("session_id")
        if org_id:
            set_tenant_context(
                int(user_id) if user_id.isdigit() else 0,
                org_id,
                session_id=session_id,
            )
        
        # Get current objective
        objectives = state.get("conversation_objectives", [])
        current_idx = state.get("current_objective_index", 0)
        current_objective = objectives[current_idx].get("content", "") if current_idx < len(objectives) else state.get("original_objective", "")
        
        # Session notes for prompt
        session_notes = (
            self.tool_manager.get_session_notes(session_id=session_id)
            if self.tool_manager else "No session notes."
        )
        
        # RAG: org knowledge (scope, ROE, methodology)
        knowledge_context = ""
        if org_id:
            knowledge_context = retrieve_knowledge(
                org_id,
                current_objective[:200] if current_objective else "",
                limit=5,
                max_chars=1500,
            )
        if not knowledge_context:
            knowledge_context = "None."
        
        # Build prompt
        execution_trace_formatted = format_execution_trace(state.get("execution_trace", []))
        todo_list_formatted = format_todo_list(state.get("todo_list", []))
        target_info_formatted = json_dumps_safe(state.get("target_info", {}), indent=2)
        qa_history_formatted = format_qa_history(state.get("qa_history", []))
        objective_history_formatted = format_objective_history(state.get("objective_history", []))
        available_tools = get_phase_tools(phase)
        
        system_prompt = REACT_SYSTEM_PROMPT.format(
            current_phase=phase,
            available_tools=available_tools,
            iteration=iteration,
            max_iterations=state.get("max_iterations", settings.AGENT_MAX_ITERATIONS),
            objective=current_objective,
            objective_history_summary=objective_history_formatted,
            execution_trace=execution_trace_formatted,
            todo_list=todo_list_formatted,
            target_info=target_info_formatted,
            session_notes=session_notes,
            knowledge_context=knowledge_context,
            qa_history=qa_history_formatted,
        )
        
        # Get LLM decision
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content="Based on the current state, what is your next action? Output EXACTLY ONE valid JSON object.")
        ]
        
        response = await self.llm.ainvoke(messages)
        response_text = response.content.strip()
        
        logger.debug(f"LLM response: {response_text[:500]}...")
        
        # Parse decision
        decision = self._parse_llm_decision(response_text)
        
        logger.info(f"[{user_id}] Decision: action={decision.action}, tool={decision.tool_name}")
        
        # Create execution step
        step = ExecutionStep(
            iteration=iteration,
            phase=phase,
            thought=decision.thought,
            reasoning=decision.reasoning,
            tool_name=decision.tool_name if decision.action == "use_tool" else None,
            tool_args=decision.tool_args if decision.action == "use_tool" else None,
        )
        
        # Update todo list
        todo_list = [item.model_dump() for item in decision.updated_todo_list] if decision.updated_todo_list else state.get("todo_list", [])
        
        updates = {
            "current_iteration": iteration,
            "todo_list": todo_list,
            "_current_step": step.model_dump(),
            "_decision": decision.model_dump(),
        }
        
        # Handle actions
        if decision.action == "complete":
            updates["task_complete"] = True
            updates["completion_reason"] = decision.completion_reason or "Task completed"
        
        elif decision.action == "transition_phase":
            to_phase = decision.phase_transition.to_phase if decision.phase_transition else "exploitation"
            
            if to_phase == phase:
                # Already in this phase, continue
                pass
            elif state.get("mode") == "agent":
                # Autonomous mode: apply phase transition immediately
                updates["current_phase"] = to_phase
                phase_history = state.get("phase_history", []) + [
                    PhaseHistoryEntry(phase=to_phase).model_dump()
                ]
                updates["phase_history"] = phase_history
                updates["phase_transition_pending"] = None
                updates["awaiting_user_approval"] = False
                logger.info(f"[{user_id}] Agent mode: auto-approved transition to {to_phase}")
            else:
                # Assist mode: request approval for phase transition
                updates["phase_transition_pending"] = PhaseTransitionRequest(
                    from_phase=phase,
                    to_phase=to_phase,
                    reason=decision.phase_transition.reason if decision.phase_transition else "",
                    planned_actions=decision.phase_transition.planned_actions if decision.phase_transition else [],
                    risks=decision.phase_transition.risks if decision.phase_transition else [],
                ).model_dump()
                updates["awaiting_user_approval"] = True
        
        elif decision.action == "ask_user":
            if decision.user_question:
                updates["pending_question"] = UserQuestionRequest(
                    question=decision.user_question.question,
                    context=decision.user_question.context,
                    format=decision.user_question.format,
                    options=decision.user_question.options,
                    phase=phase,
                ).model_dump()
                updates["awaiting_user_question"] = True
        
        return updates
    
    async def _execute_tool_node(self, state: AgentState, config=None) -> dict:
        """Execute the selected tool."""
        user_id = state.get("user_id", "unknown")
        org_id = state.get("organization_id")
        
        step_data = state.get("_current_step") or {}
        tool_name = step_data.get("tool_name")
        tool_args = step_data.get("tool_args") or {}
        phase = state.get("current_phase", "informational")
        
        logger.info(f"[{user_id}] Executing tool: {tool_name}")
        
        if not tool_name:
            step_data["tool_output"] = "Error: No tool specified"
            step_data["success"] = False
            return {"_current_step": step_data}
        
        # Set tenant context (including session_id for save_note)
        if org_id:
            set_tenant_context(
                int(user_id) if user_id.isdigit() else 0,
                org_id,
                session_id=state.get("session_id"),
            )
        
        # Check phase restriction
        if not is_tool_allowed_in_phase(tool_name, phase):
            step_data["tool_output"] = f"Error: Tool '{tool_name}' not allowed in '{phase}' phase"
            step_data["success"] = False
            return {"_current_step": step_data}
        
        # Execute tool
        result = await self.tool_manager.execute(tool_name, tool_args)
        
        step_data["tool_output"] = result.get("output") or result.get("error") or ""
        step_data["success"] = result.get("success", False)
        step_data["error_message"] = result.get("error")
        
        logger.info(f"[{user_id}] Tool result: success={step_data['success']}")
        
        return {"_current_step": step_data}
    
    async def _analyze_output_node(self, state: AgentState, config=None) -> dict:
        """Analyze tool output and extract intelligence."""
        step_data = state.get("_current_step") or {}
        tool_output = step_data.get("tool_output") or ""
        tool_name = step_data.get("tool_name") or "unknown"
        
        if not tool_output:
            tool_output = step_data.get("error_message") or "No output"
        
        # Truncate for LLM
        max_chars = settings.AGENT_TOOL_OUTPUT_MAX_CHARS
        truncated_output = tool_output[:max_chars] if len(tool_output) > max_chars else tool_output
        
        # Build analysis prompt
        analysis_prompt = OUTPUT_ANALYSIS_PROMPT.format(
            tool_name=tool_name,
            tool_args=json_dumps_safe(step_data.get("tool_args") or {}),
            tool_output=truncated_output,
            current_target_info=json_dumps_safe(state.get("target_info") or {}, indent=2),
        )
        
        response = await self.llm.ainvoke([HumanMessage(content=analysis_prompt)])
        analysis = self._parse_analysis_response(response.content)
        
        # Update step with analysis
        step_data["output_analysis"] = analysis.interpretation
        step_data["actionable_findings"] = analysis.actionable_findings or []
        step_data["recommended_next_steps"] = analysis.recommended_next_steps or []
        
        # Merge target info
        current_target = TargetInfo(**state.get("target_info", {}))
        new_target = TargetInfo(
            primary_target=analysis.extracted_info.primary_target,
            ports=analysis.extracted_info.ports,
            services=analysis.extracted_info.services,
            technologies=analysis.extracted_info.technologies,
            vulnerabilities=analysis.extracted_info.vulnerabilities,
        )
        merged_target = current_target.merge_from(new_target)
        
        # Add to execution trace
        execution_trace = state.get("execution_trace", []) + [step_data]
        
        return {
            "_current_step": step_data,
            "execution_trace": execution_trace,
            "target_info": merged_target.model_dump(),
            "messages": [AIMessage(content=f"**Step {step_data.get('iteration')}** [{state.get('current_phase')}]\n\n{analysis.interpretation[:500]}")],
        }
    
    async def _await_approval_node(self, state: AgentState, config=None) -> dict:
        """Request user approval for phase transition."""
        transition = state.get("phase_transition_pending", {})
        
        planned_actions = "\n".join(f"- {a}" for a in transition.get("planned_actions", []))
        risks = "\n".join(f"- {r}" for r in transition.get("risks", []))
        
        message = PHASE_TRANSITION_MESSAGE.format(
            from_phase=transition.get("from_phase", "informational"),
            to_phase=transition.get("to_phase", "exploitation"),
            reason=transition.get("reason", "No reason provided"),
            planned_actions=planned_actions or "- No specific actions planned",
            risks=risks or "- Standard risks apply",
        )
        
        return {
            "awaiting_user_approval": True,
            "messages": [AIMessage(content=message)],
        }
    
    async def _process_approval_node(self, state: AgentState, config=None) -> dict:
        """Process user's approval response."""
        approval = state.get("user_approval_response")
        transition = state.get("phase_transition_pending", {})
        
        clear_state = {
            "awaiting_user_approval": False,
            "phase_transition_pending": None,
            "user_approval_response": None,
            "user_modification": None,
        }
        
        if approval == "approve":
            new_phase = transition.get("to_phase", "exploitation")
            return {
                **clear_state,
                "current_phase": new_phase,
                "phase_history": state.get("phase_history", []) + [
                    PhaseHistoryEntry(phase=new_phase).model_dump()
                ],
                "messages": [AIMessage(content=f"Phase transition approved. Now in **{new_phase}** phase.")],
            }
        
        elif approval == "modify":
            modification = state.get("user_modification", "")
            return {
                **clear_state,
                "messages": [
                    HumanMessage(content=f"User modification: {modification}"),
                    AIMessage(content="Adjusting approach based on your feedback."),
                ],
            }
        
        else:  # abort
            return {
                **clear_state,
                "task_complete": True,
                "completion_reason": "Phase transition cancelled by user",
                "messages": [AIMessage(content="Phase transition cancelled. Session ended.")],
            }
    
    async def _await_question_node(self, state: AgentState, config=None) -> dict:
        """Request user answer to a question."""
        question = state.get("pending_question", {})
        
        options_text = "\n".join(f"- {opt}" for opt in question.get("options", [])) if question.get("options") else "Free text"
        
        message = USER_QUESTION_MESSAGE.format(
            question=question.get("question", ""),
            context=question.get("context", ""),
            format=question.get("format", "text"),
            options=options_text,
            default=question.get("default_value") or "None",
        )
        
        return {
            "awaiting_user_question": True,
            "messages": [AIMessage(content=message)],
        }
    
    async def _process_answer_node(self, state: AgentState, config=None) -> dict:
        """Process user's answer to a question."""
        answer = state.get("user_question_answer")
        question = state.get("pending_question", {})
        
        qa_entry = QAHistoryEntry(
            question=UserQuestionRequest(**question),
            answer={"question_id": question.get("question_id", ""), "answer": answer or ""},
            answered_at=utc_now(),
        )
        
        qa_history = state.get("qa_history", []) + [qa_entry.model_dump()]
        
        return {
            "awaiting_user_question": False,
            "pending_question": None,
            "user_question_answer": None,
            "qa_history": qa_history,
            "messages": [
                HumanMessage(content=f"User answer: {answer}"),
                AIMessage(content="Thank you. Continuing with the analysis..."),
            ],
        }
    
    async def _generate_response_node(self, state: AgentState, config=None) -> dict:
        """Generate final response."""
        report_prompt = FINAL_REPORT_PROMPT.format(
            objective=state.get("original_objective", ""),
            iteration_count=state.get("current_iteration", 0),
            final_phase=state.get("current_phase", "informational"),
            completion_reason=state.get("completion_reason", "Session ended"),
            execution_trace=format_execution_trace(state.get("execution_trace", [])),
            target_info=json_dumps_safe(state.get("target_info", {}), indent=2),
            todo_list=format_todo_list(state.get("todo_list", [])),
        )
        
        response = await self.llm.ainvoke([HumanMessage(content=report_prompt)])
        
        return {
            "messages": [AIMessage(content=response.content)],
            "task_complete": True,
            "completion_reason": state.get("completion_reason") or "Task completed",
        }
    
    # =========================================================================
    # ROUTING FUNCTIONS
    # =========================================================================
    
    def _route_after_initialize(self, state: AgentState) -> str:
        if state.get("user_approval_response") and state.get("phase_transition_pending"):
            return "process_approval"
        if state.get("user_question_answer") and state.get("pending_question"):
            return "process_answer"
        return "think"
    
    def _route_after_think(self, state: AgentState) -> str:
        if state.get("current_iteration", 0) >= state.get("max_iterations", 15):
            return "generate_response"
        if state.get("task_complete"):
            return "generate_response"
        if state.get("awaiting_user_approval"):
            return "await_approval"
        if state.get("awaiting_user_question"):
            return "await_question"
        
        decision = state.get("_decision", {})
        action = decision.get("action", "use_tool")
        
        if action == "complete":
            return "generate_response"
        elif action == "ask_user" and state.get("pending_question"):
            return "await_question"
        elif action == "transition_phase" and state.get("phase_transition_pending"):
            return "await_approval"
        elif action == "use_tool" and decision.get("tool_name"):
            return "execute_tool"
        else:
            return "generate_response"
    
    def _route_after_analyze(self, state: AgentState) -> str:
        if state.get("task_complete"):
            return "generate_response"
        if state.get("current_iteration", 0) >= state.get("max_iterations", 15):
            return "generate_response"
        return "think"
    
    def _route_after_approval(self, state: AgentState) -> str:
        if state.get("task_complete"):
            return "generate_response"
        return "think"
    
    def _route_after_answer(self, state: AgentState) -> str:
        if state.get("task_complete"):
            return "generate_response"
        return "think"
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _extract_json(self, text: str) -> Optional[str]:
        """Extract JSON from text."""
        json_start = text.find("{")
        json_end = text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            return text[json_start:json_end]
        return None
    
    def _parse_llm_decision(self, text: str) -> LLMDecision:
        """Parse LLM decision from response."""
        try:
            json_str = self._extract_json(text)
            if json_str:
                data = json.loads(json_str)
                
                # Clean empty objects
                if "user_question" in data and not data["user_question"]:
                    data["user_question"] = None
                if "phase_transition" in data and not data["phase_transition"]:
                    data["phase_transition"] = None
                
                return LLMDecision.model_validate(data)
        except Exception as e:
            logger.warning(f"Failed to parse LLM decision: {e}")
        
        return LLMDecision(
            thought=text,
            reasoning="Failed to parse response",
            action="complete",
            completion_reason="Parse error",
            updated_todo_list=[],
        )
    
    def _parse_analysis_response(self, text: str) -> OutputAnalysis:
        """Parse analysis response."""
        try:
            json_str = self._extract_json(text)
            if json_str:
                data = json.loads(json_str)
                return OutputAnalysis.model_validate(data)
        except Exception as e:
            logger.warning(f"Failed to parse analysis: {e}")
        
        return OutputAnalysis(
            interpretation=text[:1000],
            extracted_info=ExtractedTargetInfo(),
            actionable_findings=[],
            recommended_next_steps=[],
        )
    
    # =========================================================================
    # PUBLIC API
    # =========================================================================
    
    async def invoke(
        self,
        question: str,
        user_id: str,
        organization_id: int,
        session_id: str,
        initial_todos: Optional[List[Dict[str, Any]]] = None,
        mode: str = "assist",
    ) -> InvokeResponse:
        """Main entry point for agent invocation."""
        if not self._initialized:
            await self.initialize()
        
        if not self._initialized:
            return InvokeResponse(error="Agent not initialized - check OPENAI_API_KEY")
        
        logger.info(f"[{user_id}/{session_id}] Invoking with: {question[:100]}... (mode={mode})")
        
        try:
            config = {"configurable": {"thread_id": session_id}}
            input_data = {
                "messages": [HumanMessage(content=question)],
                "user_id": user_id,
                "organization_id": organization_id,
                "session_id": session_id,
                "mode": mode,
            }
            if initial_todos is not None:
                input_data["initial_todos"] = initial_todos
            
            final_state = await self.graph.ainvoke(input_data, config)
            return self._build_response(final_state)
        
        except Exception as e:
            logger.error(f"[{user_id}/{session_id}] Error: {e}")
            return InvokeResponse(error=str(e))
    
    async def resume_after_approval(
        self,
        session_id: str,
        user_id: str,
        organization_id: int,
        decision: str,
        modification: Optional[str] = None
    ) -> InvokeResponse:
        """Resume after user approval."""
        if not self._initialized:
            return InvokeResponse(error="Agent not initialized")
        
        try:
            config = {"configurable": {"thread_id": session_id}}
            
            update_data = {
                "user_approval_response": decision,
                "user_modification": modification,
                "user_id": user_id,
                "organization_id": organization_id,
            }
            
            final_state = await self.graph.ainvoke(update_data, config)
            return self._build_response(final_state)
        
        except Exception as e:
            logger.error(f"[{user_id}/{session_id}] Resume error: {e}")
            return InvokeResponse(error=str(e))
    
    async def resume_after_answer(
        self,
        session_id: str,
        user_id: str,
        organization_id: int,
        answer: str
    ) -> InvokeResponse:
        """Resume after user answers a question."""
        if not self._initialized:
            return InvokeResponse(error="Agent not initialized")
        
        try:
            config = {"configurable": {"thread_id": session_id}}
            
            update_data = {
                "user_question_answer": answer,
                "user_id": user_id,
                "organization_id": organization_id,
            }
            
            final_state = await self.graph.ainvoke(update_data, config)
            return self._build_response(final_state)
        
        except Exception as e:
            logger.error(f"[{user_id}/{session_id}] Resume error: {e}")
            return InvokeResponse(error=str(e))
    
    def _build_response(self, state: dict) -> InvokeResponse:
        """Build response from final state."""
        final_answer = ""
        messages = state.get("messages", [])
        for msg in reversed(messages):
            if isinstance(msg, AIMessage):
                final_answer = msg.content
                break
        
        step = state.get("_current_step", {})
        
        return InvokeResponse(
            answer=final_answer,
            tool_used=step.get("tool_name"),
            tool_output=step.get("tool_output"),
            current_phase=state.get("current_phase", "informational"),
            iteration_count=state.get("current_iteration", 0),
            task_complete=state.get("task_complete", False),
            todo_list=state.get("todo_list", []),
            execution_trace_summary=summarize_trace_for_response(state.get("execution_trace", [])),
            awaiting_approval=state.get("awaiting_user_approval", False),
            approval_request=state.get("phase_transition_pending"),
            awaiting_question=state.get("awaiting_user_question", False),
            question_request=state.get("pending_question"),
        )


# Global orchestrator instance
_orchestrator: Optional[AgentOrchestrator] = None


async def get_agent_orchestrator() -> AgentOrchestrator:
    """Get or create the global agent orchestrator."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AgentOrchestrator()
        await _orchestrator.initialize()
    return _orchestrator
