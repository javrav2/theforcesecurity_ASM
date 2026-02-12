"""
AI Agent API Routes

REST and WebSocket endpoints for the AI security agent.
"""

import json
import logging
import uuid
from typing import Optional, Literal
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.models.user import User
from app.models.organization import Organization
from app.services.agent.orchestrator import get_agent_orchestrator
from app.services.agent.playbooks import build_initial_objective, list_playbooks
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agent", tags=["Agent"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class AgentQueryRequest(BaseModel):
    """Request to query the AI agent."""
    question: str
    session_id: Optional[str] = None
    playbook_id: Optional[str] = None
    target: Optional[str] = None
    mode: Optional[Literal["assist", "agent"]] = "assist"


class AgentApprovalRequest(BaseModel):
    """Request to approve/modify/abort a phase transition."""
    session_id: str
    decision: str  # "approve", "modify", "abort"
    modification: Optional[str] = None


class AgentAnswerRequest(BaseModel):
    """Request to answer an agent question."""
    session_id: str
    answer: str


class AgentResponse(BaseModel):
    """Response from the AI agent."""
    answer: str
    session_id: str
    current_phase: str
    iteration_count: int
    task_complete: bool
    todo_list: list
    execution_trace_summary: str
    awaiting_approval: bool = False
    approval_request: Optional[dict] = None
    awaiting_question: bool = False
    question_request: Optional[dict] = None
    error: Optional[str] = None


# =============================================================================
# REST ENDPOINTS
# =============================================================================

def _resolve_agent_organization_id(current_user: User, db: Session):
    """Resolve organization_id for agent: user's org, or first org for superusers without org."""
    org_id = getattr(current_user, "organization_id", None)
    if org_id:
        return org_id
    if getattr(current_user, "is_superuser", False):
        first_org = db.query(Organization).order_by(Organization.id).first()
        if first_org:
            return first_org.id
    return None


@router.post("/query", response_model=AgentResponse)
async def query_agent(
    request: AgentQueryRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Send a query to the AI security agent.
    
    The agent can:
    - Analyze your attack surface
    - Query assets, vulnerabilities, and ports
    - Provide remediation guidance
    - Answer security questions
    
    For exploitation or active scanning, the agent will request approval.
    
    Supports multiple AI providers:
    - OpenAI (set OPENAI_API_KEY)
    - Anthropic/Claude (set ANTHROPIC_API_KEY)
    """
    if not settings.OPENAI_API_KEY and not settings.ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="AI agent not available - Configure OPENAI_API_KEY or ANTHROPIC_API_KEY"
        )
    
    orchestrator = await get_agent_orchestrator()
    
    # Generate session ID if not provided
    session_id = request.session_id or str(uuid.uuid4())
    
    # Get user's organization (or first org for superusers without an org)
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization to use the agent. Ask an admin to assign you to an organization in Settings → Users, or create an organization first."
        )
    
    question = request.question
    initial_todos = None
    if request.playbook_id:
        objective, initial_todos = build_initial_objective(request.playbook_id, request.target)
        if objective:
            question = objective
    
    result = await orchestrator.invoke(
        question=question,
        user_id=str(current_user.id),
        organization_id=org_id,
        session_id=session_id,
        initial_todos=initial_todos,
        mode=request.mode or "assist",
    )
    
    if result.error:
        raise HTTPException(status_code=500, detail=result.error)
    
    return AgentResponse(
        answer=result.answer,
        session_id=session_id,
        current_phase=result.current_phase,
        iteration_count=result.iteration_count,
        task_complete=result.task_complete,
        todo_list=result.todo_list,
        execution_trace_summary=result.execution_trace_summary,
        awaiting_approval=result.awaiting_approval,
        approval_request=result.approval_request,
        awaiting_question=result.awaiting_question,
        question_request=result.question_request,
    )


@router.post("/approve", response_model=AgentResponse)
async def approve_phase_transition(
    request: AgentApprovalRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Respond to a phase transition approval request.
    
    Decisions:
    - "approve": Proceed with the phase transition
    - "modify": Proceed with modifications (include modification text)
    - "abort": Cancel and end the session
    """
    if not settings.OPENAI_API_KEY and not settings.ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="AI agent not available"
        )
    
    if request.decision not in ["approve", "modify", "abort"]:
        raise HTTPException(
            status_code=400,
            detail="Decision must be 'approve', 'modify', or 'abort'"
        )
    
    orchestrator = await get_agent_orchestrator()
    
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization to use the agent. Ask an admin to assign you in Settings → Users."
        )
    
    result = await orchestrator.resume_after_approval(
        session_id=request.session_id,
        user_id=str(current_user.id),
        organization_id=org_id,
        decision=request.decision,
        modification=request.modification
    )
    
    if result.error:
        raise HTTPException(status_code=500, detail=result.error)
    
    return AgentResponse(
        answer=result.answer,
        session_id=request.session_id,
        current_phase=result.current_phase,
        iteration_count=result.iteration_count,
        task_complete=result.task_complete,
        todo_list=result.todo_list,
        execution_trace_summary=result.execution_trace_summary,
        awaiting_approval=result.awaiting_approval,
        approval_request=result.approval_request,
        awaiting_question=result.awaiting_question,
        question_request=result.question_request,
    )


@router.post("/answer", response_model=AgentResponse)
async def answer_agent_question(
    request: AgentAnswerRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Answer a question from the AI agent.
    """
    if not settings.OPENAI_API_KEY and not settings.ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="AI agent not available"
        )
    
    orchestrator = await get_agent_orchestrator()
    
    org_id = _resolve_agent_organization_id(current_user, db)
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization to use the agent. Ask an admin to assign you in Settings → Users."
        )
    
    result = await orchestrator.resume_after_answer(
        session_id=request.session_id,
        user_id=str(current_user.id),
        organization_id=org_id,
        answer=request.answer
    )
    
    if result.error:
        raise HTTPException(status_code=500, detail=result.error)
    
    return AgentResponse(
        answer=result.answer,
        session_id=request.session_id,
        current_phase=result.current_phase,
        iteration_count=result.iteration_count,
        task_complete=result.task_complete,
        todo_list=result.todo_list,
        execution_trace_summary=result.execution_trace_summary,
        awaiting_approval=result.awaiting_approval,
        approval_request=result.approval_request,
        awaiting_question=result.awaiting_question,
        question_request=result.question_request,
    )


@router.get("/playbooks")
async def get_agent_playbooks():
    """List preset playbook objectives for the agent (id, name, description)."""
    return list_playbooks()


@router.get("/status")
async def get_agent_status():
    """
    Check if the AI agent is available.
    
    Supports multiple providers:
    - OpenAI (GPT-4, GPT-4o)
    - Anthropic (Claude 3.5 Sonnet, Claude 3 Opus)
    """
    has_openai = bool(settings.OPENAI_API_KEY)
    has_anthropic = bool(settings.ANTHROPIC_API_KEY)
    available = has_openai or has_anthropic
    
    # Determine active provider
    provider = settings.AI_PROVIDER.lower()
    if provider == "anthropic" and has_anthropic:
        active_provider = "anthropic"
        active_model = settings.ANTHROPIC_MODEL
    elif provider == "openai" and has_openai:
        active_provider = "openai"
        active_model = settings.OPENAI_MODEL
    elif has_anthropic:
        active_provider = "anthropic"
        active_model = settings.ANTHROPIC_MODEL
    elif has_openai:
        active_provider = "openai"
        active_model = settings.OPENAI_MODEL
    else:
        active_provider = None
        active_model = None
    
    return {
        "available": available,
        "provider": active_provider,
        "model": active_model,
        "providers_configured": {
            "openai": has_openai,
            "anthropic": has_anthropic,
        },
        "max_iterations": settings.AGENT_MAX_ITERATIONS if available else None,
        "features": {
            "attack_surface_analysis": True,
            "vulnerability_queries": True,
            "remediation_guidance": True,
            "natural_language_queries": True,
        } if available else {}
    }


# =============================================================================
# WEBSOCKET ENDPOINT
# =============================================================================

class WebSocketManager:
    """Manage WebSocket connections for real-time agent streaming."""
    
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}
    
    async def connect(self, websocket: WebSocket, session_id: str):
        await websocket.accept()
        self.active_connections[session_id] = websocket
    
    def disconnect(self, session_id: str):
        if session_id in self.active_connections:
            del self.active_connections[session_id]
    
    async def send_message(self, session_id: str, message: dict):
        if session_id in self.active_connections:
            await self.active_connections[session_id].send_json(message)


ws_manager = WebSocketManager()


@router.websocket("/ws/{session_id}")
async def agent_websocket(
    websocket: WebSocket,
    session_id: str
):
    """
    WebSocket endpoint for real-time agent interaction.
    
    Message format (client -> server):
    - {"type": "init", "token": "jwt_token"}
    - {"type": "query", "question": "..."}
    - {"type": "approval", "decision": "approve|modify|abort", "modification": "..."}
    - {"type": "answer", "answer": "..."}
    
    Message format (server -> client):
    - {"type": "connected", "session_id": "..."}
    - {"type": "thinking", "iteration": N, "phase": "...", "thought": "..."}
    - {"type": "tool_start", "tool_name": "...", "tool_args": {...}}
    - {"type": "tool_complete", "tool_name": "...", "success": true, "output_summary": "..."}
    - {"type": "approval_request", "from_phase": "...", "to_phase": "...", "reason": "..."}
    - {"type": "question_request", "question": "...", "context": "..."}
    - {"type": "response", "answer": "...", "task_complete": false}
    - {"type": "error", "message": "..."}
    """
    await ws_manager.connect(websocket, session_id)
    
    try:
        await websocket.send_json({
            "type": "connected",
            "session_id": session_id
        })
        
        user_id = None
        org_id = None
        
        while True:
            data = await websocket.receive_json()
            msg_type = data.get("type")
            
            if msg_type == "init":
                # TODO: Validate JWT token and extract user info
                # For now, use placeholder
                user_id = data.get("user_id", "1")
                org_id = data.get("organization_id", 1)
                await websocket.send_json({"type": "initialized", "user_id": user_id})
            
            elif msg_type == "query":
                if not user_id:
                    await websocket.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                
                question = data.get("question", "")
                
                orchestrator = await get_agent_orchestrator()
                result = await orchestrator.invoke(
                    question=question,
                    user_id=str(user_id),
                    organization_id=org_id,
                    session_id=session_id
                )
                
                if result.error:
                    await websocket.send_json({"type": "error", "message": result.error})
                else:
                    await websocket.send_json({
                        "type": "response",
                        "answer": result.answer,
                        "current_phase": result.current_phase,
                        "iteration_count": result.iteration_count,
                        "task_complete": result.task_complete,
                        "awaiting_approval": result.awaiting_approval,
                        "approval_request": result.approval_request,
                        "awaiting_question": result.awaiting_question,
                        "question_request": result.question_request,
                    })
            
            elif msg_type == "approval":
                if not user_id:
                    await websocket.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                
                orchestrator = await get_agent_orchestrator()
                result = await orchestrator.resume_after_approval(
                    session_id=session_id,
                    user_id=str(user_id),
                    organization_id=org_id,
                    decision=data.get("decision", "abort"),
                    modification=data.get("modification")
                )
                
                if result.error:
                    await websocket.send_json({"type": "error", "message": result.error})
                else:
                    await websocket.send_json({
                        "type": "response",
                        "answer": result.answer,
                        "current_phase": result.current_phase,
                        "iteration_count": result.iteration_count,
                        "task_complete": result.task_complete,
                    })
            
            elif msg_type == "answer":
                if not user_id:
                    await websocket.send_json({"type": "error", "message": "Not authenticated"})
                    continue
                
                orchestrator = await get_agent_orchestrator()
                result = await orchestrator.resume_after_answer(
                    session_id=session_id,
                    user_id=str(user_id),
                    organization_id=org_id,
                    answer=data.get("answer", "")
                )
                
                if result.error:
                    await websocket.send_json({"type": "error", "message": result.error})
                else:
                    await websocket.send_json({
                        "type": "response",
                        "answer": result.answer,
                        "current_phase": result.current_phase,
                        "iteration_count": result.iteration_count,
                        "task_complete": result.task_complete,
                    })
            
            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})
    
    except WebSocketDisconnect:
        ws_manager.disconnect(session_id)
        logger.info(f"WebSocket disconnected: {session_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        ws_manager.disconnect(session_id)
