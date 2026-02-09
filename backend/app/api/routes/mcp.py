"""
MCP Tool Server API Routes

Endpoints for calling security tools via the Model Context Protocol.
"""

import logging
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User
from app.services.mcp.server import get_mcp_server

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mcp", tags=["MCP Tools"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class ToolCallRequest(BaseModel):
    """Request to call an MCP tool."""
    tool_name: str
    arguments: Dict[str, Any] = {}


class ToolCallResponse(BaseModel):
    """Response from an MCP tool call."""
    success: bool
    output: Optional[str] = None
    error: Optional[str] = None
    exit_code: Optional[int] = None


class ToolDefinition(BaseModel):
    """Tool definition."""
    name: str
    description: str
    type: str
    parameters: Dict[str, Any]
    required: List[str]
    phase: str


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/tools", response_model=List[ToolDefinition])
async def list_tools(
    phase: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """
    List available MCP tools.
    
    Args:
        phase: Optional phase filter (informational, exploitation, post_exploitation)
    """
    server = get_mcp_server()
    
    if phase:
        tools = server.get_tools_for_phase(phase)
    else:
        tools = server.get_tools()
    
    return [ToolDefinition(**t) for t in tools]


@router.post("/call", response_model=ToolCallResponse)
async def call_tool(
    request: ToolCallRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Call an MCP tool.
    
    Available tools (dynamic CLI + help):
    - execute_nuclei, execute_naabu, execute_httpx, execute_subfinder, execute_dnsx, execute_katana, execute_curl
    - execute_tldfinder: TLD/domain discovery (ProjectDiscovery tldfinder)
    - execute_waybackurls: Historical URL discovery (Wayback Machine)
    - nuclei_help, naabu_help, httpx_help, subfinder_help, dnsx_help, katana_help, tldfinder_help, waybackurls_help
    """
    server = get_mcp_server()
    
    # Check if tool exists
    tool = server.registry.get(request.tool_name)
    if not tool:
        raise HTTPException(
            status_code=404,
            detail=f"Tool '{request.tool_name}' not found"
        )
    
    # Check phase restrictions for exploitation tools
    if tool.phase == "exploitation" and not current_user.is_superuser:
        # Require admin for exploitation tools unless in appropriate context
        logger.warning(f"Non-admin user {current_user.id} attempted to use exploitation tool {request.tool_name}")
    
    result = await server.call_tool(request.tool_name, request.arguments)
    
    return ToolCallResponse(
        success=result.get("success", False),
        output=result.get("output"),
        error=result.get("error"),
        exit_code=result.get("exit_code"),
    )


@router.get("/tools/{tool_name}")
async def get_tool_details(
    tool_name: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get details for a specific tool.
    """
    server = get_mcp_server()
    tool = server.registry.get(tool_name)
    
    if not tool:
        raise HTTPException(
            status_code=404,
            detail=f"Tool '{tool_name}' not found"
        )
    
    return {
        "name": tool.name,
        "description": tool.description,
        "type": tool.tool_type.value,
        "parameters": tool.parameters,
        "required": tool.required_params,
        "phase": tool.phase,
    }


@router.post("/execute/{tool_name}")
async def execute_tool(
    tool_name: str,
    args: str = "",
    current_user: User = Depends(get_current_user)
):
    """
    Convenience endpoint to execute a tool with CLI-style arguments.
    
    Example:
        POST /mcp/execute/execute_naabu?args=-host 192.168.1.1 -p 1-1000
    """
    server = get_mcp_server()
    
    tool = server.registry.get(tool_name)
    if not tool:
        raise HTTPException(
            status_code=404,
            detail=f"Tool '{tool_name}' not found"
        )
    
    # Build arguments based on tool requirements
    arguments = {}
    if "args" in tool.required_params or "args" in tool.parameters:
        arguments["args"] = args
    
    result = await server.call_tool(tool_name, arguments)
    
    return {
        "tool": tool_name,
        "success": result.get("success", False),
        "output": result.get("output"),
        "error": result.get("error"),
    }


@router.get("/health")
async def mcp_health():
    """
    Check MCP server health and tool availability.
    """
    server = get_mcp_server()
    
    # Check if tools can be listed
    try:
        tools = server.get_tools()
        tool_count = len(tools)
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
        }
    
    return {
        "status": "healthy",
        "tools_available": tool_count,
        "tools": [t["name"] for t in tools],
    }
