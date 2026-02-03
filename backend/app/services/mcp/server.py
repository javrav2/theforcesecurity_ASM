"""
MCP Server Implementation

Provides a server for exposing security tools via the Model Context Protocol.
"""

import asyncio
import json
import logging
import subprocess
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum

from app.core.config import settings

logger = logging.getLogger(__name__)


class ToolType(str, Enum):
    """Types of MCP tools."""
    SCAN = "scan"
    QUERY = "query"
    ANALYZE = "analyze"
    EXPLOIT = "exploit"


@dataclass
class MCPTool:
    """Definition of an MCP tool."""
    name: str
    description: str
    tool_type: ToolType
    parameters: Dict[str, Any]
    required_params: List[str] = field(default_factory=list)
    phase: str = "informational"
    handler: Optional[Callable] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "description": self.description,
            "type": self.tool_type.value,
            "parameters": self.parameters,
            "required": self.required_params,
            "phase": self.phase,
        }


class MCPToolRegistry:
    """Registry for MCP tools."""
    
    def __init__(self):
        self.tools: Dict[str, MCPTool] = {}
    
    def register(self, tool: MCPTool):
        """Register a tool."""
        self.tools[tool.name] = tool
        logger.info(f"Registered MCP tool: {tool.name}")
    
    def get(self, name: str) -> Optional[MCPTool]:
        """Get a tool by name."""
        return self.tools.get(name)
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """List all registered tools."""
        return [tool.to_dict() for tool in self.tools.values()]
    
    def get_tools_for_phase(self, phase: str) -> List[Dict[str, Any]]:
        """Get tools available in a specific phase."""
        return [
            tool.to_dict() for tool in self.tools.values()
            if tool.phase == phase or tool.phase == "all"
        ]


class MCPServer:
    """
    MCP Server for exposing security tools.
    
    Supports both SSE (Server-Sent Events) and stdio transports.
    """
    
    def __init__(self, name: str = "asm-mcp-server"):
        self.name = name
        self.registry = MCPToolRegistry()
        self._register_default_tools()
    
    def _register_default_tools(self):
        """Register default security tools."""
        
        # Nuclei vulnerability scanner
        self.registry.register(MCPTool(
            name="execute_nuclei",
            description="Run Nuclei vulnerability scanner against targets. Supports templates, severity filtering, and various output formats.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Nuclei CLI arguments (e.g., '-u http://target.com -severity critical,high -jsonl')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_nuclei,
        ))
        
        # Nuclei help
        self.registry.register(MCPTool(
            name="nuclei_help",
            description="Get Nuclei command usage information.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._nuclei_help,
        ))
        
        # Naabu port scanner
        self.registry.register(MCPTool(
            name="execute_naabu",
            description="Run Naabu port scanner. Fast SYN/CONNECT port scanning.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Naabu CLI arguments (e.g., '-host 192.168.1.1 -p 1-1000 -json')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_naabu,
        ))
        
        # Naabu help
        self.registry.register(MCPTool(
            name="naabu_help",
            description="Get Naabu command usage information.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._naabu_help,
        ))
        
        # HTTPX HTTP prober
        self.registry.register(MCPTool(
            name="execute_httpx",
            description="Run HTTPX to probe HTTP endpoints for live URLs and technology detection.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "HTTPX CLI arguments (e.g., '-u http://target.com -json -tech-detect')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_httpx,
        ))
        
        # Subfinder subdomain discovery
        self.registry.register(MCPTool(
            name="execute_subfinder",
            description="Run Subfinder for subdomain enumeration.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Subfinder CLI arguments (e.g., '-d example.com -json')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_subfinder,
        ))
        
        # DNSX DNS toolkit
        self.registry.register(MCPTool(
            name="execute_dnsx",
            description="Run DNSX for DNS resolution and record enumeration.",
            tool_type=ToolType.QUERY,
            parameters={
                "args": {
                    "type": "string",
                    "description": "DNSX CLI arguments (e.g., '-d example.com -a -aaaa -mx -ns')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_dnsx,
        ))
        
        # Katana web crawler
        self.registry.register(MCPTool(
            name="execute_katana",
            description="Run Katana web crawler for endpoint discovery.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Katana CLI arguments (e.g., '-u http://target.com -d 3 -json')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_katana,
        ))
        
        # Curl HTTP client
        self.registry.register(MCPTool(
            name="execute_curl",
            description="Execute curl for HTTP requests. Useful for probing endpoints and testing APIs.",
            tool_type=ToolType.QUERY,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Curl CLI arguments (e.g., '-s -i http://target.com/')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_curl,
        ))
    
    async def _run_command(
        self,
        command: List[str],
        timeout: int = 300
    ) -> Dict[str, Any]:
        """Run a shell command and return the result."""
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            return {
                "success": process.returncode == 0,
                "output": stdout.decode("utf-8", errors="ignore"),
                "error": stderr.decode("utf-8", errors="ignore") if process.returncode != 0 else None,
                "exit_code": process.returncode,
            }
        
        except asyncio.TimeoutError:
            return {
                "success": False,
                "output": "",
                "error": f"Command timed out after {timeout} seconds",
                "exit_code": -1,
            }
        except FileNotFoundError as e:
            return {
                "success": False,
                "output": "",
                "error": f"Command not found: {e}",
                "exit_code": -1,
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "exit_code": -1,
            }
    
    async def _execute_nuclei(self, args: str) -> Dict[str, Any]:
        """Execute Nuclei scanner."""
        cmd = ["nuclei"] + args.split()
        return await self._run_command(cmd, timeout=600)
    
    async def _nuclei_help(self) -> Dict[str, Any]:
        """Get Nuclei help."""
        return await self._run_command(["nuclei", "-h"])
    
    async def _execute_naabu(self, args: str) -> Dict[str, Any]:
        """Execute Naabu port scanner."""
        cmd = ["naabu"] + args.split()
        return await self._run_command(cmd, timeout=300)
    
    async def _naabu_help(self) -> Dict[str, Any]:
        """Get Naabu help."""
        return await self._run_command(["naabu", "-h"])
    
    async def _execute_httpx(self, args: str) -> Dict[str, Any]:
        """Execute HTTPX prober."""
        cmd = ["httpx"] + args.split()
        return await self._run_command(cmd, timeout=300)
    
    async def _execute_subfinder(self, args: str) -> Dict[str, Any]:
        """Execute Subfinder."""
        cmd = ["subfinder"] + args.split()
        return await self._run_command(cmd, timeout=300)
    
    async def _execute_dnsx(self, args: str) -> Dict[str, Any]:
        """Execute DNSX."""
        cmd = ["dnsx"] + args.split()
        return await self._run_command(cmd, timeout=120)
    
    async def _execute_katana(self, args: str) -> Dict[str, Any]:
        """Execute Katana crawler."""
        cmd = ["katana"] + args.split()
        return await self._run_command(cmd, timeout=600)
    
    async def _execute_curl(self, args: str) -> Dict[str, Any]:
        """Execute curl."""
        cmd = ["curl"] + args.split()
        return await self._run_command(cmd, timeout=60)
    
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a registered tool.
        
        Args:
            name: Tool name
            arguments: Tool arguments
        
        Returns:
            Tool execution result
        """
        tool = self.registry.get(name)
        
        if not tool:
            return {
                "success": False,
                "error": f"Tool '{name}' not found",
            }
        
        if not tool.handler:
            return {
                "success": False,
                "error": f"Tool '{name}' has no handler",
            }
        
        # Validate required parameters
        for param in tool.required_params:
            if param not in arguments:
                return {
                    "success": False,
                    "error": f"Missing required parameter: {param}",
                }
        
        try:
            result = await tool.handler(**arguments)
            return result
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            return {
                "success": False,
                "error": str(e),
            }
    
    def get_tools(self) -> List[Dict[str, Any]]:
        """Get list of available tools."""
        return self.registry.list_tools()
    
    def get_tools_for_phase(self, phase: str) -> List[Dict[str, Any]]:
        """Get tools available in a phase."""
        return self.registry.get_tools_for_phase(phase)


# Global server instance
_mcp_server: Optional[MCPServer] = None


def get_mcp_server() -> MCPServer:
    """Get or create the global MCP server."""
    global _mcp_server
    if _mcp_server is None:
        _mcp_server = MCPServer()
    return _mcp_server
