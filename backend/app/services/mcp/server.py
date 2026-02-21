"""
MCP Server Implementation

Provides a server for exposing security tools via the Model Context Protocol.
"""

import asyncio
import json
import logging
import shlex
import subprocess
import time
from typing import Optional, List, Dict, Any, Callable
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum

from app.core.config import settings

logger = logging.getLogger(__name__)

# Help commands should return quickly; use short timeout so missing binaries fail fast
MCP_HELP_TIMEOUT = 15


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
        
        # Help tools: agent can query usage for each tool
        self.registry.register(MCPTool(
            name="httpx_help",
            description="Get HTTPX command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._httpx_help,
        ))
        self.registry.register(MCPTool(
            name="subfinder_help",
            description="Get Subfinder command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._subfinder_help,
        ))
        self.registry.register(MCPTool(
            name="dnsx_help",
            description="Get DNSX command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._dnsx_help,
        ))
        self.registry.register(MCPTool(
            name="katana_help",
            description="Get Katana crawler command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._katana_help,
        ))
        
        # TLDFinder (ProjectDiscovery) - TLD/domain discovery
        self.registry.register(MCPTool(
            name="execute_tldfinder",
            description="Run tldfinder to discover subdomains/domains from multiple sources. Use for better TLD coverage (e.g. -d example.com -dm domain -oJ).",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "tldfinder CLI arguments (e.g., '-d example.com -dm domain -oJ')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_tldfinder,
        ))
        self.registry.register(MCPTool(
            name="tldfinder_help",
            description="Get tldfinder command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._tldfinder_help,
        ))
        
        # WaybackURLs - historical URL discovery
        self.registry.register(MCPTool(
            name="execute_waybackurls",
            description="Run waybackurls to fetch historical URLs for a domain from the Wayback Machine.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "waybackurls CLI arguments (e.g., 'example.com' or pipe from stdin)"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_waybackurls,
        ))
        self.registry.register(MCPTool(
            name="waybackurls_help",
            description="Get waybackurls command usage (if available).",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._waybackurls_help,
        ))
        
        # Nmap - network exploration and service detection (Guardian-style)
        self.registry.register(MCPTool(
            name="execute_nmap",
            description="Run Nmap for port scanning, service/version detection, or script scanning. Example: '-sV -sC -p 80,443 target.com' or '-Pn -sT 192.168.1.0/24'.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Nmap CLI arguments (e.g., '-sV -sC -p 80,443,8080 example.com')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_nmap,
        ))
        self.registry.register(MCPTool(
            name="nmap_help",
            description="Get Nmap command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._nmap_help,
        ))
        
        # Masscan - ultra-fast port scanner (Guardian-style)
        self.registry.register(MCPTool(
            name="execute_masscan",
            description="Run Masscan for very fast port scanning (often requires root). Example: '192.168.1.0/24 -p80,443 --rate=1000'.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Masscan CLI arguments (e.g., '10.0.0.0/8 -p80,443,8080 --rate=1000')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_masscan,
        ))
        self.registry.register(MCPTool(
            name="masscan_help",
            description="Get Masscan command usage.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._masscan_help,
        ))
        
        # FFuf - web fuzzer for directory/parameter discovery (Guardian-style)
        self.registry.register(MCPTool(
            name="execute_ffuf",
            description="Run FFuf for web fuzzing (directory brute-forcing, vhost discovery, parameter fuzzing). Example: '-u https://target.com/FUZZ -w wordlist.txt -mc 200'.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "FFuf CLI arguments (e.g., '-u https://example.com/FUZZ -w /path/to/wordlist -mc 200,301')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_ffuf,
        ))
        self.registry.register(MCPTool(
            name="ffuf_help",
            description="Get FFuf command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._ffuf_help,
        ))
        
        # Amass - subdomain/network mapping (Guardian-style)
        self.registry.register(MCPTool(
            name="execute_amass",
            description="Run Amass for subdomain enumeration and network mapping (passive/active). Example: 'enum -d example.com -json -' or 'intel -org Example'.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Amass CLI arguments (e.g., 'enum -d example.com -o out.txt')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_amass,
        ))
        self.registry.register(MCPTool(
            name="amass_help",
            description="Get Amass command usage.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._amass_help,
        ))
        
        # WhatWeb - tech fingerprinting (Guardian-style; requires: gem install whatweb or apt install whatweb)
        self.registry.register(MCPTool(
            name="execute_whatweb",
            description="Run WhatWeb to identify web technologies (CMS, frameworks, servers, versions). Example: 'https://example.com' or '-a 1 --no-errors https://target.com'. Requires WhatWeb CLI installed.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "WhatWeb CLI arguments (URL and optional flags like -a 1, --log-json)"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_whatweb,
        ))
        self.registry.register(MCPTool(
            name="whatweb_help",
            description="Get WhatWeb command usage.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._whatweb_help,
        ))
    
    @staticmethod
    def _parse_args(args: str) -> List[str]:
        """Parse CLI args string safely (handles quoted values). Returns empty list if args empty."""
        if not args or not args.strip():
            return []
        try:
            return shlex.split(args.strip())
        except ValueError:
            return args.split()  # fallback for malformed quotes
    
    async def _run_command(
        self,
        command: List[str],
        timeout: int = 300,
        max_output_chars: int = 2_000_000,
    ) -> Dict[str, Any]:
        """Run a shell command and return the result. Kills process on timeout; caps output size."""
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            start = time.monotonic()
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                logger.warning(f"MCP command timed out after {timeout}s: {command[:3]}...")
                return {
                    "success": False,
                    "output": "",
                    "error": f"Command timed out after {timeout} seconds (process killed)",
                    "exit_code": -1,
                }
            elapsed = time.monotonic() - start
            out_str = stdout.decode("utf-8", errors="ignore")
            err_str = stderr.decode("utf-8", errors="ignore")
            if len(out_str) > max_output_chars:
                out_str = out_str[:max_output_chars] + f"\n\n... (truncated, {len(stdout)} bytes total)"
            if len(err_str) > max_output_chars:
                err_str = err_str[:max_output_chars] + "\n\n... (stderr truncated)"
            if process.returncode != 0 and err_str:
                logger.debug(f"MCP command finished in {elapsed:.1f}s exit={process.returncode}: {command[0]}")
            return {
                "success": process.returncode == 0,
                "output": out_str,
                "error": err_str if process.returncode != 0 else None,
                "exit_code": process.returncode,
            }
        except FileNotFoundError as e:
            return {
                "success": False,
                "output": "",
                "error": f"Command not found: {e}",
                "exit_code": -1,
            }
        except Exception as e:
            if process and process.returncode is None:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "exit_code": -1,
            }
    
    async def _execute_nuclei(self, args: str) -> Dict[str, Any]:
        """Execute Nuclei scanner."""
        cmd = ["nuclei"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _nuclei_help(self) -> Dict[str, Any]:
        return await self._run_command(["nuclei", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_naabu(self, args: str) -> Dict[str, Any]:
        cmd = ["naabu"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=300)
    
    async def _naabu_help(self) -> Dict[str, Any]:
        return await self._run_command(["naabu", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_httpx(self, args: str) -> Dict[str, Any]:
        cmd = ["httpx"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=300)
    
    async def _execute_subfinder(self, args: str) -> Dict[str, Any]:
        cmd = ["subfinder"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=300)
    
    async def _execute_dnsx(self, args: str) -> Dict[str, Any]:
        cmd = ["dnsx"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=120)
    
    async def _execute_katana(self, args: str) -> Dict[str, Any]:
        cmd = ["katana"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _execute_curl(self, args: str) -> Dict[str, Any]:
        cmd = ["curl"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=60)
    
    async def _httpx_help(self) -> Dict[str, Any]:
        return await self._run_command(["httpx", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _subfinder_help(self) -> Dict[str, Any]:
        return await self._run_command(["subfinder", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _dnsx_help(self) -> Dict[str, Any]:
        return await self._run_command(["dnsx", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _katana_help(self) -> Dict[str, Any]:
        return await self._run_command(["katana", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_tldfinder(self, args: str) -> Dict[str, Any]:
        cmd = ["tldfinder"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _tldfinder_help(self) -> Dict[str, Any]:
        return await self._run_command(["tldfinder", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_waybackurls(self, args: str) -> Dict[str, Any]:
        cmd = ["waybackurls"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=120)
    
    async def _waybackurls_help(self) -> Dict[str, Any]:
        return await self._run_command(["waybackurls", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_nmap(self, args: str) -> Dict[str, Any]:
        cmd = ["nmap"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _nmap_help(self) -> Dict[str, Any]:
        return await self._run_command(["nmap", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_masscan(self, args: str) -> Dict[str, Any]:
        cmd = ["masscan"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _masscan_help(self) -> Dict[str, Any]:
        return await self._run_command(["masscan", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_ffuf(self, args: str) -> Dict[str, Any]:
        cmd = ["ffuf"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _ffuf_help(self) -> Dict[str, Any]:
        return await self._run_command(["ffuf", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_amass(self, args: str) -> Dict[str, Any]:
        cmd = ["amass"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _amass_help(self) -> Dict[str, Any]:
        return await self._run_command(["amass", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_whatweb(self, args: str) -> Dict[str, Any]:
        cmd = ["whatweb"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=120)
    
    async def _whatweb_help(self) -> Dict[str, Any]:
        return await self._run_command(["whatweb", "-h"], timeout=MCP_HELP_TIMEOUT)
    
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
