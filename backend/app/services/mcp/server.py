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
from typing import Optional, List, Dict, Any, Callable, Union
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
        
        # Atlas (Aegis Vanguard) - org-wide attack surface mapping (wraps Praetorian pius)
        self.registry.register(MCPTool(
            name="execute_atlas",
            description="Atlas — Aegis Vanguard's attack-surface cartographer (wraps Praetorian pius). Example: 'run --org \"Acme Corp\" --domain acme.com --output ndjson --mode passive'. Discovers domains (CT logs, passive DNS, WHOIS, GLEIF) and IP netblocks across all 5 RIRs.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Atlas/pius CLI arguments (e.g., 'run --org \"Acme Corp\" --domain acme.com --output ndjson --mode passive')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_atlas,
        ))
        self.registry.register(MCPTool(
            name="atlas_help",
            description="Get Atlas (pius) command usage and plugin list.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._atlas_help,
        ))

        # Argus (Aegis Vanguard) - all-seeing secrets scanner (wraps Praetorian titus)
        self.registry.register(MCPTool(
            name="execute_argus",
            description="Argus — Aegis Vanguard's all-seeing secrets scanner (wraps Praetorian titus, 487 detection rules, optional live credential validation). Example: 'scan /path/to/repo --format json --validate' or 'scan github.com/org/repo --format json'.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Argus/titus CLI arguments (e.g., 'scan /workspace/target --format json --validate')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_argus,
        ))
        self.registry.register(MCPTool(
            name="argus_help",
            description="Get Argus (titus) command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._argus_help,
        ))

        # Hermes (Aegis Vanguard) - remote secrets finder (wraps TruffleHog v3)
        self.registry.register(MCPTool(
            name="execute_hermes",
            description=(
                "Hermes — Aegis Vanguard's remote secrets-finder (wraps TruffleHog v3). "
                "Hunts leaked credentials in sources outside the local filesystem: "
                "GitHub/GitLab orgs, S3/GCS/Azure blobs, Docker images, Postman workspaces, "
                "Jenkins, Jira, Confluence, and more. Complements Argus (local secrets). "
                "Examples: 'git https://github.com/org/repo --json --no-update', "
                "'github --org=acme --only-verified --json --no-update', "
                "'s3 --bucket=my-bucket --json --no-update', "
                "'docker --image=acme/app:latest --json --no-update'."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Hermes/trufflehog CLI arguments (e.g., 'github --org=acme --only-verified --json --no-update')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_hermes,
        ))
        self.registry.register(MCPTool(
            name="hermes_help",
            description="Get Hermes (trufflehog) command usage and available sources.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._hermes_help,
        ))

        # Janus (Aegis Vanguard) - DAST gatekeeper (wraps OWASP ZAP)
        self.registry.register(MCPTool(
            name="execute_janus",
            description=(
                "Janus — Aegis Vanguard's two-faced DAST gatekeeper (wraps OWASP ZAP). "
                "Baseline mode = passive spider + passive rules only (CI-safe). "
                "Full mode = baseline + active attack scan (in-scope only). "
                "Complements nuclei by actually spidering the app, maintaining session, "
                "and finding reflective XSS / CSRF / CORS / business-logic issues. "
                "Examples: 'zap-baseline.py -t https://example.com -J report.json -m 5', "
                "'zap-full-scan.py -t https://example.com -J report.json -m 10 -j'."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Janus/ZAP CLI arguments (e.g., 'zap-baseline.py -t https://example.com -J report.json -m 5')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_janus,
        ))
        self.registry.register(MCPTool(
            name="janus_help",
            description="Get Janus (OWASP ZAP baseline/full) command usage.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._janus_help,
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
        
        # Knockpy - active subdomain brute-forcing
        self.registry.register(MCPTool(
            name="execute_knockpy",
            description="Run Knockpy for active subdomain brute-forcing and DNS enumeration. Discovers subdomains by wordlist-based brute-forcing and zone transfer checks.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Knockpy CLI arguments (e.g., 'example.com' or 'example.com --json')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_knockpy,
        ))
        self.registry.register(MCPTool(
            name="knockpy_help",
            description="Get Knockpy command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._knockpy_help,
        ))
        
        # GAU (GetAllUrls) - passive URL discovery from multiple sources
        self.registry.register(MCPTool(
            name="execute_gau",
            description="Run GAU (GetAllUrls) for passive URL discovery from Wayback Machine, Common Crawl, OTX, and URLScan. More comprehensive than waybackurls as it aggregates multiple archive sources.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "GAU CLI arguments (e.g., 'example.com' or 'example.com --subs --json')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_gau,
        ))
        self.registry.register(MCPTool(
            name="gau_help",
            description="Get GAU (GetAllUrls) command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._gau_help,
        ))
        
        # Kiterunner - API endpoint brute-forcer
        self.registry.register(MCPTool(
            name="execute_kiterunner",
            description="Run Kiterunner for API endpoint brute-forcing. Discovers hidden API routes using smart wordlists and content-length analysis. Effective for finding undocumented REST/GraphQL endpoints.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Kiterunner CLI arguments (e.g., 'scan https://target.com -w routes-large.kite' or 'scan https://target.com -A=apiroutes-210228')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_kiterunner,
        ))
        self.registry.register(MCPTool(
            name="kiterunner_help",
            description="Get Kiterunner command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._kiterunner_help,
        ))
        
        # Wappalyzer - technology fingerprinting (Python-based, uses built-in fingerprint DB)
        self.registry.register(MCPTool(
            name="execute_wappalyzer",
            description="Run Wappalyzer technology fingerprinting against a URL. Detects 6,000+ technologies including CMS, frameworks, analytics, CDN, WAF, payment processors, and more. Returns JSON with detected technologies, versions, and confidence scores.",
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Target URL to fingerprint (e.g., 'https://example.com')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_wappalyzer,
        ))
        
        # crt.sh - certificate transparency subdomain discovery
        self.registry.register(MCPTool(
            name="execute_crtsh",
            description="Query crt.sh certificate transparency logs to discover subdomains from SSL/TLS certificates. Passive reconnaissance - no direct target interaction. Returns subdomains found in CT logs.",
            tool_type=ToolType.QUERY,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Domain to query CT logs for (e.g., 'example.com')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_crtsh,
        ))
        
        # Schemathesis - API fuzzer for OpenAPI/GraphQL schemas
        self.registry.register(MCPTool(
            name="execute_schemathesis",
            description=(
                "Run Schemathesis API fuzzer against OpenAPI or GraphQL schema endpoints. "
                "Automatically generates test cases from the schema to find server errors, "
                "validation issues, and security flaws (500 errors, crashes, auth bypasses). "
                "Provide the URL to the OpenAPI spec (e.g., /openapi.json, /swagger.json, /docs) "
                "or a GraphQL endpoint."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Schemathesis CLI arguments (e.g., 'run https://target.com/openapi.json --checks all' or 'run https://target.com/graphql --checks all')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_schemathesis,
        ))
        self.registry.register(MCPTool(
            name="schemathesis_help",
            description="Get Schemathesis command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._schemathesis_help,
        ))
        
        # SQLMap - SQL injection automation
        self.registry.register(MCPTool(
            name="execute_sqlmap",
            description=(
                "Run SQLMap for automated SQL injection detection and exploitation. "
                "Supports detection of all major SQL injection types: error-based, boolean-based blind, "
                "time-based blind, UNION query, stacked queries, and out-of-band. "
                "Example: '-u \"http://target.com/page?id=1\" --batch --level=3 --risk=2 --dbs'."
            ),
            tool_type=ToolType.EXPLOIT,
            parameters={
                "args": {
                    "type": "string",
                    "description": "SQLMap CLI arguments (e.g., '-u \"http://target.com/page?id=1\" --batch --dbs')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_sqlmap,
        ))
        self.registry.register(MCPTool(
            name="sqlmap_help",
            description="Get SQLMap command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._sqlmap_help,
        ))
        
        # Nikto - web server vulnerability scanner
        self.registry.register(MCPTool(
            name="execute_nikto",
            description=(
                "Run Nikto web server vulnerability scanner. Checks for dangerous files, "
                "outdated server versions, insecure configurations, default files, and "
                "6,700+ potentially dangerous CGIs. "
                "Example: '-h http://target.com -Format json'."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Nikto CLI arguments (e.g., '-h http://target.com -Format json')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_nikto,
        ))
        self.registry.register(MCPTool(
            name="nikto_help",
            description="Get Nikto command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._nikto_help,
        ))
        
        # wafw00f - WAF detection
        self.registry.register(MCPTool(
            name="execute_wafw00f",
            description=(
                "Run wafw00f to detect Web Application Firewalls (WAFs). "
                "Identifies WAF vendor/product protecting a website. "
                "Useful to run before injection testing to understand protections. "
                "Example: 'https://target.com' or '-a https://target.com' (test all WAFs)."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "wafw00f CLI arguments (e.g., 'https://target.com' or '-a https://target.com')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_wafw00f,
        ))
        self.registry.register(MCPTool(
            name="wafw00f_help",
            description="Get wafw00f command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._wafw00f_help,
        ))
        
        # testssl.sh - TLS/SSL testing
        self.registry.register(MCPTool(
            name="execute_testssl",
            description=(
                "Run testssl.sh for comprehensive TLS/SSL testing. Checks protocols, ciphers, "
                "vulnerabilities (Heartbleed, POODLE, BEAST, ROBOT, etc.), certificate details, "
                "and security headers. Example: 'https://target.com' or '--json https://target.com'."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "testssl.sh CLI arguments (e.g., 'https://target.com' or '--json https://target.com')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_testssl,
        ))
        self.registry.register(MCPTool(
            name="testssl_help",
            description="Get testssl.sh command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._testssl_help,
        ))
        
        # SSLyze - Python TLS scanner
        self.registry.register(MCPTool(
            name="execute_sslyze",
            description=(
                "Run SSLyze for fast TLS/SSL configuration analysis. Tests certificate validation, "
                "supported cipher suites, protocol versions, and known TLS vulnerabilities. "
                "Python-based, faster than testssl.sh for targeted checks. "
                "Example: 'target.com' or '--json_out=- target.com:443'."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "SSLyze CLI arguments (e.g., 'target.com' or '--json_out=- target.com')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_sslyze,
        ))
        self.registry.register(MCPTool(
            name="sslyze_help",
            description="Get SSLyze command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._sslyze_help,
        ))
        
        # Arjun - HTTP parameter discovery
        self.registry.register(MCPTool(
            name="execute_arjun",
            description=(
                "Run Arjun for HTTP parameter discovery. Finds hidden GET/POST parameters "
                "using a smart wordlist and response analysis. Useful before injection testing. "
                "Example: '-u https://target.com/api/endpoint' or '-u https://target.com/search -m POST'."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Arjun CLI arguments (e.g., '-u https://target.com/search')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_arjun,
        ))
        self.registry.register(MCPTool(
            name="arjun_help",
            description="Get Arjun command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._arjun_help,
        ))
        
        # WPScan - WordPress scanner
        self.registry.register(MCPTool(
            name="execute_wpscan",
            description=(
                "Run WPScan for WordPress vulnerability scanning. Detects WordPress version, "
                "plugins, themes, users, and known vulnerabilities. Use when WordPress is detected. "
                "Example: '--url https://target.com --enumerate vp,vt,u' or '--url https://target.com --api-token YOUR_TOKEN'."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "WPScan CLI arguments (e.g., '--url https://target.com --enumerate vp,vt,u')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_wpscan,
        ))
        self.registry.register(MCPTool(
            name="wpscan_help",
            description="Get WPScan command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._wpscan_help,
        ))
        
        # XSStrike - XSS scanner
        self.registry.register(MCPTool(
            name="execute_xsstrike",
            description=(
                "Run XSStrike for advanced XSS vulnerability detection. Uses fuzzy matching, "
                "context analysis, and payload generation to find reflected, stored, and DOM XSS. "
                "Example: '-u \"https://target.com/search?q=test\"' or '-u \"https://target.com/search?q=test\" --crawl'."
            ),
            tool_type=ToolType.EXPLOIT,
            parameters={
                "args": {
                    "type": "string",
                    "description": "XSStrike CLI arguments (e.g., '-u \"https://target.com/search?q=test\"')"
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_xsstrike,
        ))
        self.registry.register(MCPTool(
            name="xsstrike_help",
            description="Get XSStrike command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._xsstrike_help,
        ))
        
        # Gitleaks - secret scanning
        self.registry.register(MCPTool(
            name="execute_gitleaks",
            description=(
                "Run Gitleaks to detect hardcoded secrets (API keys, passwords, tokens) in git repos "
                "or directories. Scans commit history for leaked credentials. "
                "Example: 'detect --source /path/to/repo' or 'detect --source https://github.com/org/repo'."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "Gitleaks CLI arguments (e.g., 'detect --source /path/to/repo --report-format json')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_gitleaks,
        ))
        self.registry.register(MCPTool(
            name="gitleaks_help",
            description="Get Gitleaks command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._gitleaks_help,
        ))

        # Remote JS / text assets — secret scan (fetch + gitleaks --no-git + regex hints)
        self.registry.register(MCPTool(
            name="scan_js_urls_for_secrets",
            description=(
                "Download one or more http(s) URLs (typically .js bundles from Katana/crawl), "
                "write them to a temp directory, run Gitleaks in --no-git mode for hardcoded secrets, "
                "and add regex-based hints (API keys, tokens) per URL. "
                "Pass newline- or comma-separated URLs. Use after execute_katana to scan discovered script URLs."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "urls": {
                    "type": "string",
                    "description": (
                        "Newline- or comma-separated https URLs to fetch and scan "
                        "(e.g. clientlib bundles, /static/*.js)."
                    ),
                },
                "max_urls": {
                    "type": "integer",
                    "description": "Max URLs to fetch (default 30, cap 100).",
                },
            },
            required_params=["urls"],
            phase="informational",
            handler=self._scan_js_urls_for_secrets,
        ))
        
        # CMSeeK - CMS detection
        self.registry.register(MCPTool(
            name="execute_cmseek",
            description=(
                "Run CMSeeK for CMS detection and vulnerability scanning. Detects 180+ CMS "
                "(WordPress, Joomla, Drupal, etc.) and their vulnerabilities. "
                "Example: '-u https://target.com' or '-u https://target.com --batch'."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "args": {
                    "type": "string",
                    "description": "CMSeeK CLI arguments (e.g., '-u https://target.com')"
                }
            },
            required_params=["args"],
            phase="informational",
            handler=self._execute_cmseek,
        ))
        self.registry.register(MCPTool(
            name="cmseek_help",
            description="Get CMSeeK command usage and options.",
            tool_type=ToolType.QUERY,
            parameters={},
            required_params=[],
            phase="informational",
            handler=self._cmseek_help,
        ))
        
        # Browser automation - headless browser for live exploit execution
        self.registry.register(MCPTool(
            name="execute_browser",
            description=(
                "Headless browser automation for live web application exploit testing. "
                "Supports XSS detection (check_xss), form injection (submit_form), "
                "authentication bypass (set_cookie, check_response), SSRF detection "
                "(monitors outgoing network requests), JavaScript execution (execute_js), "
                "and multi-step exploit chains with session persistence. "
                "Pass a JSON object with an 'actions' array."
            ),
            tool_type=ToolType.EXPLOIT,
            parameters={
                "args": {
                    "type": "string",
                    "description": (
                        'JSON actions. Example: \'{"actions": ['
                        '{"action": "navigate", "url": "https://target.com/login"}, '
                        '{"action": "fill", "selector": "#user", "value": "admin"}, '
                        '{"action": "click", "selector": "#submit"}, '
                        '{"action": "get_cookies"}]}\''
                    )
                }
            },
            required_params=["args"],
            phase="exploitation",
            handler=self._execute_browser,
        ))
        
        # LLM Red Team Scanner
        self.registry.register(MCPTool(
            name="execute_llm_red_team",
            description=(
                "Run LLM red team security assessment against chatbot/AI endpoints. "
                "Tests for prompt injection, jailbreak, data exfiltration, SSRF, "
                "excessive agency, and more. Auto-discovers chat endpoints on the target."
            ),
            tool_type=ToolType.SCAN,
            parameters={
                "target_url": {
                    "type": "string",
                    "description": "Target URL to scan for chatbot/AI endpoints"
                },
                "categories": {
                    "type": "string",
                    "description": "Comma-separated attack categories (prompt_injection,jailbreak,data_exfiltration,ssrf_tool_abuse,system_prompt_leakage,excessive_agency,hallucination,harmful_content). Omit for all."
                },
                "endpoint_url": {
                    "type": "string",
                    "description": "Direct URL to a known chatbot API endpoint (optional)"
                },
                "message_field": {
                    "type": "string",
                    "description": "JSON field name for the message in the API request (default: message)"
                },
            },
            required_params=["target_url"],
            phase="exploitation",
            handler=None,  # Handled by ASMToolsManager directly
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
    
    # Blocked URL patterns for SSRF prevention
    _BLOCKED_CURL_PATTERNS = [
        "169.254.169.254",   # AWS metadata
        "metadata.google",    # GCP metadata
        "100.100.100.200",   # Alibaba metadata
        "metadata.azure",     # Azure metadata
        "file://",            # Local file access
        "gopher://",          # Gopher protocol abuse
        "dict://",            # Dict protocol abuse
        "ftp://localhost",    # Local FTP
        "127.0.0.1",         # Localhost
        "0.0.0.0",           # All interfaces
        "[::1]",             # IPv6 localhost
        "localhost",          # Localhost by name
    ]

    async def _execute_curl(self, args: str) -> Dict[str, Any]:
        # SSRF prevention: block access to metadata endpoints and internal services
        args_lower = args.lower()
        for pattern in self._BLOCKED_CURL_PATTERNS:
            if pattern.lower() in args_lower:
                return {
                    "success": False,
                    "output": "",
                    "error": f"Blocked: curl access to '{pattern}' is not allowed (SSRF prevention). "
                             f"Only external targets within your organization's scope are permitted.",
                    "exit_code": -1,
                }
        cmd = ["curl", "--max-time", "30"] + self._parse_args(args)
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

    async def _execute_atlas(self, args: str) -> Dict[str, Any]:
        cmd = ["pius"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=900)

    async def _atlas_help(self) -> Dict[str, Any]:
        return await self._run_command(["pius", "--help"], timeout=MCP_HELP_TIMEOUT)

    async def _execute_argus(self, args: str) -> Dict[str, Any]:
        cmd = ["titus"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=900)

    async def _argus_help(self) -> Dict[str, Any]:
        return await self._run_command(["titus", "--help"], timeout=MCP_HELP_TIMEOUT)

    async def _execute_hermes(self, args: str) -> Dict[str, Any]:
        cmd = ["trufflehog"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=900)

    async def _hermes_help(self) -> Dict[str, Any]:
        return await self._run_command(["trufflehog", "--help"], timeout=MCP_HELP_TIMEOUT)

    async def _execute_janus(self, args: str) -> Dict[str, Any]:
        """
        Janus routes to the right ZAP entrypoint based on the first token.
        Callers may pass 'zap-baseline.py ...' / 'zap-full-scan.py ...' or plain
        ZAP CLI flags — in the latter case we default to the baseline script.
        """
        parts = self._parse_args(args)
        if not parts:
            return {"error": "Janus requires arguments (e.g., 'zap-baseline.py -t https://example.com -J report.json')"}
        first = parts[0]
        if first in ("zap-baseline.py", "zap-full-scan.py", "zap.sh"):
            cmd = parts
        else:
            cmd = ["zap-baseline.py"] + parts
        return await self._run_command(cmd, timeout=1800)

    async def _janus_help(self) -> Dict[str, Any]:
        return await self._run_command(["zap-baseline.py", "--help"], timeout=MCP_HELP_TIMEOUT)
    
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
    
    async def _execute_knockpy(self, args: str) -> Dict[str, Any]:
        cmd = ["knockpy"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _knockpy_help(self) -> Dict[str, Any]:
        return await self._run_command(["knockpy", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_gau(self, args: str) -> Dict[str, Any]:
        cmd = ["gau"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=300)
    
    async def _gau_help(self) -> Dict[str, Any]:
        return await self._run_command(["gau", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_kiterunner(self, args: str) -> Dict[str, Any]:
        cmd = ["kiterunner"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _kiterunner_help(self) -> Dict[str, Any]:
        return await self._run_command(["kiterunner", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_wappalyzer(self, args: str) -> Dict[str, Any]:
        """Run Wappalyzer fingerprinting using the built-in Python service."""
        import json as _json
        url = args.strip()
        if not url:
            return {"success": False, "output": "", "error": "URL is required. Example: execute_wappalyzer(args=\"https://example.com\")", "exit_code": -1}
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        try:
            from app.services.wappalyzer_service import WappalyzerService
            svc = WappalyzerService()
            techs = await svc.analyze_url(url)
            if not techs:
                return {"success": True, "output": f"No technologies detected for {url}", "error": None, "exit_code": 0}
            results = []
            for t in techs:
                entry = {"name": t.name, "confidence": t.confidence, "categories": t.categories}
                if t.version:
                    entry["version"] = t.version
                if t.cpe:
                    entry["cpe"] = t.cpe
                if t.website:
                    entry["website"] = t.website
                results.append(entry)
            output = f"Wappalyzer detected {len(results)} technologies for {url}:\n\n"
            output += _json.dumps(results, indent=2)
            return {"success": True, "output": output, "error": None, "exit_code": 0}
        except Exception as e:
            logger.error(f"Wappalyzer scan failed for {url}: {e}")
            return {"success": False, "output": "", "error": f"Wappalyzer error: {e}", "exit_code": -1}
    
    async def _execute_crtsh(self, args: str) -> Dict[str, Any]:
        """Query crt.sh certificate transparency logs."""
        import json as _json
        domain = args.strip().lower()
        if not domain:
            return {"success": False, "output": "", "error": "Domain is required. Example: execute_crtsh(args=\"example.com\")", "exit_code": -1}
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/").split("/")[0]
        try:
            import httpx as _httpx
            async with _httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    follow_redirects=True
                )
                if response.status_code != 200:
                    return {"success": False, "output": "", "error": f"crt.sh returned HTTP {response.status_code}", "exit_code": -1}
                data = response.json()
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.startswith("*."):
                        n = n[2:]
                    if n.endswith(f".{domain}") or n == domain:
                        subdomains.add(n)
            sorted_subs = sorted(subdomains)
            output = f"crt.sh found {len(sorted_subs)} unique subdomains for {domain}:\n\n"
            output += "\n".join(sorted_subs)
            return {"success": True, "output": output, "error": None, "exit_code": 0}
        except Exception as e:
            logger.error(f"crt.sh query failed for {domain}: {e}")
            return {"success": False, "output": "", "error": f"crt.sh error: {e}", "exit_code": -1}
    
    async def _execute_schemathesis(self, args: str) -> Dict[str, Any]:
        parsed = self._parse_args(args)
        if parsed and parsed[0] != "run":
            parsed.insert(0, "run")
        cmd = ["schemathesis"] + parsed
        return await self._run_command(cmd, timeout=600)
    
    async def _schemathesis_help(self) -> Dict[str, Any]:
        return await self._run_command(["schemathesis", "run", "--help"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_browser(self, args: str) -> Dict[str, Any]:
        """Execute browser automation actions for security testing."""
        try:
            from app.services.browser_automation_service import execute_browser_actions
            return await execute_browser_actions(args)
        except ImportError as e:
            return {"success": False, "output": "", "error": f"Browser automation service not available: {e}", "exit_code": -1}
        except Exception as e:
            logger.error(f"Browser automation failed: {e}")
            return {"success": False, "output": "", "error": f"Browser automation error: {e}", "exit_code": -1}
    
    # --- New Guardian-parity tools ---
    
    async def _execute_sqlmap(self, args: str) -> Dict[str, Any]:
        cmd = ["sqlmap"] + self._parse_args(args)
        if "--batch" not in args:
            cmd.append("--batch")
        return await self._run_command(cmd, timeout=600)
    
    async def _sqlmap_help(self) -> Dict[str, Any]:
        return await self._run_command(["sqlmap", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_nikto(self, args: str) -> Dict[str, Any]:
        cmd = ["nikto"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _nikto_help(self) -> Dict[str, Any]:
        return await self._run_command(["nikto", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_wafw00f(self, args: str) -> Dict[str, Any]:
        cmd = ["wafw00f"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=120)
    
    async def _wafw00f_help(self) -> Dict[str, Any]:
        return await self._run_command(["wafw00f", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_testssl(self, args: str) -> Dict[str, Any]:
        cmd = ["testssl"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=600)
    
    async def _testssl_help(self) -> Dict[str, Any]:
        return await self._run_command(["testssl", "--help"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_sslyze(self, args: str) -> Dict[str, Any]:
        cmd = ["sslyze"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=300)
    
    async def _sslyze_help(self) -> Dict[str, Any]:
        return await self._run_command(["sslyze", "--help"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_arjun(self, args: str) -> Dict[str, Any]:
        cmd = ["arjun"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=300)
    
    async def _arjun_help(self) -> Dict[str, Any]:
        return await self._run_command(["arjun", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_wpscan(self, args: str) -> Dict[str, Any]:
        cmd = ["wpscan"] + self._parse_args(args)
        if "--no-banner" not in args:
            cmd.append("--no-banner")
        return await self._run_command(cmd, timeout=600)
    
    async def _wpscan_help(self) -> Dict[str, Any]:
        return await self._run_command(["wpscan", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_xsstrike(self, args: str) -> Dict[str, Any]:
        cmd = ["xsstrike"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=300)
    
    async def _xsstrike_help(self) -> Dict[str, Any]:
        return await self._run_command(["xsstrike", "-h"], timeout=MCP_HELP_TIMEOUT)
    
    async def _execute_gitleaks(self, args: str) -> Dict[str, Any]:
        cmd = ["gitleaks"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=300)
    
    async def _gitleaks_help(self) -> Dict[str, Any]:
        return await self._run_command(["gitleaks", "--help"], timeout=MCP_HELP_TIMEOUT)

    async def _scan_js_urls_for_secrets(
        self, urls: str, max_urls: Optional[Union[int, str]] = None,
    ) -> Dict[str, Any]:
        from app.services.js_url_secrets_service import scan_js_urls_for_secrets

        try:
            mu = int(max_urls) if max_urls is not None else 30
        except (TypeError, ValueError):
            mu = 30
        mu = max(1, min(mu, 100))

        try:
            result = await asyncio.to_thread(scan_js_urls_for_secrets, urls, mu)
        except Exception as e:
            logger.exception("scan_js_urls_for_secrets failed")
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "exit_code": -1,
            }

        out = json.dumps(result, indent=2, default=str)
        return {
            "success": bool(result.get("success", True)),
            "output": out,
            "error": result.get("error") if result.get("success") is False else None,
            "exit_code": 0,
        }
    
    async def _execute_cmseek(self, args: str) -> Dict[str, Any]:
        cmd = ["cmseek"] + self._parse_args(args)
        return await self._run_command(cmd, timeout=300)
    
    async def _cmseek_help(self) -> Dict[str, Any]:
        return await self._run_command(["cmseek", "-h"], timeout=MCP_HELP_TIMEOUT)
    
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
