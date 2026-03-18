"""
Agent Tools

Tools for the AI agent to interact with the ASM platform.
"""

import json
import logging
from typing import List, Optional, Dict, Any
from contextvars import ContextVar
from sqlalchemy.orm import Session

import httpx

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.vulnerability import Vulnerability, Severity
from app.models.port_service import PortService
from app.models.technology import Technology
from app.models.agent_note import AgentNote
from app.core.config import settings

# Max chars for tool output (used for truncation; align with AGENT_TOOL_OUTPUT_MAX_CHARS)
def _tool_output_max_chars() -> int:
    return getattr(settings, "AGENT_TOOL_OUTPUT_MAX_CHARS", 20000)

logger = logging.getLogger(__name__)

# Context variables for tenant isolation and session
current_user_id: ContextVar[Optional[int]] = ContextVar('current_user_id', default=None)
current_organization_id: ContextVar[Optional[int]] = ContextVar('current_organization_id', default=None)
current_session_id: ContextVar[Optional[str]] = ContextVar('current_session_id', default=None)


def set_tenant_context(user_id: int, organization_id: int, session_id: Optional[str] = None) -> None:
    """Set the current tenant context for tool execution."""
    current_user_id.set(user_id)
    current_organization_id.set(organization_id)
    if session_id is not None:
        current_session_id.set(session_id)


def get_tenant_context() -> tuple:
    """Get the current tenant context (user_id, organization_id)."""
    return current_user_id.get(), current_organization_id.get()


class ASMToolsManager:
    """Manager for ASM platform tools accessible by the AI agent."""
    
    def __init__(self):
        self.tools = self._register_tools()
        self._mcp_server = None
    
    def _get_mcp_server(self):
        """Lazy load MCP server."""
        if self._mcp_server is None:
            from app.services.mcp.server import get_mcp_server
            self._mcp_server = get_mcp_server()
        return self._mcp_server
    
    def _register_tools(self) -> Dict[str, callable]:
        """Register all available tools."""
        tools = {
            # ASM Query Tools
            "query_assets": self.query_assets,
            "query_vulnerabilities": self.query_vulnerabilities,
            "query_ports": self.query_ports,
            "query_technologies": self.query_technologies,
            "query_graph": self.query_graph,
            "analyze_attack_surface": self.analyze_attack_surface,
            "get_asset_details": self.get_asset_details,
            "search_cve": self.search_cve,
            # Asset management
            "add_asset": self.add_asset,
            # Scan management
            "create_scan": self.create_scan,
            # Session notes and findings
            "save_note": self.save_note,
            "get_notes": self.get_notes,
            "create_finding": self.create_finding,
            # LLM Red Team Scanner
            "execute_llm_red_team": self.execute_llm_red_team,
            # MCP Security Tools (delegated)
            "execute_nuclei": self.execute_mcp_tool,
            "execute_naabu": self.execute_mcp_tool,
            "execute_httpx": self.execute_mcp_tool,
            "execute_subfinder": self.execute_mcp_tool,
            "execute_dnsx": self.execute_mcp_tool,
            "execute_katana": self.execute_mcp_tool,
            "execute_curl": self.execute_mcp_tool,
            "execute_tldfinder": self.execute_mcp_tool,
            "execute_waybackurls": self.execute_mcp_tool,
            "execute_nmap": self.execute_mcp_tool,
            "execute_masscan": self.execute_mcp_tool,
            "execute_ffuf": self.execute_mcp_tool,
            "execute_amass": self.execute_mcp_tool,
            "execute_whatweb": self.execute_mcp_tool,
            "execute_knockpy": self.execute_mcp_tool,
            "execute_gau": self.execute_mcp_tool,
            "execute_kiterunner": self.execute_mcp_tool,
            "execute_wappalyzer": self.execute_mcp_tool,
            "execute_crtsh": self.execute_mcp_tool,
            "execute_schemathesis": self.execute_mcp_tool,
            "execute_browser": self.execute_mcp_tool,
            "nuclei_help": self.execute_mcp_tool,
            "naabu_help": self.execute_mcp_tool,
            "httpx_help": self.execute_mcp_tool,
            "subfinder_help": self.execute_mcp_tool,
            "dnsx_help": self.execute_mcp_tool,
            "katana_help": self.execute_mcp_tool,
            "tldfinder_help": self.execute_mcp_tool,
            "waybackurls_help": self.execute_mcp_tool,
            "nmap_help": self.execute_mcp_tool,
            "masscan_help": self.execute_mcp_tool,
            "ffuf_help": self.execute_mcp_tool,
            "amass_help": self.execute_mcp_tool,
            "whatweb_help": self.execute_mcp_tool,
            "knockpy_help": self.execute_mcp_tool,
            "gau_help": self.execute_mcp_tool,
            "kiterunner_help": self.execute_mcp_tool,
            "schemathesis_help": self.execute_mcp_tool,
        }
        # Optional: web search (RedAmon-style) when Tavily API key is set
        if getattr(settings, "TAVILY_API_KEY", None):
            tools["web_search"] = self.web_search
        return tools

    def get_tool(self, name: str) -> Optional[callable]:
        """Get a tool by name."""
        return self.tools.get(name)
    
    def get_all_tools(self) -> Dict[str, callable]:
        """Get all registered tools."""
        return self.tools
    
    async def execute(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with the given arguments."""
        # Route MCP tools: execute_* and *_help (dynamic CLI + help)
        if tool_name.startswith("execute_") or tool_name.endswith("_help"):
            try:
                mcp = self._get_mcp_server()
                # Normalize: MCP execute_* tools expect {"args": "<cli string>"}.
                # LLMs often pass {"url": "...", "target": "..."} instead.
                if tool_name.startswith("execute_") and "args" not in tool_args and tool_args:
                    parts = []
                    for k, v in tool_args.items():
                        sv = str(v).strip()
                        if not sv:
                            continue
                        if k in ("url", "target", "host", "domain"):
                            if not sv.startswith("-"):
                                parts.insert(0, f"-u {sv}" if "http" in tool_name else sv)
                            else:
                                parts.insert(0, sv)
                        elif k in ("flags", "options", "arguments", "command"):
                            parts.append(sv)
                        else:
                            parts.append(sv)
                    tool_args = {"args": " ".join(parts)} if parts else {"args": ""}
                    logger.info(f"Normalized MCP args for {tool_name}: {tool_args}")
                result = await mcp.call_tool(tool_name, tool_args)
                
                max_chars = _tool_output_max_chars()
                if result.get("success"):
                    output = result.get("output", "")
                    if len(output) > max_chars:
                        output = output[:max_chars] + f"\n\n... (truncated, total {len(result.get('output', ''))} chars)"
                    return {
                        "success": True,
                        "output": output or "Command completed.",
                        "error": None
                    }
                else:
                    err = result.get("error", "Unknown error")
                    out = result.get("output", "")
                    err_max = min(8000, max_chars)
                    hint = (
                        f"\n\nHINT: {tool_name} expects a single 'args' parameter with CLI arguments as a string. "
                        f"Example: {tool_name}(args=\"-u https://target.com -json\")"
                    ) if "Missing required parameter" in err or "unexpected keyword" in err else ""
                    combined = f"Error: {err}{hint}"
                    if out and out.strip():
                        combined += f"\nStdout:\n{out[:err_max]}" + ("\n... (truncated)" if len(out) > err_max else "")
                    return {
                        "success": False,
                        "output": combined,
                        "error": err
                    }
            except Exception as e:
                logger.error(f"MCP tool execution failed: {tool_name} - {e}")
                return {
                    "success": False,
                    "output": f"Error: {e}\n\nHINT: All execute_* tools accept a single 'args' parameter with CLI arguments. "
                              f"Example: {tool_name}(args=\"-u https://target.com\")",
                    "error": str(e)
                }
        
        # Regular ASM tool
        tool = self.get_tool(tool_name)
        if not tool:
            return {
                "success": False,
                "output": None,
                "error": f"Tool '{tool_name}' not found"
            }
        
        try:
            result = await tool(**tool_args)
            return {
                "success": True,
                "output": result,
                "error": None
            }
        except TypeError as e:
            import inspect
            sig = inspect.signature(tool)
            params = [p for p in sig.parameters if p != "self"]
            hint = f"Tool '{tool_name}' accepts: {', '.join(params)}. You passed: {list(tool_args.keys())}."
            logger.error(f"Tool argument mismatch: {tool_name} - {e}. {hint}")
            return {
                "success": False,
                "output": hint,
                "error": f"{e}. {hint}"
            }
        except Exception as e:
            logger.error(f"Tool execution failed: {tool_name} - {e}")
            return {
                "success": False,
                "output": None,
                "error": str(e)
            }
    
    async def query_assets(
        self,
        asset_type: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Query assets from the ASM database.
        
        Args:
            asset_type: Filter by asset type (domain, subdomain, ip_address, url, etc.)
            search: Search term to filter asset values
            limit: Maximum number of results
        
        Returns:
            JSON string with asset information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply type filter
            if asset_type:
                try:
                    asset_type_enum = AssetType(asset_type.lower())
                    query = query.filter(Asset.asset_type == asset_type_enum)
                except ValueError:
                    pass
            
            # Apply search filter
            if search:
                query = query.filter(Asset.value.ilike(f"%{search}%"))
            
            # Limit results
            assets = query.limit(limit).all()
            
            result = []
            for asset in assets:
                result.append({
                    "id": asset.id,
                    "value": asset.value,
                    "type": asset.asset_type.value if asset.asset_type else None,
                    "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
                    "is_live": getattr(asset, 'is_live', None),
                    "risk_score": getattr(asset, 'ars_score', None),
                })
            
            return f"Found {len(result)} assets:\n" + "\n".join(
                f"- [{a['type']}] {a['value']} (ID: {a['id']}, Risk: {a.get('risk_score', 'N/A')})"
                for a in result
            )
        finally:
            db.close()
    
    async def query_vulnerabilities(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Query vulnerabilities from the ASM database.
        
        Args:
            severity: Filter by severity (critical, high, medium, low, info)
            status: Filter by status (open, in_progress, resolved, etc.)
            cve_id: Filter by CVE ID
            limit: Maximum number of results
        
        Returns:
            JSON string with vulnerability information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Vulnerability).join(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply severity filter (handles both string "critical" and list ["critical","high"])
            if severity:
                if isinstance(severity, list):
                    sev_enums = []
                    for s in severity:
                        try:
                            sev_enums.append(Severity(str(s).lower()))
                        except (ValueError, AttributeError):
                            pass
                    if sev_enums:
                        query = query.filter(Vulnerability.severity.in_(sev_enums))
                else:
                    try:
                        severity_enum = Severity(str(severity).lower())
                        query = query.filter(Vulnerability.severity == severity_enum)
                    except (ValueError, AttributeError):
                        pass
            
            # Apply CVE filter
            if cve_id:
                query = query.filter(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
            
            # Limit results
            vulns = query.limit(limit).all()
            
            result = []
            for vuln in vulns:
                result.append({
                    "id": vuln.id,
                    "title": vuln.title,
                    "severity": vuln.severity.value if vuln.severity else None,
                    "cvss_score": vuln.cvss_score,
                    "cve_id": vuln.cve_id,
                    "cwe_id": vuln.cwe_id,
                    "status": vuln.status.value if vuln.status else None,
                    "asset": vuln.asset.value if vuln.asset else None,
                })
            
            return f"Found {len(result)} vulnerabilities:\n" + "\n".join(
                f"- [{v['severity'].upper()}] {v['title']} ({v['cve_id'] or 'No CVE'}) on {v['asset']}"
                for v in result
            )
        finally:
            db.close()
    
    async def query_ports(
        self,
        port: Optional[int] = None,
        service: Optional[str] = None,
        is_risky: Optional[bool] = None,
        limit: int = 50
    ) -> str:
        """
        Query open ports and services from the ASM database.
        
        Args:
            port: Filter by port number
            service: Filter by service name
            is_risky: Filter by risky port flag
            limit: Maximum number of results
        
        Returns:
            String with port/service information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(PortService).join(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply port filter
            if port:
                query = query.filter(PortService.port == port)
            
            # Apply service filter
            if service:
                query = query.filter(PortService.service.ilike(f"%{service}%"))
            
            # Apply risky filter
            if is_risky is not None:
                query = query.filter(PortService.is_risky == is_risky)
            
            # Limit results
            ports = query.limit(limit).all()
            
            result = []
            for p in ports:
                result.append({
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "is_risky": p.is_risky,
                    "asset": p.asset.value if p.asset else None,
                })
            
            # Group by port for summary
            port_summary = {}
            for p in result:
                port_key = f"{p['port']}/{p['protocol']}"
                if port_key not in port_summary:
                    port_summary[port_key] = {"count": 0, "service": p["service"], "risky": p["is_risky"]}
                port_summary[port_key]["count"] += 1
            
            return f"Found {len(result)} open ports:\n" + "\n".join(
                f"- {pk}: {pv['service'] or 'unknown'} ({pv['count']} hosts){' [RISKY]' if pv['risky'] else ''}"
                for pk, pv in sorted(port_summary.items())
            )
        finally:
            db.close()
    
    async def query_technologies(
        self,
        category: Optional[str] = None,
        name: Optional[str] = None,
        limit: int = 50
    ) -> str:
        """
        Query detected technologies from the ASM database.
        
        Args:
            category: Filter by technology category
            name: Filter by technology name
            limit: Maximum number of results
        
        Returns:
            String with technology information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Technology).join(Asset)
            
            # Apply organization filter
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            # Apply category filter
            if category:
                query = query.filter(Technology.category.ilike(f"%{category}%"))
            
            # Apply name filter
            if name:
                query = query.filter(Technology.name.ilike(f"%{name}%"))
            
            # Limit results
            techs = query.limit(limit).all()
            
            # Group by technology
            tech_summary = {}
            for t in techs:
                key = f"{t.name} ({t.category})" if t.category else t.name
                if key not in tech_summary:
                    tech_summary[key] = {"count": 0, "versions": set()}
                tech_summary[key]["count"] += 1
                if t.version:
                    tech_summary[key]["versions"].add(t.version)
            
            return f"Found {len(tech_summary)} unique technologies:\n" + "\n".join(
                f"- {tk}: {tv['count']} instances" + (f" (versions: {', '.join(tv['versions'])})" if tv['versions'] else "")
                for tk, tv in sorted(tech_summary.items(), key=lambda x: -x[1]["count"])
            )
        finally:
            db.close()
    
    async def query_graph(
        self,
        cypher: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
        limit: int = 50,
        # Accept common LLM argument name variations
        cypher_query: Optional[str] = None,
        query: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """
        Run a Cypher query against the Neo4j attack surface graph.
        
        Use this to understand relationships: Domain → Subdomain → IP → Port → Service
        → Technology → Vulnerability → CVE. Always include a filter on organization_id
        for tenant safety (use $org_id in your WHERE clause).
        
        Args:
            cypher: Cypher query string. Must filter by organization_id, e.g.
                    WHERE a.organization_id = $org_id
            params: Optional query parameters (org_id is added automatically from context)
            limit: Max rows to return (default 50)
        
        Returns:
            JSON string of query results
        """
        cypher = cypher or cypher_query or query or kwargs.get("cypher_string", "")
        if not cypher:
            return json.dumps({"error": "No Cypher query provided. Pass the query as the 'cypher' argument."})
        user_id, org_id = get_tenant_context()
        if not org_id:
            return json.dumps({"error": "No organization context. Set organization for this session."})
        
        try:
            from app.services.graph_service import get_graph_service
            graph = get_graph_service()
            if not graph.connect():
                return json.dumps({"error": "Neo4j graph not available."})
            
            merged = dict(params or {})
            merged["org_id"] = org_id
            if "LIMIT" not in cypher.upper():
                cypher = cypher.rstrip() + f" LIMIT {limit}"
            results = graph.query(cypher, merged)
            return json.dumps(results[:limit], default=str)
        except Exception as e:
            logger.exception("query_graph failed")
            return json.dumps({"error": str(e)})
    
    async def analyze_attack_surface(self) -> str:
        """
        Get a comprehensive attack surface summary.
        
        Returns:
            String with attack surface analysis
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            # Count assets by type
            asset_counts = {}
            for asset_type in AssetType:
                query = db.query(Asset).filter(Asset.asset_type == asset_type)
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                asset_counts[asset_type.value] = query.count()
            
            # Count vulnerabilities by severity
            vuln_counts = {}
            for severity in Severity:
                query = db.query(Vulnerability).join(Asset).filter(Vulnerability.severity == severity)
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                vuln_counts[severity.value] = query.count()
            
            # Count risky ports
            query = db.query(PortService).join(Asset).filter(PortService.is_risky == True)
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            risky_ports = query.count()
            
            # Total ports
            query = db.query(PortService).join(Asset)
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            total_ports = query.count()
            
            report = "# Attack Surface Summary\n\n"
            
            report += "## Assets\n"
            for at, count in asset_counts.items():
                if count > 0:
                    report += f"- {at}: {count}\n"
            
            report += "\n## Vulnerabilities\n"
            total_vulns = sum(vuln_counts.values())
            report += f"- Total: {total_vulns}\n"
            for sev, count in vuln_counts.items():
                if count > 0:
                    report += f"  - {sev.upper()}: {count}\n"
            
            report += f"\n## Exposed Services\n"
            report += f"- Total open ports: {total_ports}\n"
            report += f"- Risky ports: {risky_ports}\n"
            
            return report
        finally:
            db.close()
    
    async def get_asset_details(
        self,
        asset_id: Optional[int] = None,
        # Accept common LLM argument name variations
        asset_identifier: Optional[Any] = None,
        hostname: Optional[str] = None,
        asset: Optional[Any] = None,
        id: Optional[int] = None,
        **kwargs: Any,
    ) -> str:
        """
        Get detailed information about a specific asset.
        
        Args:
            asset_id: ID (integer) of the asset to retrieve. Use query_assets first to find asset IDs.
        
        Returns:
            String with detailed asset information
        """
        resolved_id = asset_id or id or asset_identifier or asset or kwargs.get("asset_value")
        lookup_by_name = hostname or (resolved_id if isinstance(resolved_id, str) and not str(resolved_id).isdigit() else None)

        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            if lookup_by_name:
                query = db.query(Asset).filter(Asset.value.ilike(f"%{lookup_by_name}%"))
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                asset_obj = query.first()
            else:
                try:
                    resolved_id = int(resolved_id)
                except (TypeError, ValueError):
                    return f"Invalid asset_id: {resolved_id}. Use query_assets to find integer asset IDs."
                query = db.query(Asset).filter(Asset.id == resolved_id)
                if org_id:
                    query = query.filter(Asset.organization_id == org_id)
                asset_obj = query.first()
            
            if not asset_obj:
                return f"Asset '{resolved_id or lookup_by_name}' not found. Use query_assets to list available assets."
            
            asset = asset_obj
            
            details = f"# Asset Details: {asset.value}\n\n"
            details += f"- **Type**: {asset.asset_type.value if asset.asset_type else 'Unknown'}\n"
            details += f"- **First Seen**: {asset.first_seen.isoformat() if asset.first_seen else 'Unknown'}\n"
            details += f"- **Live**: {'Yes' if getattr(asset, 'is_live', False) else 'No'}\n"
            
            if hasattr(asset, 'ars_score') and asset.ars_score:
                details += f"- **Risk Score (ARS)**: {asset.ars_score}/100\n"
            
            if hasattr(asset, 'acs_score') and asset.acs_score:
                details += f"- **Criticality Score (ACS)**: {asset.acs_score}/10\n"
            
            # Get vulnerabilities
            if asset.vulnerabilities:
                details += f"\n## Vulnerabilities ({len(asset.vulnerabilities)})\n"
                for vuln in asset.vulnerabilities[:10]:
                    details += f"- [{vuln.severity.value.upper()}] {vuln.title}\n"
                if len(asset.vulnerabilities) > 10:
                    details += f"... and {len(asset.vulnerabilities) - 10} more\n"
            
            # Get ports
            if hasattr(asset, 'ports') and asset.ports:
                details += f"\n## Open Ports ({len(asset.ports)})\n"
                for port in asset.ports[:10]:
                    risky = " [RISKY]" if port.is_risky else ""
                    details += f"- {port.port}/{port.protocol}: {port.service or 'unknown'}{risky}\n"
            
            # Get technologies
            if hasattr(asset, 'technologies') and asset.technologies:
                details += f"\n## Technologies ({len(asset.technologies)})\n"
                for tech in asset.technologies[:10]:
                    version = f" v{tech.version}" if tech.version else ""
                    details += f"- {tech.name}{version} ({tech.category or 'unknown'})\n"
            
            return details
        finally:
            db.close()
    
    async def search_cve(self, cve_id: str) -> str:
        """
        Search for CVE information in the database.
        
        Args:
            cve_id: CVE ID to search for (e.g., CVE-2021-44228)
        
        Returns:
            String with CVE information and affected assets
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Vulnerability).join(Asset).filter(
                Vulnerability.cve_id.ilike(f"%{cve_id}%")
            )
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            vulns = query.all()
            
            if not vulns:
                return f"No findings for {cve_id} in your attack surface."
            
            result = f"# CVE Search: {cve_id}\n\n"
            result += f"Found {len(vulns)} affected assets:\n\n"
            
            for vuln in vulns[:20]:
                result += f"## {vuln.asset.value if vuln.asset else 'Unknown Asset'}\n"
                result += f"- **Severity**: {vuln.severity.value.upper()}\n"
                result += f"- **CVSS**: {vuln.cvss_score or 'N/A'}\n"
                result += f"- **Status**: {vuln.status.value if vuln.status else 'Unknown'}\n"
                if vuln.description:
                    result += f"- **Description**: {vuln.description[:200]}...\n"
                result += "\n"
            
            if len(vulns) > 20:
                result += f"... and {len(vulns) - 20} more affected assets.\n"
            
            return result
        finally:
            db.close()

    async def web_search(self, query: str, max_results: int = 5) -> str:
        """
        Search the web for CVE details, exploit info, or general security research (RedAmon-style).
        Uses Tavily API when TAVILY_API_KEY is set.
        
        Args:
            query: Search query (e.g. "CVE-2021-44228 exploit", "Log4j remediation")
            max_results: Max results to return (1-10, default 5)
        
        Returns:
            Summarized search results or an error message.
        """
        api_key = getattr(settings, "TAVILY_API_KEY", None)
        if not api_key:
            return "Web search is not configured. Set TAVILY_API_KEY in .env to enable (get a key at tavily.com)."
        max_results = max(1, min(10, max_results))
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                r = await client.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": api_key,
                        "query": query,
                        "search_depth": "basic",
                        "max_results": max_results,
                    },
                )
                r.raise_for_status()
                data = r.json()
        except httpx.HTTPStatusError as e:
            logger.warning(f"Tavily API error: {e.response.status_code} - {e.response.text[:200]}")
            return f"Web search failed: HTTP {e.response.status_code}. Check TAVILY_API_KEY and quota."
        except Exception as e:
            logger.exception("Tavily web_search failed")
            return f"Web search failed: {e!s}"
        results = data.get("results") or []
        if not results:
            return f"No results for: {query}"
        out = [f"# Web search: {query}\n"]
        for i, hit in enumerate(results, 1):
            title = hit.get("title", "")
            url = hit.get("url", "")
            content = (hit.get("content") or "")[:_tool_output_max_chars() // max_results]
            out.append(f"## {i}. {title}\nURL: {url}\n{content}\n")
        return "\n".join(out)

    def _resolve_asset_type(self, value: str) -> AssetType:
        """Infer AssetType from a raw value string."""
        import re
        v = value.strip().lower()
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", v):
            return AssetType.IP_ADDRESS
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$", v):
            return AssetType.IP_RANGE
        if v.startswith(("http://", "https://")):
            return AssetType.URL
        if "." in v and v.count(".") >= 2:
            return AssetType.SUBDOMAIN
        if "." in v:
            return AssetType.DOMAIN
        return AssetType.OTHER

    def _extract_hostname(self, value: str) -> str:
        """Extract clean hostname/domain from a URL or value."""
        v = value.strip()
        if v.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse
                p = urlparse(v)
                return (p.netloc or p.path.split("/")[0] or v).split(":")[0]
            except Exception:
                pass
        return v.rstrip("/").split("/")[0].split(":")[0]

    def _get_or_create_asset(self, db, org_id: int, target: str) -> "Asset":
        """Find existing asset or create a new one for the given target.

        Tries exact match, then case-insensitive, then creates a new asset.
        Returns the Asset ORM object (already flushed so it has an id).
        """
        target_clean = self._extract_hostname(target)
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == org_id, Asset.value == target_clean)
            .first()
        )
        if asset:
            return asset
        asset = (
            db.query(Asset)
            .filter(Asset.organization_id == org_id, Asset.value.ilike(target_clean))
            .first()
        )
        if asset:
            return asset

        asset_type = self._resolve_asset_type(target)
        root = target_clean
        parts = target_clean.split(".")
        if len(parts) > 2:
            root = ".".join(parts[-2:])

        new_asset = Asset(
            organization_id=org_id,
            name=target_clean,
            value=target_clean,
            asset_type=asset_type,
            root_domain=root,
            discovery_source="agent",
            status=AssetStatus.DISCOVERED,
            is_monitored=True,
        )
        db.add(new_asset)
        db.flush()
        return new_asset

    async def add_asset(
        self,
        value: str,
        asset_type: Optional[str] = None,
        description: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Add a target to the asset inventory so it can be scanned and receive findings.

        Use this when a target URL/domain/IP is not yet in the database. The asset
        will be created with status=discovered and can then be used with create_finding,
        query_assets, and scan tools.

        Args:
            value: The hostname, domain, IP, or URL to add (e.g. "test-git.glensserver.com")
            asset_type: Optional override — DOMAIN, SUBDOMAIN, IP_ADDRESS, URL, etc. Auto-detected if omitted.
            description: Optional description of the asset.
        """
        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: No organization context."
        if not value or not value.strip():
            return "Error: 'value' is required (hostname, domain, IP, or URL)."

        target_clean = self._extract_hostname(value.strip())

        db = SessionLocal()
        try:
            existing = (
                db.query(Asset)
                .filter(Asset.organization_id == org_id, Asset.value.ilike(target_clean))
                .first()
            )
            if existing:
                return (
                    f"Asset already exists: id={existing.id}, value={existing.value}, "
                    f"type={existing.asset_type.value if existing.asset_type else 'N/A'}. "
                    f"No action needed — you can now use create_finding with target='{existing.value}'."
                )

            resolved_type = self._resolve_asset_type(value.strip())
            if asset_type:
                try:
                    resolved_type = AssetType(asset_type.upper())
                except (ValueError, KeyError):
                    pass

            root = target_clean
            parts = target_clean.split(".")
            if len(parts) > 2:
                root = ".".join(parts[-2:])

            new_asset = Asset(
                organization_id=org_id,
                name=target_clean,
                value=target_clean,
                asset_type=resolved_type,
                root_domain=root,
                discovery_source="agent",
                status=AssetStatus.DISCOVERED,
                is_monitored=True,
                description=(description or "")[:2000] if description else None,
            )
            db.add(new_asset)
            db.commit()
            db.refresh(new_asset)
            return (
                f"Asset added: id={new_asset.id}, value={new_asset.value}, "
                f"type={new_asset.asset_type.value}. "
                f"You can now scan it and use create_finding with target='{new_asset.value}'."
            )
        except Exception as e:
            db.rollback()
            logger.exception("add_asset failed")
            return f"Error adding asset: {e}"
        finally:
            db.close()

    async def create_scan(
        self,
        scan_type: str,
        targets: Optional[List[str]] = None,
        name: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> str:
        """Create an async scan job processed by the scanner worker. Use this for
        bulk operations (scanning many IPs/domains) instead of execute_* tools.

        The scan runs in the background — results appear in the Scans page and
        update asset records automatically.

        Args:
            scan_type: One of: port_scan, vulnerability, waybackurls, katana,
                       paramspider, http_probe, technology, screenshot,
                       login_portal, subdomain_enum, dns_resolution, discovery,
                       full, geo_enrich, tldfinder, whatweb
            targets: List of hostnames, domains, or IPs to scan. If omitted,
                     scans all org domains/assets automatically.
            name: Optional scan name (auto-generated if omitted).
            config: Optional dict with scan-specific settings, e.g.
                    {"severity": ["critical","high"]} for vulnerability scans,
                    {"ports": "80,443,8080"} for port_scan.
        """
        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: No organization context."
        if not scan_type:
            return "Error: scan_type is required."

        from app.models.scan import Scan, ScanType as ST, ScanStatus

        type_map = {
            "port_scan": ST.PORT_SCAN,
            "vulnerability": ST.VULNERABILITY,
            "waybackurls": ST.WAYBACKURLS,
            "katana": ST.KATANA,
            "paramspider": ST.PARAMSPIDER,
            "http_probe": ST.HTTP_PROBE,
            "technology": ST.TECHNOLOGY,
            "whatweb": ST.WHATWEB,
            "screenshot": ST.SCREENSHOT,
            "login_portal": ST.LOGIN_PORTAL,
            "subdomain_enum": ST.SUBDOMAIN_ENUM,
            "dns_resolution": ST.DNS_RESOLUTION,
            "discovery": ST.DISCOVERY,
            "full": ST.FULL,
            "geo_enrich": ST.GEO_ENRICH,
            "tldfinder": ST.TLDFINDER,
        }
        st = type_map.get(scan_type.lower().strip())
        if not st:
            return (
                f"Unknown scan_type '{scan_type}'. Valid types: {', '.join(sorted(type_map.keys()))}"
            )

        auto_name = name or f"Agent {scan_type} scan"
        scan_config = dict(config or {})
        scan_config["created_by"] = "agent"

        db = SessionLocal()
        try:
            new_scan = Scan(
                name=auto_name[:255],
                scan_type=st,
                organization_id=org_id,
                targets=targets or [],
                config=scan_config,
                status=ScanStatus.PENDING,
                started_by="agent",
            )
            db.add(new_scan)
            db.commit()
            db.refresh(new_scan)

            try:
                from app.api.routes.scans import send_scan_to_sqs
                send_scan_to_sqs(new_scan)
            except Exception:
                pass

            target_desc = f"{len(targets)} targets" if targets else "all org assets"
            return (
                f"Scan created: id={new_scan.id}, type={scan_type}, status=pending, "
                f"targets={target_desc}. The scanner worker will pick it up automatically. "
                f"Results will appear on the Scans page and update asset records."
            )
        except Exception as e:
            db.rollback()
            logger.exception("create_scan failed")
            return f"Error creating scan: {e}"
        finally:
            db.close()

    async def create_finding(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        evidence: Optional[str] = None,
        cve_id: Optional[str] = None,
        remediation: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Create a vulnerability/finding in the findings table for the current organization. Use this so discoveries appear in the UI findings list. target = hostname, domain, or URL that must match an existing asset's value (use query_assets to find). severity = critical|high|medium|low|info."""
        _, org_id = get_tenant_context()
        if not org_id:
            return "Error: No organization context. create_finding requires an active session."
        # Normalize target for asset lookup: strip scheme and path
        target_clean = (target or "").strip()
        if target_clean.startswith(("http://", "https://")):
            try:
                from urllib.parse import urlparse
                p = urlparse(target_clean)
                target_clean = p.netloc or p.path.split("/")[0] or target_clean
            except Exception:
                pass
        target_clean = target_clean.rstrip("/").split("/")[0].split(":")[0] or target
        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
        severity_enum = sev_map.get((severity or "info").strip().lower(), Severity.INFO)
        db = SessionLocal()
        try:
            asset = self._get_or_create_asset(db, org_id, target_clean)
            auto_added = not asset.id or db.is_modified(asset)
            if auto_added:
                db.flush()
                logger.info(f"create_finding auto-added asset: {asset.value} (id={asset.id})")
            vuln = Vulnerability(
                title=(title or "Agent finding")[:500],
                description=(description or "")[:10000] if description else None,
                severity=severity_enum,
                asset_id=asset.id,
                detected_by="agent",
                evidence=(evidence or "")[:5000] if evidence else None,
                cve_id=(cve_id or "").strip() or None,
                remediation=(remediation or "")[:5000] if remediation else None,
            )
            db.add(vuln)
            db.commit()
            db.refresh(vuln)
            return f"Finding created: id={vuln.id}, title={vuln.title[:60]}..., severity={vuln.severity.value}, asset={asset.value}"
        except Exception as e:
            db.rollback()
            logger.exception("create_finding failed")
            return f"Error creating finding: {e}"
        finally:
            db.close()

    async def execute_llm_red_team(
        self,
        target_url: str,
        categories: Optional[List[str]] = None,
        endpoint_url: Optional[str] = None,
        message_field: Optional[str] = None,
        auto_discover: bool = True,
        max_payloads: Optional[int] = None,
        create_findings: bool = True,
        **kwargs: Any,
    ) -> str:
        """Run LLM red team scan against chatbot/AI endpoints on a target URL. Tests for prompt injection, jailbreak, data exfiltration, SSRF, excessive agency, and more. Optionally auto-discovers chat endpoints. If endpoint_url is provided, it will be tested directly. categories = prompt_injection|system_prompt_leakage|data_exfiltration|jailbreak|ssrf_tool_abuse|excessive_agency|hallucination|harmful_content (comma-separated or list; omit for all). Returns a formatted report of findings."""
        from app.services.llm_red_team.scanner import (
            run_scan, ScanConfig, ChatEndpoint, format_scan_report, build_finding_data,
        )
        _, org_id = get_tenant_context()

        cat_list = None
        if categories:
            if isinstance(categories, str):
                cat_list = [c.strip() for c in categories.split(",")]
            else:
                cat_list = list(categories)

        endpoints = []
        if endpoint_url:
            endpoints.append(ChatEndpoint(
                url=endpoint_url.strip(),
                message_field=message_field or "message",
                detected_by="agent",
            ))

        config = ScanConfig(
            target_url=target_url.strip(),
            endpoints=endpoints,
            categories=cat_list,
            auto_discover=auto_discover,
            use_llm_grading=True,
            max_payloads=int(max_payloads) if max_payloads else None,
        )

        try:
            scan_result = await run_scan(config)
        except Exception as e:
            logger.exception("LLM red team scan failed")
            return f"Error running LLM red team scan: {e}"

        if create_findings and org_id and scan_result.vulnerabilities_found > 0:
            db = SessionLocal()
            try:
                created_count = 0
                for test_result in scan_result.results:
                    if test_result.get("verdict") != "fail":
                        continue
                    finding_data = build_finding_data(test_result, target_url)
                    asset = self._get_or_create_asset(db, org_id, target_url.strip())
                    if not asset.id or db.is_modified(asset):
                        db.flush()
                    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                    vuln = Vulnerability(
                        title=finding_data["title"][:500],
                        description=finding_data.get("description", "")[:10000],
                        severity=sev_map.get(finding_data.get("severity", "medium"), Severity.MEDIUM),
                        asset_id=asset.id,
                        detected_by="llm_red_team",
                        template_id=finding_data.get("template_id"),
                        evidence=finding_data.get("evidence", "")[:5000],
                        cwe_id=finding_data.get("cwe_id"),
                        remediation=finding_data.get("remediation", "")[:5000],
                        tags=finding_data.get("tags", []),
                        metadata_=finding_data.get("metadata", {}),
                    )
                    db.add(vuln)
                    created_count += 1
                db.commit()
                logger.info(f"LLM red team: created {created_count} findings for {target_url}")
            except Exception as e:
                db.rollback()
                logger.exception("Failed to create LLM red team findings")
                scan_result.errors.append(f"Finding creation error: {e}")
            finally:
                db.close()

        report = format_scan_report(scan_result)
        max_chars = _tool_output_max_chars()
        if len(report) > max_chars:
            report = report[:max_chars] + "\n\n... (truncated)"
        return report

    async def save_note(
        self,
        category: str,
        content: str,
        target: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Save a session note (credential, vulnerability, finding, artifact). Uses current org/session from context."""
        user_id, org_id = get_tenant_context()
        session_id = current_session_id.get()
        if not org_id:
            return "Error: No organization context. save_note requires an active session."
        db = SessionLocal()
        try:
            note = AgentNote(
                organization_id=org_id,
                user_id=user_id,
                session_id=session_id,
                category=category.strip().lower() if category else "finding",
                content=content[:10000] if content else "",
                target=target[:512] if target else None,
            )
            db.add(note)
            db.commit()
            return f"Saved note: category={note.category}, target={note.target or 'N/A'}"
        except Exception as e:
            db.rollback()
            logger.exception("save_note failed")
            return f"Error saving note: {e}"
        finally:
            db.close()

    def get_session_notes(
        self,
        session_id: Optional[str] = None,
        category: Optional[str] = None,
    ) -> str:
        """Return formatted session notes for prompt injection. Used by orchestrator or get_notes tool."""
        _, org_id = get_tenant_context()
        if not org_id:
            return "No session notes (no organization context)."
        db = SessionLocal()
        try:
            q = db.query(AgentNote).filter(AgentNote.organization_id == org_id)
            if session_id:
                q = q.filter(AgentNote.session_id == session_id)
            if category:
                q = q.filter(AgentNote.category == category.strip().lower())
            notes = q.order_by(AgentNote.created_at.desc()).limit(50).all()
            if not notes:
                return "No session notes yet."
            lines = []
            for n in notes:
                target_str = f" target={n.target}" if n.target else ""
                lines.append(f"- [{n.category}]{target_str}: {n.content[:500]}{'...' if len(n.content) > 500 else ''}")
            return "\n".join(lines)
        finally:
            db.close()

    async def get_notes(
        self,
        session_id: Optional[str] = None,
        category: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Get session notes (optionally filtered by category). Uses current session from context if session_id not provided."""
        sid = session_id or current_session_id.get()
        return self.get_session_notes(session_id=sid, category=category)
    
    async def execute_mcp_tool(self, tool_name: str = None, args: str = "", **kwargs) -> str:
        """
        Execute an MCP security tool.
        
        This method delegates to the MCP server for tool execution.
        
        Args:
            tool_name: Name of the MCP tool to execute
            args: CLI arguments for the tool
        
        Returns:
            Tool output as string
        """
        mcp = self._get_mcp_server()
        
        # Get the actual tool name from kwargs if provided
        actual_tool = tool_name or kwargs.get("_tool_name", "")
        
        if not actual_tool:
            return "Error: No tool name specified"
        
        # Build arguments
        arguments = {"args": args} if args else kwargs
        
        # Call MCP tool
        result = await mcp.call_tool(actual_tool, arguments)
        
        max_chars = _tool_output_max_chars()
        if result.get("success"):
            output = result.get("output", "")
            if len(output) > max_chars:
                output = output[:max_chars] + f"\n\n... (truncated, {len(result['output'])} total chars)"
            return output or "Command completed with no output."
        else:
            err = result.get("error", "Unknown error")
            out = result.get("output", "")
            err_max = min(8000, max_chars)
            if out and out.strip():
                return f"Error: {err}\nStdout:\n{out[:err_max]}" + ("\n... (truncated)" if len(out) > err_max else "")
            return f"Error: {err}"
