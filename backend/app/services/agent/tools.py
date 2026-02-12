"""
Agent Tools

Tools for the AI agent to interact with the ASM platform.
"""

import json
import logging
from typing import List, Optional, Dict, Any
from contextvars import ContextVar
from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType
from app.models.vulnerability import Vulnerability, Severity
from app.models.port_service import PortService
from app.models.technology import Technology
from app.models.agent_note import AgentNote
from app.core.config import settings

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
        return {
            # ASM Query Tools
            "query_assets": self.query_assets,
            "query_vulnerabilities": self.query_vulnerabilities,
            "query_ports": self.query_ports,
            "query_technologies": self.query_technologies,
            "query_graph": self.query_graph,
            "analyze_attack_surface": self.analyze_attack_surface,
            "get_asset_details": self.get_asset_details,
            "search_cve": self.search_cve,
            # Session notes
            "save_note": self.save_note,
            "get_notes": self.get_notes,
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
            "nuclei_help": self.execute_mcp_tool,
            "naabu_help": self.execute_mcp_tool,
            "httpx_help": self.execute_mcp_tool,
            "subfinder_help": self.execute_mcp_tool,
            "dnsx_help": self.execute_mcp_tool,
            "katana_help": self.execute_mcp_tool,
            "tldfinder_help": self.execute_mcp_tool,
            "waybackurls_help": self.execute_mcp_tool,
        }
    
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
                # MCP expects args for execute_* tools; help tools use {}
                result = await mcp.call_tool(tool_name, tool_args)
                
                if result.get("success"):
                    output = result.get("output", "")
                    if len(output) > 10000:
                        output = output[:10000] + f"\n\n... (truncated)"
                    return {
                        "success": True,
                        "output": output or "Command completed.",
                        "error": None
                    }
                else:
                    return {
                        "success": False,
                        "output": result.get("output", ""),
                        "error": result.get("error", "Unknown error")
                    }
            except Exception as e:
                logger.error(f"MCP tool execution failed: {tool_name} - {e}")
                return {
                    "success": False,
                    "output": None,
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
                    "is_active": asset.is_active,
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
            
            # Apply severity filter
            if severity:
                try:
                    severity_enum = Severity(severity.lower())
                    query = query.filter(Vulnerability.severity == severity_enum)
                except ValueError:
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
        cypher: str,
        params: Optional[Dict[str, Any]] = None,
        limit: int = 50,
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
    
    async def get_asset_details(self, asset_id: int) -> str:
        """
        Get detailed information about a specific asset.
        
        Args:
            asset_id: ID of the asset to retrieve
        
        Returns:
            String with detailed asset information
        """
        user_id, org_id = get_tenant_context()
        
        db = SessionLocal()
        try:
            query = db.query(Asset).filter(Asset.id == asset_id)
            if org_id:
                query = query.filter(Asset.organization_id == org_id)
            
            asset = query.first()
            if not asset:
                return f"Asset with ID {asset_id} not found or not accessible."
            
            details = f"# Asset Details: {asset.value}\n\n"
            details += f"- **Type**: {asset.asset_type.value if asset.asset_type else 'Unknown'}\n"
            details += f"- **First Seen**: {asset.first_seen.isoformat() if asset.first_seen else 'Unknown'}\n"
            details += f"- **Active**: {'Yes' if asset.is_active else 'No'}\n"
            
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
        
        if result.get("success"):
            output = result.get("output", "")
            if len(output) > 10000:
                output = output[:10000] + f"\n\n... (truncated, {len(result['output'])} total chars)"
            return output or "Command completed with no output."
        else:
            return f"Error: {result.get('error', 'Unknown error')}"
