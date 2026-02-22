"""
Neo4j Graph Database Service

Stores the canonical chain:
  Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE
                                                              Vulnerability → MITRE (CWE)

Also keeps Asset nodes for API compatibility (get_asset_relationships, get_attack_paths).
"""

import hashlib
import logging
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from urllib.parse import urlparse

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable

from app.core.config import settings
from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType
from app.models.vulnerability import Vulnerability
from app.models.port_service import PortService
from app.models.technology import Technology

logger = logging.getLogger(__name__)


class GraphService:
    """
    Service for managing the Neo4j graph database.

    Canonical chain (see docs/GRAPH_SCHEMA.md):
    - Domain -[:HAS_SUBDOMAIN]-> Subdomain -[:RESOLVES_TO]-> IP -[:HAS_PORT]-> Port
      -[:RUNS_SERVICE]-> Service -[:USES_TECHNOLOGY]-> Technology -[:HAS_VULNERABILITY]-> Vulnerability
      -[:REFERENCES]-> CVE, Vulnerability -[:MAPS_TO]-> MITRE (CWE)

    Asset nodes and Asset-based edges are kept for API compatibility.
    """
    
    def __init__(self):
        self.driver = None
        self._connected = False
    
    def connect(self) -> bool:
        """Connect to Neo4j database."""
        try:
            self.driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
            )
            # Verify connection
            self.driver.verify_connectivity()
            self._connected = True
            logger.info(f"Connected to Neo4j at {settings.NEO4J_URI}")
            return True
        except ServiceUnavailable as e:
            logger.warning(f"Neo4j not available: {e}")
            self._connected = False
            return False
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            self._connected = False
            return False
    
    def close(self):
        """Close the Neo4j connection."""
        if self.driver:
            self.driver.close()
            self._connected = False
    
    @contextmanager
    def session(self):
        """Get a Neo4j session context manager."""
        if not self._connected:
            self.connect()
        
        if not self._connected or not self.driver:
            raise RuntimeError("Neo4j not connected")
        
        session = self.driver.session()
        try:
            yield session
        finally:
            session.close()
    
    def initialize_schema(self):
        """Create indexes and constraints for the graph."""
        if not self._connected:
            self.connect()
        
        if not self._connected:
            logger.warning("Cannot initialize schema - Neo4j not connected")
            return
        
        with self.session() as session:
            # Create uniqueness constraints for all node types
            constraints = [
                # Canonical chain: Domain, Subdomain (composite for multi-tenant)
                "CREATE CONSTRAINT domain_org_name IF NOT EXISTS FOR (d:Domain) REQUIRE (d.organization_id, d.name) IS UNIQUE",
                "CREATE CONSTRAINT subdomain_org_name IF NOT EXISTS FOR (s:Subdomain) REQUIRE (s.organization_id, s.name) IS UNIQUE",
                # Core asset nodes
                "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:Asset) REQUIRE a.asset_id IS UNIQUE",
                "CREATE CONSTRAINT ip_address IF NOT EXISTS FOR (i:IP) REQUIRE i.address IS UNIQUE",
                "CREATE CONSTRAINT port_id IF NOT EXISTS FOR (p:Port) REQUIRE p.port_id IS UNIQUE",
                "CREATE CONSTRAINT service_name IF NOT EXISTS FOR (s:Service) REQUIRE s.name IS UNIQUE",
                "CREATE CONSTRAINT tech_name IF NOT EXISTS FOR (t:Technology) REQUIRE t.name IS UNIQUE",
                # Vulnerability nodes
                "CREATE CONSTRAINT vulnerability_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.vuln_id IS UNIQUE",
                "CREATE CONSTRAINT cve_id IF NOT EXISTS FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
                "CREATE CONSTRAINT cwe_id IF NOT EXISTS FOR (w:CWE) REQUIRE w.cwe_id IS UNIQUE",
                # Web application layer
                "CREATE CONSTRAINT baseurl_id IF NOT EXISTS FOR (b:BaseURL) REQUIRE b.baseurl_id IS UNIQUE",
                "CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.endpoint_id IS UNIQUE",
                "CREATE CONSTRAINT parameter_id IF NOT EXISTS FOR (p:Parameter) REQUIRE p.parameter_id IS UNIQUE",
            ]
            
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    logger.debug(f"Constraint may already exist: {e}")
            
            # Create indexes for common queries
            indexes = [
                # Domain / Subdomain (canonical chain)
                "CREATE INDEX domain_org IF NOT EXISTS FOR (d:Domain) ON (d.organization_id)",
                "CREATE INDEX domain_name IF NOT EXISTS FOR (d:Domain) ON (d.name)",
                "CREATE INDEX subdomain_org IF NOT EXISTS FOR (s:Subdomain) ON (s.organization_id)",
                "CREATE INDEX subdomain_name IF NOT EXISTS FOR (s:Subdomain) ON (s.name)",
                # Asset indexes
                "CREATE INDEX asset_org IF NOT EXISTS FOR (a:Asset) ON (a.organization_id)",
                "CREATE INDEX asset_type IF NOT EXISTS FOR (a:Asset) ON (a.asset_type)",
                "CREATE INDEX asset_value IF NOT EXISTS FOR (a:Asset) ON (a.value)",
                "CREATE INDEX asset_root_domain IF NOT EXISTS FOR (a:Asset) ON (a.root_domain)",
                "CREATE INDEX asset_risk IF NOT EXISTS FOR (a:Asset) ON (a.ars_score)",
                "CREATE INDEX asset_live IF NOT EXISTS FOR (a:Asset) ON (a.is_live)",
                # IP indexes
                "CREATE INDEX ip_org IF NOT EXISTS FOR (i:IP) ON (i.organization_id)",
                # Port indexes
                "CREATE INDEX port_number IF NOT EXISTS FOR (p:Port) ON (p.port)",
                "CREATE INDEX port_risky IF NOT EXISTS FOR (p:Port) ON (p.is_risky)",
                # Vulnerability indexes
                "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
                "CREATE INDEX vuln_status IF NOT EXISTS FOR (v:Vulnerability) ON (v.status)",
                "CREATE INDEX vuln_org IF NOT EXISTS FOR (v:Vulnerability) ON (v.organization_id)",
                # Technology indexes
                "CREATE INDEX tech_categories IF NOT EXISTS FOR (t:Technology) ON (t.categories)",
                # Web application layer
                "CREATE INDEX baseurl_org IF NOT EXISTS FOR (b:BaseURL) ON (b.organization_id)",
                "CREATE INDEX endpoint_org IF NOT EXISTS FOR (e:Endpoint) ON (e.organization_id)",
                "CREATE INDEX parameter_org IF NOT EXISTS FOR (p:Parameter) ON (p.organization_id)",
            ]
            
            for index in indexes:
                try:
                    session.run(index)
                except Exception as e:
                    logger.debug(f"Index may already exist: {e}")
        
        logger.info("Neo4j schema initialized with full relationship chain support")
    
    def sync_organization(self, organization_id: int):
        """
        Sync all assets from an organization to the graph.
        
        This creates nodes for:
        - Assets (Domain, Subdomain, IP, URL)
        - Vulnerabilities
        - Ports
        - Technologies
        
        And relationships:
        - DISCOVERED_FROM (asset to parent asset)
        - RESOLVES_TO (domain/subdomain to IP)
        - HAS_VULNERABILITY
        - HAS_PORT
        - USES_TECHNOLOGY
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            logger.warning("Cannot sync - Neo4j not connected")
            return {"synced": 0, "error": "Neo4j not connected"}

        if organization_id is None:
            logger.warning("Cannot sync - no organization specified")
            return {"synced": 0, "error": "Select an organization to sync. Sync runs for one organization at a time."}
        
        db = SessionLocal()
        try:
            # Get all assets for the organization
            assets = db.query(Asset).filter(
                Asset.organization_id == organization_id
            ).all()
            
            synced = 0
            
            with self.session() as session:
                for asset in assets:
                    self._sync_asset(session, asset, organization_id)
                    synced += 1
                # RedAmon-style: logical links between subdomains on same IP
                self._create_same_ip_links(session, organization_id)
            
            logger.info(f"Synced {synced} assets for organization {organization_id}")
            return {"synced": synced, "error": None}
        
        except Exception as e:
            logger.error(f"Sync error: {e}")
            return {"synced": 0, "error": str(e)}
        finally:
            db.close()
    
    def _sync_asset(self, session, asset: Asset, org_id: int):
        """
        Sync a single asset and all its relationships to the graph.
        
        Creates the full relationship chain:
        Domain → Subdomain → IP → Port → Service → Technology → Vulnerability → CVE
        """
        # Determine node label based on asset type
        label = self._get_label_for_type(asset.asset_type)
        
        # Create or update the asset node with all relevant fields
        session.run("""
            MERGE (a:Asset {asset_id: $id})
            SET a:""" + label + """,
                a.value = $value,
                a.name = $name,
                a.asset_type = $type,
                a.organization_id = $org_id,
                a.root_domain = $root_domain,
                a.is_active = $is_active,
                a.is_live = $is_live,
                a.first_seen = $first_seen,
                a.ars_score = $ars_score,
                a.acs_score = $acs_score,
                a.risk_score = $risk_score,
                a.criticality = $criticality,
                a.device_class = $device_class,
                a.device_subclass = $device_subclass,
                a.operating_system = $operating_system,
                a.hosting_type = $hosting_type,
                a.hosting_provider = $hosting_provider,
                a.country = $country,
                a.region = $region,
                a.in_scope = $in_scope,
                a.http_status = $http_status,
                a.has_login_portal = $has_login_portal
        """, {
            "id": asset.id,
            "value": asset.value,
            "name": asset.name,
            "type": asset.asset_type.value if asset.asset_type else None,
            "org_id": org_id,
            "root_domain": asset.root_domain,
            "is_active": getattr(asset, 'is_active', True),
            "is_live": getattr(asset, 'is_live', False),
            "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
            "ars_score": getattr(asset, 'ars_score', None),
            "acs_score": getattr(asset, 'acs_score', None),
            "risk_score": getattr(asset, 'risk_score', 0),
            "criticality": getattr(asset, 'criticality', 'medium'),
            "device_class": getattr(asset, 'device_class', None),
            "device_subclass": getattr(asset, 'device_subclass', None),
            "operating_system": getattr(asset, 'operating_system', None),
            "hosting_type": getattr(asset, 'hosting_type', None),
            "hosting_provider": getattr(asset, 'hosting_provider', None),
            "country": getattr(asset, 'country', None),
            "region": getattr(asset, 'region', None),
            "in_scope": getattr(asset, 'in_scope', True),
            "http_status": getattr(asset, 'http_status', None),
            "has_login_portal": getattr(asset, 'has_login_portal', False),
        })
        
        # ===== 1. CANONICAL CHAIN: Domain → Subdomain =====
        root_domain = getattr(asset, 'root_domain', None) or (
            asset.value if asset.asset_type == AssetType.DOMAIN else None
        )
        if asset.asset_type == AssetType.SUBDOMAIN and not root_domain:
            root_domain = asset.value  # use self as root if not set
        subdomain_name = (
            asset.value if asset.asset_type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)
            else (getattr(asset, 'root_domain', None) or asset.value)
        )
        if root_domain and subdomain_name:
            session.run("""
                MERGE (d:Domain {organization_id: $org_id, name: $root_domain})
                SET d.discovered_at = coalesce(d.discovered_at, datetime($first_seen))
                MERGE (s:Subdomain {organization_id: $org_id, name: $subdomain_name})
                SET s.status = $status
                MERGE (d)-[:HAS_SUBDOMAIN]->(s)
            """, {
                "org_id": org_id,
                "root_domain": root_domain,
                "subdomain_name": subdomain_name,
                "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
                "status": (asset.status.value if asset.status else "discovered"),
            })

        # ===== 1b. PARENT RELATIONSHIP (Asset hierarchy, for compatibility) =====
        if asset.parent_id:
            session.run("""
                MATCH (child:Asset {asset_id: $child_id})
                MATCH (parent:Asset {asset_id: $parent_id})
                MERGE (parent)-[:HAS_CHILD]->(child)
                MERGE (child)-[:BELONGS_TO]->(parent)
            """, {
                "child_id": asset.id,
                "parent_id": asset.parent_id,
            })

        # ===== 2. IP RESOLUTION: Subdomain RESOLVES_TO IP, Asset RESOLVES_TO IP =====
        ip_addresses = getattr(asset, 'ip_addresses', None) or []
        if not ip_addresses and getattr(asset, 'ip_address', None):
            ip_addresses = [asset.ip_address]
        for ip in ip_addresses:
            if ip:
                ip_type = "ipv6" if ":" in ip else "ipv4"
                is_cdn = bool(getattr(asset, 'hosting_type', None) in ("cdn", "cloud") or getattr(asset, 'hosting_provider', None))
                session.run("""
                    MATCH (a:Asset {asset_id: $asset_id})
                    MERGE (ip:IP {address: $ip_address})
                    SET ip.organization_id = $org_id,
                        ip.type = $ip_type,
                        ip.is_cdn = $is_cdn
                    MERGE (a)-[:RESOLVES_TO]->(ip)
                """, {
                    "asset_id": asset.id,
                    "ip_address": ip,
                    "org_id": org_id,
                    "ip_type": ip_type,
                    "is_cdn": is_cdn,
                })
                if root_domain and subdomain_name:
                    session.run("""
                        MERGE (s:Subdomain {organization_id: $org_id, name: $subdomain_name})
                        MERGE (ip:IP {address: $ip_address})
                        MERGE (s)-[:RESOLVES_TO]->(ip)
                    """, {
                        "org_id": org_id,
                        "subdomain_name": subdomain_name,
                        "ip_address": ip,
                    })
        
        # ===== 3. PORT/SERVICE: IP HAS_PORT Port, Port RUNS_SERVICE Service =====
        port_services = getattr(asset, 'port_services', None) or []
        for ps in port_services:
            port_num = ps.port
            protocol = ps.protocol.value if ps.protocol else 'tcp'
            state = ps.state.value if ps.state else 'open'
            service_name = ps.service_name or 'unknown'
            ip_for_port = ps.scanned_ip or (ip_addresses[0] if ip_addresses else None)

            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (p:Port {port_id: $port_id})
                SET p.port = $port,
                    p.protocol = $protocol,
                    p.state = $state,
                    p.is_risky = $is_risky,
                    p.scanned_ip = $scanned_ip,
                    p.organization_id = $org_id
                MERGE (a)-[:HAS_PORT]->(p)
            """, {
                "asset_id": asset.id,
                "port_id": ps.id,
                "port": port_num,
                "protocol": protocol,
                "state": state,
                "is_risky": ps.is_risky,
                "scanned_ip": ps.scanned_ip,
                "org_id": org_id,
            })

            if ip_for_port:
                session.run("""
                    MATCH (ip:IP {address: $ip_address})
                    MATCH (p:Port {port_id: $port_id})
                    MERGE (ip)-[:HAS_PORT]->(p)
                """, {"ip_address": ip_for_port, "port_id": ps.id})

            session.run("""
                MATCH (p:Port {port_id: $port_id})
                MERGE (s:Service {name: $service_name})
                SET s.version = $version,
                    s.banner = $banner,
                    s.product = $product,
                    s.cpe = $cpe
                MERGE (p)-[:RUNS_SERVICE]->(s)
            """, {
                "port_id": ps.id,
                "service_name": service_name,
                "version": ps.service_version,
                "banner": ps.banner,
                "product": ps.service_product,
                "cpe": ps.cpe,
            })
        
        # ===== 4. TECHNOLOGY: Asset USES_TECHNOLOGY, Service USES_TECHNOLOGY =====
        technologies = getattr(asset, 'technologies', None) or []
        for tech in technologies:
            categories = tech.categories if tech.categories else []
            category_str = ', '.join(categories) if categories else None
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (t:Technology {name: $name})
                SET t.slug = $slug,
                    t.version = $version,
                    t.category = $category,
                    t.categories = $categories,
                    t.cpe = $cpe,
                    t.website = $website
                MERGE (a)-[:USES_TECHNOLOGY]->(t)
            """, {
                "asset_id": asset.id,
                "name": tech.name,
                "slug": tech.slug,
                "version": getattr(tech, 'version', None),
                "category": categories[0] if categories else None,
                "categories": category_str,
                "cpe": tech.cpe,
                "website": tech.website,
            })
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})-[:HAS_PORT]->(p:Port)-[:RUNS_SERVICE]->(s:Service)
                MATCH (t:Technology {name: $name})
                MERGE (s)-[:USES_TECHNOLOGY]->(t)
            """, {"asset_id": asset.id, "name": tech.name})
        
        # ===== 5. VULNERABILITY: Technology HAS_VULNERABILITY, REFERENCES CVE, MAPS_TO MITRE =====
        vulnerabilities = getattr(asset, 'vulnerabilities', None) or []
        for vuln in vulnerabilities:
            desc = (vuln.description or getattr(vuln, 'evidence', None) or vuln.title or "")[:2000]
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (v:Vulnerability {vuln_id: $vuln_id})
                SET v.id = $vuln_id,
                    v.title = $title,
                    v.severity = $severity,
                    v.description = $description,
                    v.cvss_score = $cvss,
                    v.status = $status,
                    v.template_id = $template_id,
                    v.detected_by = $detected_by,
                    v.organization_id = $org_id
                MERGE (a)-[:HAS_VULNERABILITY]->(v)
            """, {
                "asset_id": asset.id,
                "vuln_id": vuln.id,
                "title": vuln.title,
                "severity": vuln.severity.value if vuln.severity else None,
                "description": desc,
                "cvss": vuln.cvss_score,
                "status": vuln.status.value if vuln.status else None,
                "template_id": vuln.template_id,
                "detected_by": vuln.detected_by,
                "org_id": org_id,
            })
            if technologies:
                session.run("""
                    MATCH (a:Asset {asset_id: $asset_id})-[:USES_TECHNOLOGY]->(t:Technology)
                    MATCH (v:Vulnerability {vuln_id: $vuln_id})
                    MERGE (t)-[:HAS_VULNERABILITY]->(v)
                """, {"asset_id": asset.id, "vuln_id": vuln.id})
            if vuln.cve_id:
                session.run("""
                    MATCH (v:Vulnerability {vuln_id: $vuln_id})
                    MERGE (cve:CVE {cve_id: $cve_id})
                    SET cve.cvss_score = $cvss,
                        cve.cwe_id = $cwe_id
                    MERGE (v)-[:REFERENCES]->(cve)
                """, {
                    "vuln_id": vuln.id,
                    "cve_id": vuln.cve_id,
                    "cvss": vuln.cvss_score,
                    "cwe_id": vuln.cwe_id,
                })
            if vuln.cwe_id:
                session.run("""
                    MATCH (v:Vulnerability {vuln_id: $vuln_id})
                    MERGE (cwe:CWE {cwe_id: $cwe_id})
                    MERGE (v)-[:MAPS_TO]->(cwe)
                """, {"vuln_id": vuln.id, "cwe_id": vuln.cwe_id})
                if vuln.cve_id:
                    session.run("""
                        MATCH (cve:CVE {cve_id: $cve_id})
                        MATCH (cwe:CWE {cwe_id: $cwe_id})
                        MERGE (cve)-[:EXPLOITS_WEAKNESS]->(cwe)
                    """, {"cve_id": vuln.cve_id, "cwe_id": vuln.cwe_id})
            
            # ===== 7b. FOUND_AT: link vulnerability to Endpoint when url/path known (web layer) =====
            path_for_endpoint = None
            meta = getattr(vuln, 'metadata_', None) or {}
            if isinstance(meta, dict):
                if meta.get('path'):
                    path_for_endpoint = (meta.get('path') or '').strip()
                elif meta.get('url'):
                    path_for_endpoint = urlparse(meta['url']).path or ''
            if not path_for_endpoint and getattr(vuln, 'evidence', None):
                try:
                    path_for_endpoint = urlparse(str(vuln.evidence)).path or ''
                except Exception:
                    pass
            if path_for_endpoint:
                path_for_endpoint = path_for_endpoint.strip()[:2000]
                endpoint_id = "ep_" + hashlib.sha256(f"{org_id}:{asset.id}:{path_for_endpoint}".encode()).hexdigest()[:20]
                session.run("""
                    MATCH (v:Vulnerability {vuln_id: $vuln_id})
                    MATCH (a:Asset {asset_id: $asset_id})-[:HAS_ENDPOINT]->(e:Endpoint {endpoint_id: $endpoint_id})
                    MERGE (v)-[:FOUND_AT]->(e)
                """, {"vuln_id": vuln.id, "asset_id": asset.id, "endpoint_id": endpoint_id})
        
        # ===== 8. BASEURL (live HTTP endpoint) =====
        live_url = getattr(asset, 'live_url', None) or (asset.value if getattr(asset, 'asset_type', None) and str(getattr(asset.asset_type, 'value', '')) == 'URL' else None)
        if live_url:
            baseurl_id = f"url_{org_id}_{asset.id}"
            http_headers = getattr(asset, 'http_headers', None) or {}
            server = http_headers.get('Server') or http_headers.get('server') if isinstance(http_headers, dict) else None
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (b:BaseURL {baseurl_id: $baseurl_id})
                SET b.url = $url,
                    b.status_code = $status_code,
                    b.title = $title,
                    b.server = $server,
                    b.organization_id = $org_id
                MERGE (a)-[:SERVES_URL]->(b)
            """, {
                "asset_id": asset.id,
                "baseurl_id": baseurl_id,
                "url": live_url,
                "status_code": getattr(asset, 'http_status', None),
                "title": getattr(asset, 'http_title', None),
                "server": server,
                "org_id": org_id,
            })
            # Link Service (80/443) to BaseURL when present
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})-[:HAS_PORT]->(p:Port)
                WHERE p.port IN [80, 443]
                WITH p LIMIT 1
                MATCH (p)-[:RUNS_SERVICE]->(s:Service)
                MATCH (b:BaseURL {baseurl_id: $baseurl_id})
                MERGE (s)-[:SERVES_URL]->(b)
            """, {"asset_id": asset.id, "baseurl_id": baseurl_id})
        
        # ===== 9. ENDPOINTS (discovered paths from Katana, ParamSpider, Wayback) =====
        endpoints = getattr(asset, 'endpoints', None) or []
        for path in endpoints[:500]:  # Cap for sync performance
            if not path or not isinstance(path, str):
                continue
            path_strip = path.strip()
            if not path_strip:
                continue
            endpoint_id = "ep_" + hashlib.sha256(f"{org_id}:{asset.id}:{path_strip}".encode()).hexdigest()[:20]
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (e:Endpoint {endpoint_id: $endpoint_id})
                SET e.path = $path,
                    e.source = $source,
                    e.organization_id = $org_id
                MERGE (a)-[:HAS_ENDPOINT]->(e)
            """, {
                "asset_id": asset.id,
                "endpoint_id": endpoint_id,
                "path": path_strip[:2000],
                "source": "aggregated",
                "org_id": org_id,
            })
        
        # ===== 10. PARAMETERS (discovered params from Katana, ParamSpider) =====
        parameters = getattr(asset, 'parameters', None) or []
        for param_name in parameters[:300]:
            if param_name is None:
                continue
            name_str = str(param_name).strip()
            if not name_str:
                continue
            parameter_id = "pm_" + hashlib.sha256(f"{org_id}:{asset.id}:{name_str}".encode()).hexdigest()[:20]
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (p:Parameter {parameter_id: $parameter_id})
                SET p.name = $name,
                    p.organization_id = $org_id
                MERGE (a)-[:HAS_PARAMETER]->(p)
            """, {
                "asset_id": asset.id,
                "parameter_id": parameter_id,
                "name": name_str[:500],
                "org_id": org_id,
            })
    
    def _create_same_ip_links(self, session, org_id: int):
        """
        Create SAME_IP_AS relationships between Subdomains that resolve to the same IP.
        Enables queries like "what other subdomains share this IP?" (RedAmon-style graph robustness).
        """
        try:
            session.run("""
                MATCH (s1:Subdomain {organization_id: $org_id})-[:RESOLVES_TO]->(ip:IP)
                MATCH (s2:Subdomain {organization_id: $org_id})-[:RESOLVES_TO]->(ip)
                WHERE s1.name < s2.name
                MERGE (s1)-[:SAME_IP_AS]->(s2)
                MERGE (s2)-[:SAME_IP_AS]->(s1)
            """, {"org_id": org_id})
        except Exception as e:
            logger.debug(f"SAME_IP_AS links: {e}")

    def _get_label_for_type(self, asset_type: AssetType) -> str:
        """Get Neo4j node label for an asset type."""
        if not asset_type:
            return "Asset"
        
        label_map = {
            AssetType.DOMAIN: "Domain",
            AssetType.SUBDOMAIN: "Subdomain",
            AssetType.IP_ADDRESS: "IP",
            AssetType.URL: "URL",
            AssetType.CERTIFICATE: "Certificate",
        }
        return label_map.get(asset_type, "Asset")
    
    def query(self, cypher: str, params: Dict[str, Any] = None) -> List[Dict]:
        """
        Execute a Cypher query and return results.
        
        Args:
            cypher: Cypher query string
            params: Query parameters
        
        Returns:
            List of result records as dictionaries
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            return []
        
        with self.session() as session:
            result = session.run(cypher, params or {})
            return [record.data() for record in result]
    
    def get_attack_paths(
        self,
        organization_id: int,
        target_asset_id: Optional[int] = None,
        max_depth: int = 5
    ) -> List[Dict]:
        """
        Find potential attack paths in the graph.
        
        An attack path is a chain of relationships that could be
        exploited by an attacker to reach a critical asset.
        
        Args:
            organization_id: Organization to query
            target_asset_id: Optional specific target asset
            max_depth: Maximum path depth
        
        Returns:
            List of attack paths with nodes and relationships
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            return []
        
        if target_asset_id:
            # Find paths to a specific asset
            cypher = """
                MATCH path = (start:Asset)-[*1..""" + str(max_depth) + """]->(target:Asset {asset_id: $target_id})
                WHERE start.organization_id = $org_id
                  AND target.organization_id = $org_id
                  AND (target)-[:HAS_VULNERABILITY]->(:Vulnerability)
                RETURN path,
                       [node IN nodes(path) | node.value] AS assets,
                       [rel IN relationships(path) | type(rel)] AS relationships
                LIMIT 20
            """
            params = {"org_id": organization_id, "target_id": target_asset_id}
        else:
            # Find paths to any vulnerable asset
            cypher = """
                MATCH path = (start:Asset)-[*1..""" + str(max_depth) + """]->(target:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
                WHERE start.organization_id = $org_id
                  AND target.organization_id = $org_id
                  AND v.severity IN ['critical', 'high']
                RETURN path,
                       [node IN nodes(path) | node.value] AS assets,
                       [rel IN relationships(path) | type(rel)] AS relationships,
                       v.cve_id AS target_cve,
                       v.severity AS severity
                LIMIT 20
            """
            params = {"org_id": organization_id}
        
        return self.query(cypher, params)
    
    def get_asset_relationships(
        self,
        asset_id: int,
        depth: int = 2
    ) -> Dict[str, Any]:
        """
        Get all relationships for an asset up to a given depth.
        
        Args:
            asset_id: Asset ID to query
            depth: Relationship depth
        
        Returns:
            Dict with nodes and edges for visualization
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            return {"nodes": [], "edges": []}
        
        cypher = """
            MATCH (center:Asset {asset_id: $asset_id})
            CALL apoc.path.subgraphAll(center, {
                maxLevel: $depth,
                relationshipFilter: ">",
                labelFilter: "+Asset|+Vulnerability|+Port|+Technology|+IP"
            })
            YIELD nodes, relationships
            RETURN 
                [n IN nodes | {
                    id: id(n),
                    labels: labels(n),
                    properties: properties(n)
                }] AS nodes,
                [r IN relationships | {
                    source: id(startNode(r)),
                    target: id(endNode(r)),
                    type: type(r)
                }] AS edges
        """
        
        try:
            results = self.query(cypher, {"asset_id": asset_id, "depth": depth})
            if results:
                return results[0]
            return {"nodes": [], "edges": []}
        except Exception as e:
            # APOC might not be installed - fallback to simpler query
            logger.warning(f"APOC query failed, using fallback: {e}")
            
            fallback_cypher = """
                MATCH (center:Asset {asset_id: $asset_id})-[r*1..""" + str(depth) + """]-(connected)
                WITH center, collect(DISTINCT connected) AS connected_nodes, collect(DISTINCT r) AS rels
                RETURN center, connected_nodes
            """
            
            results = self.query(fallback_cypher, {"asset_id": asset_id})
            return {"nodes": results, "edges": []}
    
    def get_vulnerability_impact(
        self,
        vulnerability_id: int,
        organization_id: int
    ) -> Dict[str, Any]:
        """
        Analyze the potential impact of a vulnerability.
        
        Finds all assets that could be affected through relationships.
        
        Args:
            vulnerability_id: Vulnerability ID
            organization_id: Organization ID
        
        Returns:
            Impact analysis with affected assets
        """
        if not self._connected:
            self.connect()
        
        if not self._connected:
            return {"direct": [], "indirect": [], "total_impact": 0}
        
        cypher = """
            MATCH (v:Vulnerability {vuln_id: $vuln_id})<-[:HAS_VULNERABILITY]-(direct:Asset)
            WHERE direct.organization_id = $org_id
            OPTIONAL MATCH (direct)<-[:DISCOVERED_FROM|RESOLVES_TO*1..3]-(indirect:Asset)
            WHERE indirect.organization_id = $org_id
            RETURN 
                collect(DISTINCT {id: direct.asset_id, value: direct.value, type: direct.asset_type}) AS direct_assets,
                collect(DISTINCT {id: indirect.asset_id, value: indirect.value, type: indirect.asset_type}) AS indirect_assets
        """
        
        results = self.query(cypher, {
            "vuln_id": vulnerability_id,
            "org_id": organization_id
        })
        
        if results:
            result = results[0]
            direct = [a for a in result.get("direct_assets", []) if a.get("id")]
            indirect = [a for a in result.get("indirect_assets", []) if a.get("id") and a not in direct]
            
            return {
                "direct": direct,
                "indirect": indirect,
                "total_impact": len(direct) + len(indirect)
            }
        
        return {"direct": [], "indirect": [], "total_impact": 0}


# Global service instance
_graph_service: Optional[GraphService] = None


def get_graph_service() -> GraphService:
    """Get or create the global graph service."""
    global _graph_service
    if _graph_service is None:
        _graph_service = GraphService()
        _graph_service.connect()
        if _graph_service._connected:
            _graph_service.initialize_schema()
    return _graph_service


def sync_asset_to_graph(asset_id: int, organization_id: int) -> bool:
    """
    Sync a single asset to the graph database.
    
    This is designed to be called after asset creation/updates
    to keep the graph in sync.
    
    Returns True if sync succeeded, False otherwise.
    """
    try:
        graph = get_graph_service()
        if not graph._connected:
            return False
        
        db = SessionLocal()
        try:
            asset = db.query(Asset).filter(Asset.id == asset_id).first()
            if not asset:
                return False
            
            with graph.session() as session:
                graph._sync_asset(session, asset, organization_id)
            
            logger.info(f"Synced asset {asset_id} to graph")
            return True
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"Failed to sync asset {asset_id} to graph: {e}")
        return False


def sync_organization_background(organization_id: int) -> dict:
    """
    Sync all assets for an organization to the graph.
    
    This is designed to be called from background tasks.
    Returns sync statistics.
    """
    try:
        graph = get_graph_service()
        if not graph._connected:
            return {"synced": 0, "error": "Neo4j not connected"}
        
        return graph.sync_organization(organization_id)
    except Exception as e:
        logger.error(f"Background graph sync error: {e}")
        return {"synced": 0, "error": str(e)}
