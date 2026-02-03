"""
Neo4j Graph Database Service

Manages the graph representation of assets and their relationships
for attack path analysis and visualization.
"""

import logging
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

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
    
    Models the following relationships:
    - Domain -> Subdomain (HAS_SUBDOMAIN)
    - Asset -> IP (RESOLVES_TO)
    - IP -> Port (HAS_PORT)
    - Asset -> Vulnerability (HAS_VULNERABILITY)
    - Asset -> Technology (USES_TECHNOLOGY)
    - Asset -> Asset (DISCOVERED_FROM)
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
            ]
            
            for constraint in constraints:
                try:
                    session.run(constraint)
                except Exception as e:
                    logger.debug(f"Constraint may already exist: {e}")
            
            # Create indexes for common queries
            indexes = [
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
        
        # ===== 1. PARENT RELATIONSHIP (Domain → Subdomain) =====
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
        
        # ===== 2. IP RESOLUTION (Asset → IP addresses) =====
        # Use the actual ip_addresses array from the asset
        ip_addresses = getattr(asset, 'ip_addresses', None) or []
        if not ip_addresses and getattr(asset, 'ip_address', None):
            ip_addresses = [asset.ip_address]
        
        for ip in ip_addresses:
            if ip:
                session.run("""
                    MATCH (a:Asset {asset_id: $asset_id})
                    MERGE (ip:IP {address: $ip_address})
                    SET ip.organization_id = $org_id
                    MERGE (a)-[:RESOLVES_TO]->(ip)
                """, {
                    "asset_id": asset.id,
                    "ip_address": ip,
                    "org_id": org_id,
                })
        
        # ===== 3. PORT/SERVICE RELATIONSHIPS =====
        # Use port_services relationship from the model
        port_services = getattr(asset, 'port_services', None) or []
        for ps in port_services:
            port_num = ps.port
            protocol = ps.protocol.value if ps.protocol else 'tcp'
            service_name = ps.service_name or 'unknown'
            
            # Create Port node
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
                "state": ps.state.value if ps.state else 'open',
                "is_risky": ps.is_risky,
                "scanned_ip": ps.scanned_ip,
                "org_id": org_id,
            })
            
            # Create Service node connected to Port
            if ps.service_name:
                session.run("""
                    MATCH (p:Port {port_id: $port_id})
                    MERGE (s:Service {name: $service_name})
                    SET s.product = $product,
                        s.version = $version,
                        s.cpe = $cpe
                    MERGE (p)-[:RUNS_SERVICE]->(s)
                """, {
                    "port_id": ps.id,
                    "service_name": ps.service_name,
                    "product": ps.service_product,
                    "version": ps.service_version,
                    "cpe": ps.cpe,
                })
            
            # Connect IP to Port if we have scanned_ip
            if ps.scanned_ip:
                session.run("""
                    MATCH (ip:IP {address: $ip_address})
                    MATCH (p:Port {port_id: $port_id})
                    MERGE (ip)-[:EXPOSES_PORT]->(p)
                """, {
                    "ip_address": ps.scanned_ip,
                    "port_id": ps.id,
                })
        
        # ===== 4. TECHNOLOGY RELATIONSHIPS =====
        technologies = getattr(asset, 'technologies', None) or []
        for tech in technologies:
            # Get categories as a string
            categories = tech.categories if tech.categories else []
            category_str = ', '.join(categories) if categories else None
            
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (t:Technology {name: $name})
                SET t.slug = $slug,
                    t.categories = $categories,
                    t.cpe = $cpe,
                    t.website = $website
                MERGE (a)-[:USES_TECHNOLOGY]->(t)
            """, {
                "asset_id": asset.id,
                "name": tech.name,
                "slug": tech.slug,
                "categories": category_str,
                "cpe": tech.cpe,
                "website": tech.website,
            })
        
        # ===== 5. VULNERABILITY RELATIONSHIPS =====
        vulnerabilities = getattr(asset, 'vulnerabilities', None) or []
        for vuln in vulnerabilities:
            session.run("""
                MATCH (a:Asset {asset_id: $asset_id})
                MERGE (v:Vulnerability {vuln_id: $vuln_id})
                SET v.title = $title,
                    v.severity = $severity,
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
                "cvss": vuln.cvss_score,
                "status": vuln.status.value if vuln.status else None,
                "template_id": vuln.template_id,
                "detected_by": vuln.detected_by,
                "org_id": org_id,
            })
            
            # ===== 6. CVE NODE (from vulnerability) =====
            if vuln.cve_id:
                session.run("""
                    MATCH (v:Vulnerability {vuln_id: $vuln_id})
                    MERGE (cve:CVE {cve_id: $cve_id})
                    SET cve.cvss_score = $cvss,
                        cve.cwe_id = $cwe_id
                    MERGE (v)-[:REFERENCES_CVE]->(cve)
                """, {
                    "vuln_id": vuln.id,
                    "cve_id": vuln.cve_id,
                    "cvss": vuln.cvss_score,
                    "cwe_id": vuln.cwe_id,
                })
            
            # ===== 7. CWE NODE (from vulnerability) =====
            if vuln.cwe_id:
                session.run("""
                    MATCH (v:Vulnerability {vuln_id: $vuln_id})
                    MERGE (cwe:CWE {cwe_id: $cwe_id})
                    MERGE (v)-[:HAS_WEAKNESS]->(cwe)
                """, {
                    "vuln_id": vuln.id,
                    "cwe_id": vuln.cwe_id,
                })
                
                # Connect CVE to CWE if both exist
                if vuln.cve_id:
                    session.run("""
                        MATCH (cve:CVE {cve_id: $cve_id})
                        MATCH (cwe:CWE {cwe_id: $cwe_id})
                        MERGE (cve)-[:EXPLOITS_WEAKNESS]->(cwe)
                    """, {
                        "cve_id": vuln.cve_id,
                        "cwe_id": vuln.cwe_id,
                    })
    
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
        _graph_service.initialize_schema()
    return _graph_service
