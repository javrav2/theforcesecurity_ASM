"""
Graph Database API Routes

Endpoints for querying and visualizing asset relationships
using the Neo4j graph database.
"""

import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User
from app.services.graph_service import get_graph_service
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["Graph"])


# =============================================================================
# RESPONSE MODELS
# =============================================================================

class GraphNode(BaseModel):
    """A node in the graph."""
    id: int
    labels: List[str]
    properties: dict


class GraphEdge(BaseModel):
    """An edge/relationship in the graph."""
    source: int
    target: int
    type: str


class GraphData(BaseModel):
    """Graph data for visualization."""
    nodes: List[dict]
    edges: List[dict]


class AttackPath(BaseModel):
    """An attack path in the graph."""
    assets: List[str]
    relationships: List[str]
    target_cve: Optional[str] = None
    severity: Optional[str] = None


class VulnerabilityImpact(BaseModel):
    """Impact analysis for a vulnerability."""
    direct: List[dict]
    indirect: List[dict]
    total_impact: int


class SyncResult(BaseModel):
    """Result of a graph sync operation."""
    synced: int
    error: Optional[str] = None


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/status")
async def get_graph_status():
    """
    Check if the graph database is available.
    """
    try:
        graph = get_graph_service()
        connected = graph._connected
        
        # Test query
        node_count = 0
        relationship_count = 0
        if connected:
            result = graph.query("RETURN 1 AS test")
            connected = bool(result)
            
            if connected:
                # Get counts
                node_result = graph.query("MATCH (n) RETURN count(n) AS count")
                if node_result:
                    node_count = node_result[0].get("count", 0)
                
                rel_result = graph.query("MATCH ()-[r]->() RETURN count(r) AS count")
                if rel_result:
                    relationship_count = rel_result[0].get("count", 0)
        
        return {
            "connected": connected,
            "enabled": bool(settings.NEO4J_URI),
            "uri": settings.NEO4J_URI if connected else None,
            "node_count": node_count,
            "relationship_count": relationship_count,
        }
    except Exception as e:
        return {
            "connected": False,
            "enabled": bool(settings.NEO4J_URI),
            "error": str(e)
        }


@router.post("/sync")
async def sync_organization_graph(
    organization_id: Optional[int] = Query(default=None),
    current_user: User = Depends(get_current_user)
):
    """
    Sync organization's assets to the graph database.
    
    This creates nodes and relationships for all assets, vulnerabilities,
    ports, and technologies in the organization.
    """
    org_id = organization_id or (current_user.organization_id if hasattr(current_user, 'organization_id') else None)
    
    try:
        graph = get_graph_service()
        result = graph.sync_organization(org_id)
        return {
            "assets_synced": result.get("synced", 0),
            "error": result.get("error"),
        }
    except Exception as e:
        logger.error(f"Graph sync error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/asset/{asset_id}/relationships")
async def get_asset_relationships(
    asset_id: int,
    depth: int = Query(default=2, ge=1, le=5),
    current_user: User = Depends(get_current_user)
):
    """
    Get all relationships for an asset up to a specified depth.
    
    Returns nodes and relationships suitable for graph visualization.
    """
    try:
        graph = get_graph_service()
        result = graph.get_asset_relationships(asset_id, depth)
        
        # Transform to frontend format
        nodes = []
        relationships = []
        seen_nodes = set()
        
        for record in result.get("nodes", []):
            node_id = record.get("id") or record.get("element_id")
            if node_id and node_id not in seen_nodes:
                seen_nodes.add(node_id)
                nodes.append({
                    "id": node_id,
                    "element_id": node_id,
                    "labels": record.get("labels", []),
                    "properties": record.get("properties", {}),
                })
        
        for record in result.get("edges", []):
            relationships.append({
                "source": record.get("source"),
                "target": record.get("target"),
                "start_node": record.get("source"),
                "end_node": record.get("target"),
                "type": record.get("type"),
                "properties": record.get("properties", {}),
            })
        
        return {
            "nodes": nodes,
            "relationships": relationships,
        }
    except Exception as e:
        logger.error(f"Relationship query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-paths")
async def get_attack_paths(
    source_id: Optional[int] = None,
    target_id: Optional[int] = None,
    organization_id: Optional[int] = None,
    max_paths: int = Query(default=5, ge=1, le=20),
    current_user: User = Depends(get_current_user)
):
    """
    Find potential attack paths between assets.
    
    Attack paths show chains of relationships that could be exploited
    by an attacker to move between assets.
    
    Args:
        source_id: Starting asset (entry point)
        target_id: Ending asset (goal)
        organization_id: Filter by organization
        max_paths: Maximum number of paths to return
    """
    org_id = organization_id or (current_user.organization_id if hasattr(current_user, 'organization_id') else None)
    
    try:
        graph = get_graph_service()
        
        # Build query based on parameters
        if source_id and target_id:
            # Find paths between specific assets
            query = """
            MATCH path = shortestPath((source:Asset {id: $source_id})-[*1..6]-(target:Asset {id: $target_id}))
            RETURN path
            LIMIT $max_paths
            """
            params = {"source_id": source_id, "target_id": target_id, "max_paths": max_paths}
        else:
            # Find paths to vulnerable assets
            query = """
            MATCH path = (entry:Asset)-[*1..4]->(vuln:Vulnerability)
            WHERE vuln.severity IN ['critical', 'high']
            RETURN path
            LIMIT $max_paths
            """
            params = {"max_paths": max_paths}
            if org_id:
                query = query.replace("MATCH path", "MATCH path = (entry:Asset {organization_id: $org_id})")
                params["org_id"] = org_id
        
        results = graph.query(query, params)
        
        paths = []
        for record in results:
            path_data = record.get("path")
            if path_data:
                nodes = []
                relationships = []
                
                # Extract nodes and relationships from path
                if hasattr(path_data, 'nodes'):
                    for node in path_data.nodes:
                        nodes.append({
                            "id": node.element_id if hasattr(node, 'element_id') else str(node.id),
                            "labels": list(node.labels) if hasattr(node, 'labels') else [],
                            "properties": dict(node) if node else {},
                        })
                
                if hasattr(path_data, 'relationships'):
                    for rel in path_data.relationships:
                        relationships.append({
                            "type": rel.type if hasattr(rel, 'type') else str(type(rel)),
                            "source": rel.start_node.element_id if hasattr(rel, 'start_node') else None,
                            "target": rel.end_node.element_id if hasattr(rel, 'end_node') else None,
                        })
                
                paths.append({
                    "nodes": nodes,
                    "relationships": relationships,
                })
        
        return {"paths": paths}
    except Exception as e:
        logger.error(f"Attack path query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/vulnerability/{vuln_id}/impact", response_model=VulnerabilityImpact)
async def get_vulnerability_impact(
    vuln_id: int,
    current_user: User = Depends(get_current_user)
):
    """
    Analyze the potential impact of a vulnerability.
    
    Returns directly affected assets and indirectly affected assets
    through relationship chains.
    """
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    try:
        graph = get_graph_service()
        result = graph.get_vulnerability_impact(vuln_id, org_id)
        return VulnerabilityImpact(**result)
    except Exception as e:
        logger.error(f"Impact analysis error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/query")
async def execute_graph_query(
    query: str,
    current_user: User = Depends(get_current_user)
):
    """
    Execute a custom Cypher query (admin only).
    
    The query is automatically filtered by organization_id.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="Only admins can execute custom queries"
        )
    
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    
    # Add organization filter for safety
    if org_id and "organization_id" not in query.lower():
        # Inject org filter into WHERE clause
        if "WHERE" in query.upper():
            query = query.replace("WHERE", f"WHERE n.organization_id = {org_id} AND ", 1)
        elif "RETURN" in query.upper():
            query = query.replace("RETURN", f"WHERE n.organization_id = {org_id} RETURN", 1)
    
    try:
        graph = get_graph_service()
        results = graph.query(query)
        return {"results": results, "count": len(results)}
    except Exception as e:
        logger.error(f"Custom query error: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/statistics")
async def get_graph_statistics(
    current_user: User = Depends(get_current_user)
):
    """
    Get statistics about the graph database.
    """
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    try:
        graph = get_graph_service()
        
        # Get node counts by label
        node_counts = graph.query("""
            MATCH (n)
            WHERE n.organization_id = $org_id
            RETURN labels(n)[0] AS label, count(n) AS count
            ORDER BY count DESC
        """, {"org_id": org_id})
        
        # Get relationship counts
        rel_counts = graph.query("""
            MATCH (n)-[r]->(m)
            WHERE n.organization_id = $org_id
            RETURN type(r) AS type, count(r) AS count
            ORDER BY count DESC
        """, {"org_id": org_id})
        
        # Get vulnerability severity distribution
        vuln_dist = graph.query("""
            MATCH (a:Asset)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            WHERE a.organization_id = $org_id
            RETURN v.severity AS severity, count(v) AS count
        """, {"org_id": org_id})
        
        return {
            "nodes": {r.get("label", "Unknown"): r.get("count", 0) for r in node_counts},
            "relationships": {r.get("type", "Unknown"): r.get("count", 0) for r in rel_counts},
            "vulnerabilities_by_severity": {r.get("severity", "Unknown"): r.get("count", 0) for r in vuln_dist},
        }
    except Exception as e:
        logger.error(f"Statistics query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
