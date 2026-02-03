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
        if connected:
            result = graph.query("RETURN 1 AS test")
            connected = bool(result)
        
        return {
            "available": connected,
            "uri": settings.NEO4J_URI if connected else None,
        }
    except Exception as e:
        return {
            "available": False,
            "error": str(e)
        }


@router.post("/sync", response_model=SyncResult)
async def sync_organization_graph(
    current_user: User = Depends(get_current_user)
):
    """
    Sync the current organization's assets to the graph database.
    
    This creates nodes and relationships for all assets, vulnerabilities,
    ports, and technologies in the organization.
    """
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    try:
        graph = get_graph_service()
        result = graph.sync_organization(org_id)
        return SyncResult(**result)
    except Exception as e:
        logger.error(f"Graph sync error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/asset/{asset_id}/relationships", response_model=GraphData)
async def get_asset_relationships(
    asset_id: int,
    depth: int = Query(default=2, ge=1, le=5),
    current_user: User = Depends(get_current_user)
):
    """
    Get all relationships for an asset up to a specified depth.
    
    Returns nodes and edges suitable for graph visualization.
    """
    try:
        graph = get_graph_service()
        result = graph.get_asset_relationships(asset_id, depth)
        return GraphData(**result)
    except Exception as e:
        logger.error(f"Relationship query error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/attack-paths", response_model=List[AttackPath])
async def get_attack_paths(
    target_asset_id: Optional[int] = None,
    max_depth: int = Query(default=5, ge=1, le=10),
    current_user: User = Depends(get_current_user)
):
    """
    Find potential attack paths in the organization's infrastructure.
    
    Attack paths show chains of relationships that could be exploited
    by an attacker to reach critical assets.
    
    Args:
        target_asset_id: Optional specific target asset
        max_depth: Maximum path depth to search
    """
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    try:
        graph = get_graph_service()
        results = graph.get_attack_paths(org_id, target_asset_id, max_depth)
        
        paths = []
        for r in results:
            paths.append(AttackPath(
                assets=r.get("assets", []),
                relationships=r.get("relationships", []),
                target_cve=r.get("target_cve"),
                severity=r.get("severity"),
            ))
        
        return paths
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
