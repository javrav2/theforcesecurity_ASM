"""
MITRE ATT&CK Enrichment API Routes

Endpoints for enriching vulnerabilities with MITRE ATT&CK framework data.
"""

import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User
from app.services.mitre_enrichment_service import get_mitre_service
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


# =============================================================================
# RESPONSE MODELS
# =============================================================================

class AttackTechnique(BaseModel):
    """ATT&CK Technique information."""
    id: str
    name: Optional[str] = None
    tactic: Optional[str] = None
    description: Optional[str] = None
    mitre_url: Optional[str] = None


class CAPECPattern(BaseModel):
    """CAPEC Attack Pattern."""
    id: str
    name: str
    url: str


class EnrichmentResult(BaseModel):
    """Result of vulnerability enrichment."""
    enriched: bool
    cwe_id: Optional[str] = None
    cwe_description: Optional[str] = None
    capec_ids: List[str] = []
    attack_patterns: List[str] = []
    attack_techniques: List[AttackTechnique] = []
    reason: Optional[str] = None


class BatchEnrichmentResult(BaseModel):
    """Result of batch enrichment."""
    total: int
    enriched: int
    not_mapped: int
    error: Optional[str] = None


class CWELookupResult(BaseModel):
    """Result of CWE lookup."""
    cwe_id: str
    description: Optional[str] = None
    capec_patterns: List[CAPECPattern]
    attack_techniques: List[AttackTechnique]


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/status")
async def get_enrichment_status():
    """
    Check if MITRE enrichment is enabled.
    """
    return {
        "enabled": settings.MITRE_ENRICHMENT_ENABLED,
        "supported_cwes": len(get_mitre_service().get_supported_cwes()),
    }


@router.post("/enrich/{vulnerability_id}", response_model=EnrichmentResult)
async def enrich_vulnerability(
    vulnerability_id: int,
    current_user: User = Depends(get_current_user)
):
    """
    Enrich a single vulnerability with MITRE ATT&CK data.
    
    Maps the vulnerability's CWE to CAPEC attack patterns and
    ATT&CK techniques, then updates the vulnerability metadata.
    """
    service = get_mitre_service()
    result = service.enrich_and_update(vulnerability_id)
    
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    
    return EnrichmentResult(**result)


@router.post("/batch-enrich", response_model=BatchEnrichmentResult)
async def batch_enrich_vulnerabilities(
    current_user: User = Depends(get_current_user)
):
    """
    Enrich all vulnerabilities in the organization with MITRE data.
    
    Only processes vulnerabilities that have a CWE ID.
    """
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    service = get_mitre_service()
    result = service.batch_enrich(org_id)
    
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])
    
    return BatchEnrichmentResult(**result)


@router.get("/lookup/{cwe_id}", response_model=CWELookupResult)
async def lookup_cwe_mappings(
    cwe_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Look up MITRE mappings for a specific CWE.
    
    Returns associated CAPEC attack patterns and ATT&CK techniques.
    """
    service = get_mitre_service()
    
    # Normalize CWE ID
    cwe_id_normalized = cwe_id.upper()
    if not cwe_id_normalized.startswith("CWE-"):
        cwe_id_normalized = f"CWE-{cwe_id_normalized}"
    
    capec_patterns = service.get_capec_for_cwe(cwe_id_normalized)
    attack_techniques = service.get_attack_techniques_for_cwe(cwe_id_normalized)
    
    if not capec_patterns and not attack_techniques:
        raise HTTPException(
            status_code=404,
            detail=f"No MITRE mappings found for {cwe_id_normalized}"
        )
    
    # Get description from mapping
    from app.services.mitre_enrichment_service import CWE_TO_CAPEC
    mapping = CWE_TO_CAPEC.get(cwe_id_normalized, {})
    
    return CWELookupResult(
        cwe_id=cwe_id_normalized,
        description=mapping.get("description"),
        capec_patterns=[CAPECPattern(**p) for p in capec_patterns],
        attack_techniques=[AttackTechnique(**t) for t in attack_techniques],
    )


@router.get("/cwes")
async def list_supported_cwes(
    current_user: User = Depends(get_current_user)
):
    """
    List all CWEs that have MITRE mappings.
    """
    service = get_mitre_service()
    cwes = service.get_supported_cwes()
    
    # Add descriptions
    from app.services.mitre_enrichment_service import CWE_TO_CAPEC
    
    cwe_list = []
    for cwe_id in sorted(cwes):
        mapping = CWE_TO_CAPEC.get(cwe_id, {})
        cwe_list.append({
            "id": cwe_id,
            "description": mapping.get("description"),
            "capec_count": len(mapping.get("capec_ids", [])),
            "technique_count": len(mapping.get("attack_techniques", [])),
        })
    
    return {
        "cwes": cwe_list,
        "count": len(cwe_list)
    }


@router.get("/techniques/{technique_id}")
async def get_technique_details(
    technique_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get details for an ATT&CK technique.
    """
    from app.services.mitre_enrichment_service import ATTACK_TECHNIQUES
    
    # Normalize ID
    technique_id = technique_id.upper()
    if not technique_id.startswith("T"):
        technique_id = f"T{technique_id}"
    
    technique = ATTACK_TECHNIQUES.get(technique_id)
    
    if not technique:
        raise HTTPException(
            status_code=404,
            detail=f"Technique {technique_id} not found"
        )
    
    return {
        "id": technique_id,
        "name": technique.get("name"),
        "tactic": technique.get("tactic"),
        "description": technique.get("description"),
        "mitre_url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    }
