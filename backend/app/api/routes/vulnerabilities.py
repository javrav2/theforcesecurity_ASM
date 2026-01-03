"""Vulnerability routes."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.vulnerability import Vulnerability, Severity, VulnerabilityStatus
from app.models.asset import Asset
from app.models.user import User
from app.schemas.vulnerability import VulnerabilityCreate, VulnerabilityUpdate, VulnerabilityResponse
from app.api.deps import get_current_active_user, require_analyst

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


def check_org_access(db: Session, user: User, asset_id: int) -> bool:
    """Check if user has access to asset's organization."""
    if user.is_superuser:
        return True
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return False
    return user.organization_id == asset.organization_id


def build_vuln_response(vuln: Vulnerability) -> dict:
    """Build vulnerability response with computed fields."""
    response = {
        **vuln.__dict__,
        "name": vuln.title,  # Alias for frontend compatibility
        "host": vuln.asset.value if vuln.asset else None,
        "matched_at": vuln.evidence[:200] if vuln.evidence else None,
    }
    # Remove SQLAlchemy internal state
    response.pop("_sa_instance_state", None)
    return response


@router.get("/", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    severity: Optional[Severity] = None,
    status: Optional[VulnerabilityStatus] = None,
    asset_id: Optional[int] = None,
    cve_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List vulnerabilities with filtering options."""
    query = db.query(Vulnerability).join(Asset)
    
    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return []
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Apply filters
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if status:
        query = query.filter(Vulnerability.status == status)
    if asset_id:
        query = query.filter(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.filter(Vulnerability.cve_id == cve_id)
    
    vulns = query.order_by(Vulnerability.severity.desc(), Vulnerability.created_at.desc()).offset(skip).limit(limit).all()
    
    # Build response with computed fields
    return [build_vuln_response(v) for v in vulns]


@router.post("/", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED)
def create_vulnerability(
    vuln_data: VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new vulnerability."""
    # Check asset exists and user has access
    asset = db.query(Asset).filter(Asset.id == vuln_data.asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not current_user.is_superuser and current_user.organization_id != asset.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    new_vuln = Vulnerability(**vuln_data.model_dump())
    db.add(new_vuln)
    db.commit()
    db.refresh(new_vuln)
    
    return new_vuln


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vulnerability by ID."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return vuln


@router.put("/{vuln_id}", response_model=VulnerabilityResponse)
def update_vulnerability(
    vuln_id: int,
    vuln_data: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Update fields
    update_data = vuln_data.model_dump(exclude_unset=True)
    
    # Handle status change to resolved
    if update_data.get("status") == VulnerabilityStatus.RESOLVED and vuln.status != VulnerabilityStatus.RESOLVED:
        vuln.resolved_at = datetime.utcnow()
    
    for field, value in update_data.items():
        setattr(vuln, field, value)
    
    db.commit()
    db.refresh(vuln)
    
    return vuln


@router.delete("/{vuln_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    db.delete(vuln)
    db.commit()
    
    return None


@router.get("/stats/summary")
def get_vulnerabilities_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vulnerability statistics summary."""
    query = db.query(Vulnerability).join(Asset)
    
    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return {"total": 0, "by_severity": {}, "by_status": {}}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    vulns = query.all()
    
    # Calculate stats
    by_severity = {}
    by_status = {}
    
    for vuln in vulns:
        sev_key = vuln.severity.value
        status_key = vuln.status.value
        
        by_severity[sev_key] = by_severity.get(sev_key, 0) + 1
        by_status[status_key] = by_status.get(status_key, 0) + 1
    
    return {
        "total": len(vulns),
        "by_severity": by_severity,
        "by_status": by_status
    }

















