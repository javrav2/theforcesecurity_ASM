"""Organization routes."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.database import get_db
from app.models.organization import Organization
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, Severity
from app.models.user import User
from app.schemas.organization import OrganizationCreate, OrganizationUpdate, OrganizationResponse
from app.api.deps import get_current_active_user, require_admin

router = APIRouter(prefix="/organizations", tags=["Organizations"])


def build_org_response(db: Session, org: Organization) -> dict:
    """Build organization response with computed counts."""
    # Get asset count
    asset_count = db.query(func.count(Asset.id)).filter(
        Asset.organization_id == org.id
    ).scalar() or 0
    
    # Get vulnerability counts by severity
    vuln_counts = db.query(
        Vulnerability.severity,
        func.count(Vulnerability.id)
    ).join(Asset).filter(
        Asset.organization_id == org.id
    ).group_by(Vulnerability.severity).all()
    
    counts = {sev: cnt for sev, cnt in vuln_counts}
    
    return {
        **org.__dict__,
        "asset_count": asset_count,
        "vulnerability_count": sum(counts.values()),
        "critical_count": counts.get(Severity.CRITICAL, 0),
        "high_count": counts.get(Severity.HIGH, 0),
        "medium_count": counts.get(Severity.MEDIUM, 0),
        "low_count": counts.get(Severity.LOW, 0),
    }


@router.get("/", response_model=List[OrganizationResponse])
def list_organizations(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all organizations (admin sees all, others see their own)."""
    query = db.query(Organization).filter(Organization.is_active == True)
    
    if not current_user.is_superuser:
        if current_user.organization_id:
            query = query.filter(Organization.id == current_user.organization_id)
        else:
            return []
    
    organizations = query.offset(skip).limit(limit).all()
    return [build_org_response(db, org) for org in organizations]


@router.post("/", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization(
    org_data: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create a new organization (admin only)."""
    # Check if organization already exists
    existing = db.query(Organization).filter(Organization.name == org_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization with this name already exists"
        )
    
    new_org = Organization(**org_data.model_dump())
    db.add(new_org)
    db.commit()
    db.refresh(new_org)
    
    return new_org


@router.get("/{org_id}", response_model=OrganizationResponse)
def get_organization(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get organization by ID."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Check access
    if not current_user.is_superuser and current_user.organization_id != org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return build_org_response(db, org)


@router.put("/{org_id}", response_model=OrganizationResponse)
def update_organization(
    org_id: int,
    org_data: OrganizationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Update organization (admin only)."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Update fields
    update_data = org_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(org, field, value)
    
    db.commit()
    db.refresh(org)
    
    return org


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_organization(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete organization (admin only)."""
    org = db.query(Organization).filter(Organization.id == org_id).first()
    
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    db.delete(org)
    db.commit()
    
    return None















