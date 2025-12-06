"""Scan routes for ASM scan management."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanUpdate, ScanResponse
from app.api.deps import get_current_active_user, require_analyst

router = APIRouter(prefix="/scans", tags=["Scans"])


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.is_superuser:
        return True
    return user.organization_id == org_id


@router.get("/", response_model=List[ScanResponse])
def list_scans(
    organization_id: Optional[int] = None,
    scan_type: Optional[ScanType] = None,
    status: Optional[ScanStatus] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List scans with filtering options."""
    query = db.query(Scan)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Scan.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return []
        query = query.filter(Scan.organization_id == current_user.organization_id)
    
    # Apply filters
    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)
    if status:
        query = query.filter(Scan.status == status)
    
    scans = query.order_by(Scan.created_at.desc()).offset(skip).limit(limit).all()
    return scans


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    scan_data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new scan."""
    # Check organization access
    if not check_org_access(current_user, scan_data.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    new_scan = Scan(
        **scan_data.model_dump(),
        started_by=current_user.username
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    return new_scan


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get scan by ID."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return scan


@router.put("/{scan_id}", response_model=ScanResponse)
def update_scan(
    scan_id: int,
    scan_data: ScanUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Update fields
    update_data = scan_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(scan, field, value)
    
    db.commit()
    db.refresh(scan)
    
    return scan


@router.post("/{scan_id}/start", response_model=ScanResponse)
def start_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Start a pending scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    if scan.status != ScanStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot start scan with status {scan.status.value}"
        )
    
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.utcnow()
    scan.started_by = current_user.username
    
    db.commit()
    db.refresh(scan)
    
    # Note: In production, this would trigger an async scan job
    return scan


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Cancel a running or pending scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan with status {scan.status.value}"
        )
    
    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.utcnow()
    
    db.commit()
    db.refresh(scan)
    
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a running scan"
        )
    
    db.delete(scan)
    db.commit()
    
    return None




