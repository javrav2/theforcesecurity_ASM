"""Scan routes for ASM scan management."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.asset import Asset
from app.models.label import Label
from app.models.user import User
from app.schemas.scan import ScanCreate, ScanUpdate, ScanResponse, ScanByLabelRequest
from app.api.deps import get_current_active_user, require_analyst
from app.services.nuclei_service import count_cidr_targets

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
    
    # Enrich with organization names and computed fields
    result = []
    for scan in scans:
        scan_dict = {
            "id": scan.id,
            "name": scan.name,
            "scan_type": scan.scan_type,
            "organization_id": scan.organization_id,
            "organization_name": scan.organization.name if scan.organization else None,
            "targets": scan.targets or [],
            "config": scan.config or {},
            "status": scan.status,
            "progress": scan.progress,
            "assets_discovered": scan.assets_discovered,
            "technologies_found": scan.technologies_found,
            "vulnerabilities_found": scan.vulnerabilities_found,
            "targets_count": count_cidr_targets(scan.targets) if scan.targets else 0,
            "findings_count": scan.vulnerabilities_found,
            "started_by": scan.started_by,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
            "error_message": scan.error_message,
            "results": scan.results or {},
            "created_at": scan.created_at,
            "updated_at": scan.updated_at,
        }
        result.append(scan_dict)
    
    return result


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
    
    # If label_ids are provided, get assets with those labels
    scan_dict = scan_data.model_dump()
    label_ids = scan_dict.pop('label_ids', [])
    match_all_labels = scan_dict.pop('match_all_labels', False)
    
    if label_ids:
        # Get assets with the specified labels
        query = db.query(Asset).filter(Asset.organization_id == scan_data.organization_id)
        
        if match_all_labels:
            # Assets must have ALL labels
            for label_id in label_ids:
                query = query.filter(Asset.labels.any(Label.id == label_id))
        else:
            # Assets must have ANY of the labels
            query = query.filter(Asset.labels.any(Label.id.in_(label_ids)))
        
        assets = query.distinct().all()
        
        # Add asset values to targets
        asset_values = [a.value for a in assets]
        scan_dict['targets'] = list(set(scan_dict.get('targets', []) + asset_values))
        
        # Store label info in config for reference
        scan_dict['config'] = scan_dict.get('config', {})
        scan_dict['config']['source_labels'] = label_ids
        scan_dict['config']['match_all_labels'] = match_all_labels
        scan_dict['config']['assets_from_labels'] = len(assets)
    
    new_scan = Scan(
        **scan_dict,
        started_by=current_user.username
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    return new_scan


@router.post("/by-label", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan_by_label(
    request: ScanByLabelRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a scan targeting assets with specific labels."""
    # Check organization access
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Verify labels exist and belong to the organization
    labels = db.query(Label).filter(
        Label.id.in_(request.label_ids),
        Label.organization_id == request.organization_id
    ).all()
    
    if len(labels) != len(request.label_ids):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="One or more labels not found or do not belong to this organization"
        )
    
    # Get assets with the specified labels
    query = db.query(Asset).filter(
        Asset.organization_id == request.organization_id,
        Asset.in_scope == True
    )
    
    if request.match_all_labels:
        for label_id in request.label_ids:
            query = query.filter(Asset.labels.any(Label.id == label_id))
    else:
        query = query.filter(Asset.labels.any(Label.id.in_(request.label_ids)))
    
    assets = query.distinct().all()
    
    if not assets:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No in-scope assets found with the specified labels"
        )
    
    # Create targets from asset values
    targets = [a.value for a in assets]
    
    # Create the scan
    new_scan = Scan(
        name=request.name,
        scan_type=request.scan_type,
        organization_id=request.organization_id,
        targets=targets,
        config={
            **request.config,
            "source_labels": request.label_ids,
            "label_names": [l.name for l in labels],
            "match_all_labels": request.match_all_labels,
            "assets_count": len(assets),
        },
        started_by=current_user.username
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    return new_scan


@router.get("/labels/preview")
def preview_scan_by_labels(
    label_ids: List[int] = Query(...),
    organization_id: int = Query(...),
    match_all: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Preview which assets would be included in a label-based scan."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    
    query = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.in_scope == True
    )
    
    if match_all:
        for label_id in label_ids:
            query = query.filter(Asset.labels.any(Label.id == label_id))
    else:
        query = query.filter(Asset.labels.any(Label.id.in_(label_ids)))
    
    assets = query.distinct().all()
    
    # Get label names for display
    labels = db.query(Label).filter(Label.id.in_(label_ids)).all()
    
    return {
        "label_ids": label_ids,
        "label_names": [l.name for l in labels],
        "match_all": match_all,
        "asset_count": len(assets),
        "assets": [
            {
                "id": a.id,
                "name": a.name,
                "value": a.value,
                "asset_type": a.asset_type.value,
                "labels": [{"id": l.id, "name": l.name, "color": l.color} for l in a.labels],
            }
            for a in assets[:100]  # Limit preview to 100 assets
        ],
        "truncated": len(assets) > 100,
    }


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















