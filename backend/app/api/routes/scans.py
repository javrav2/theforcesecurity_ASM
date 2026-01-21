"""Scan routes for ASM scan management."""

import os
import json
import logging
from typing import List, Optional, Dict
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

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/scans", tags=["Scans"])

# SQS Configuration
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Initialize SQS client lazily
_sqs_client = None

def get_sqs_client():
    """Get or create SQS client."""
    global _sqs_client
    if _sqs_client is None and SQS_QUEUE_URL:
        try:
            import boto3
            _sqs_client = boto3.client('sqs', region_name=AWS_REGION)
            logger.info(f"SQS client initialized for queue: {SQS_QUEUE_URL}")
        except Exception as e:
            logger.error(f"Failed to initialize SQS client: {e}")
    return _sqs_client


def send_scan_to_sqs(scan: Scan) -> bool:
    """
    Send a scan job to SQS queue for processing.
    
    Returns True if message was sent successfully, False otherwise.
    """
    if not SQS_QUEUE_URL:
        logger.debug("SQS_QUEUE_URL not configured, skipping SQS notification")
        return False
    
    sqs = get_sqs_client()
    if not sqs:
        return False
    
    # Build job message
    job_type_map = {
        ScanType.VULNERABILITY: 'NUCLEI_SCAN',
        ScanType.PORT_SCAN: 'PORT_SCAN',
        ScanType.DISCOVERY: 'DISCOVERY',
        ScanType.FULL: 'DISCOVERY',
        ScanType.SUBDOMAIN_ENUM: 'SUBDOMAIN_ENUM',
        ScanType.DNS_RESOLUTION: 'DNS_RESOLUTION',
        ScanType.HTTP_PROBE: 'HTTP_PROBE',
        ScanType.DNS_ENUM: 'DNS_RESOLUTION',
        ScanType.LOGIN_PORTAL: 'LOGIN_PORTAL',
        ScanType.SCREENSHOT: 'SCREENSHOT',
        ScanType.TECHNOLOGY: 'TECHNOLOGY_SCAN',
    }
    
    job_type = job_type_map.get(scan.scan_type, 'NUCLEI_SCAN')
    config = scan.config or {}
    
    message_body = {
        'job_type': job_type,
        'scan_id': scan.id,
        'organization_id': scan.organization_id,
        'targets': scan.targets or [],
        'config': config,
        'scanner': config.get('scanner', 'naabu'),
        'ports': config.get('ports'),
        'severity': config.get('severity'),
    }
    
    try:
        response = sqs.send_message(
            QueueUrl=SQS_QUEUE_URL,
            MessageBody=json.dumps(message_body),
            MessageAttributes={
                'job_type': {
                    'StringValue': job_type,
                    'DataType': 'String'
                },
                'scan_id': {
                    'StringValue': str(scan.id),
                    'DataType': 'Number'
                }
            }
        )
        logger.info(f"Sent scan {scan.id} to SQS, MessageId: {response.get('MessageId')}")
        return True
    except Exception as e:
        logger.error(f"Failed to send scan {scan.id} to SQS: {e}")
        return False


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


@router.get("/queue/status")
def get_queue_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get scan queue status including pending, running, and capacity info.
    
    Useful for understanding if ad-hoc scans can run immediately.
    """
    import os
    max_concurrent = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))
    
    # Count scans by status
    pending_count = db.query(Scan).filter(Scan.status == ScanStatus.PENDING).count()
    running_count = db.query(Scan).filter(Scan.status == ScanStatus.RUNNING).count()
    
    # Get running scans details
    running_scans = db.query(Scan).filter(
        Scan.status == ScanStatus.RUNNING
    ).order_by(Scan.started_at.asc()).all()
    
    running_details = []
    for scan in running_scans:
        is_scheduled = (scan.config or {}).get('triggered_by_schedule') is not None
        running_details.append({
            "id": scan.id,
            "name": scan.name,
            "scan_type": scan.scan_type.value if scan.scan_type else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "current_step": scan.current_step,
            "is_scheduled": is_scheduled,
        })
    
    # Get next pending scans
    pending_scans = db.query(Scan).filter(
        Scan.status == ScanStatus.PENDING
    ).order_by(Scan.created_at.asc()).limit(5).all()
    
    pending_details = []
    for scan in pending_scans:
        is_scheduled = (scan.config or {}).get('triggered_by_schedule') is not None
        pending_details.append({
            "id": scan.id,
            "name": scan.name,
            "scan_type": scan.scan_type.value if scan.scan_type else None,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "is_scheduled": is_scheduled,
        })
    
    available_slots = max(0, max_concurrent - running_count)
    
    return {
        "max_concurrent": max_concurrent,
        "running": running_count,
        "pending": pending_count,
        "available_slots": available_slots,
        "can_start_immediately": available_slots > 0,
        "running_scans": running_details,
        "next_pending": pending_details,
    }


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
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(new_scan)
    
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
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(new_scan)
    
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


@router.post("/{scan_id}/rescan", response_model=ScanResponse)
def rescan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Create a new scan based on an existing scan's configuration.
    
    This clones the original scan's targets, type, and config, then queues it for execution.
    Useful for re-running completed or failed scans.
    """
    original_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not original_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Original scan not found"
        )
    
    if not check_org_access(current_user, original_scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Clone the scan configuration
    new_scan = Scan(
        name=f"{original_scan.name} (Rescan)",
        scan_type=original_scan.scan_type,
        organization_id=original_scan.organization_id,
        targets=original_scan.targets,
        config={
            **(original_scan.config or {}),
            "rescan_of": original_scan.id,
            "original_scan_name": original_scan.name,
        },
        status=ScanStatus.PENDING,
        started_by=current_user.username,
    )
    
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(new_scan)
    
    return new_scan


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


# =============================================================================
# Quick Action Scan Endpoints
# =============================================================================

@router.post("/quick/dns-resolution", response_model=ScanResponse)
def quick_dns_resolution_scan(
    organization_id: int = Query(..., description="Organization ID"),
    include_geo: bool = Query(True, description="Include geo-enrichment"),
    limit: int = Query(500, ge=1, le=2000, description="Max assets to process"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Quick action: Create a DNS resolution scan to resolve all domains to IPs.
    
    This scan will:
    1. Find all domain/subdomain assets without IP addresses
    2. Resolve them using dnsx
    3. Update assets with resolved IPs
    4. Optionally geo-enrich with lat/lon for the world map
    
    Use this to populate IP addresses and geolocation for the asset map.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Count unresolved assets
    from app.models.asset import AssetType
    unresolved_count = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        (Asset.ip_address.is_(None) | (Asset.ip_address == ''))
    ).count()
    
    if unresolved_count == 0:
        raise HTTPException(
            status_code=400,
            detail="No assets need DNS resolution. All domains already have IP addresses."
        )
    
    # Create scan
    scan = Scan(
        name=f"DNS Resolution - {min(unresolved_count, limit)} assets",
        scan_type=ScanType.DNS_RESOLUTION,
        organization_id=organization_id,
        targets=[],  # Will resolve all unresolved assets
        config={
            "include_geo": include_geo,
            "limit": limit,
        },
        status=ScanStatus.PENDING,
        started_by=current_user.username,
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(scan)
    
    return {
        "id": scan.id,
        "name": scan.name,
        "scan_type": scan.scan_type,
        "organization_id": scan.organization_id,
        "organization_name": scan.organization.name if scan.organization else None,
        "targets": scan.targets or [],
        "config": scan.config or {},
        "status": scan.status,
        "progress": scan.progress,
        "assets_discovered": 0,
        "technologies_found": 0,
        "vulnerabilities_found": 0,
        "targets_count": min(unresolved_count, limit),
        "findings_count": 0,
        "started_by": scan.started_by,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message,
        "results": {"pending_assets": min(unresolved_count, limit)},
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
    }


@router.post("/quick/http-probe", response_model=ScanResponse)
def quick_http_probe_scan(
    organization_id: int = Query(..., description="Organization ID"),
    limit: int = Query(500, ge=1, le=2000, description="Max assets to probe"),
    timeout: int = Query(30, ge=5, le=120, description="Timeout per target"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Quick action: Create an HTTP probe scan to find live web assets.
    
    This scan will:
    1. Probe all domain/subdomain assets for HTTP/HTTPS
    2. Update assets with live status, HTTP status code, and page title
    3. Store the final URL (after redirects)
    4. Update IP addresses if discovered
    
    Use this to identify which assets have live web services.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Count assets to probe
    from app.models.asset import AssetType
    asset_count = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN])
    ).count()
    
    if asset_count == 0:
        raise HTTPException(
            status_code=400,
            detail="No domain/subdomain assets found to probe."
        )
    
    # Create scan
    scan = Scan(
        name=f"HTTP Probe - {min(asset_count, limit)} assets",
        scan_type=ScanType.HTTP_PROBE,
        organization_id=organization_id,
        targets=[],  # Will probe all assets
        config={
            "limit": limit,
            "timeout": timeout,
        },
        status=ScanStatus.PENDING,
        started_by=current_user.username,
    )
    
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Send scan job to SQS for processing
    send_scan_to_sqs(scan)
    
    return {
        "id": scan.id,
        "name": scan.name,
        "scan_type": scan.scan_type,
        "organization_id": scan.organization_id,
        "organization_name": scan.organization.name if scan.organization else None,
        "targets": scan.targets or [],
        "config": scan.config or {},
        "status": scan.status,
        "progress": scan.progress,
        "assets_discovered": 0,
        "technologies_found": 0,
        "vulnerabilities_found": 0,
        "targets_count": min(asset_count, limit),
        "findings_count": 0,
        "started_by": scan.started_by,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "error_message": scan.error_message,
        "results": {"pending_assets": min(asset_count, limit)},
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
    }


# =============================================================================
# Unified Export Endpoints
# =============================================================================

@router.get("/{scan_id}/export/unified", response_model=dict)
def export_scan_unified(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export scan results in unified ASM format.
    
    This standardized format is compatible with H-ISAC and ASM Recon outputs,
    making it easy to share, integrate, or import into other security tools.
    """
    from app.schemas.unified_results import (
        UnifiedFinding, UnifiedScanResult, ASMExportFormat,
        ResultType, Severity
    )
    from app.models.vulnerability import Vulnerability
    from app.models.port_service import PortService
    
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
    
    # Build unified scan result
    unified_result = UnifiedScanResult(
        scan_id=scan.id,
        scan_type=scan.scan_type.value if scan.scan_type else "unknown",
        scanner=scan.config.get("scanner", "unknown") if scan.config else "unknown",
        success=scan.status == ScanStatus.COMPLETED,
        status=scan.status.value if scan.status else "unknown",
        targets_original=scan.targets or [],
        targets_scanned=count_cidr_targets(scan.targets) if scan.targets else 0,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=(scan.completed_at - scan.started_at).total_seconds() if scan.started_at and scan.completed_at else 0,
        organization_id=scan.organization_id,
        started_by=scan.started_by,
        errors=[scan.error_message] if scan.error_message else [],
    )
    
    # Add vulnerability findings
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    for vuln in vulns:
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        finding = UnifiedFinding(
            type=ResultType.VULNERABILITY,
            source=vuln.detected_by or "nuclei",
            target=vuln.asset.value if vuln.asset else "",
            host=vuln.asset.value if vuln.asset else "",
            ip=vuln.ip_address,
            url=vuln.url,
            title=vuln.title,
            description=vuln.description,
            severity=severity_map.get(vuln.severity.value if vuln.severity else "info", Severity.INFO),
            template_id=vuln.template_id,
            cve_id=vuln.cve_id,
            cvss_score=vuln.cvss_score,
            tags=vuln.tags or [],
            references=vuln.references or [],
            timestamp=vuln.first_detected_at or vuln.created_at,
            first_seen=vuln.first_detected_at,
            last_seen=vuln.last_detected_at,
            organization_id=scan.organization_id,
            asset_id=vuln.asset_id,
            scan_id=scan.id,
        )
        unified_result.add_finding(finding)
    
    # Add port findings (for port scans)
    if scan.scan_type == ScanType.PORT_SCAN:
        # Get assets scanned in this job
        for target in scan.targets or []:
            asset = db.query(Asset).filter(
                Asset.organization_id == scan.organization_id,
                Asset.value == target
            ).first()
            if asset:
                ports = db.query(PortService).filter(PortService.asset_id == asset.id).all()
                for port in ports:
                    finding = UnifiedFinding(
                        type=ResultType.PORT,
                        source=port.discovered_by or "naabu",
                        target=target,
                        host=asset.value,
                        ip=asset.ip_address,
                        port=port.port,
                        protocol=port.protocol.value if port.protocol else "tcp",
                        title=f"Port {port.port}/{port.protocol.value if port.protocol else 'tcp'} Open",
                        service_name=port.service_name,
                        service_product=port.service_product,
                        service_version=port.service_version,
                        banner=port.banner,
                        state=port.state.value if port.state else "open",
                        is_risky=port.is_risky or False,
                        risk_reason=port.risk_reason,
                        severity=Severity.MEDIUM if port.is_risky else Severity.INFO,
                        timestamp=port.first_seen or port.created_at,
                        first_seen=port.first_seen,
                        last_seen=port.last_seen,
                        organization_id=scan.organization_id,
                        asset_id=asset.id,
                        scan_id=scan.id,
                    )
                    unified_result.add_finding(finding)
    
    # Build export format
    org_name = scan.organization.name if scan.organization else None
    export = ASMExportFormat.from_scan_result(unified_result, org_name)
    
    return export.model_dump(mode="json")


@router.get("/export/all", response_model=dict)
def export_all_findings(
    organization_id: Optional[int] = None,
    finding_type: Optional[str] = Query(None, description="Filter by type: vulnerability, port, subdomain, etc."),
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low, info"),
    source: Optional[str] = Query(None, description="Filter by source tool: nuclei, naabu, subfinder, etc."),
    since: Optional[datetime] = Query(None, description="Filter findings after this date"),
    limit: int = Query(1000, ge=1, le=10000, description="Maximum findings to export"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export all findings in unified ASM format across all scans.
    
    This endpoint provides a consolidated view of all findings for:
    - Threat intel sharing (H-ISAC compatible)
    - SIEM integration
    - Security reporting
    - Cross-tool analysis
    """
    from app.schemas.unified_results import (
        UnifiedFinding, ASMExportFormat,
        ResultType, Severity
    )
    from app.models.vulnerability import Vulnerability
    from app.models.port_service import PortService
    from app.models.organization import Organization
    
    # Determine organization scope
    if current_user.is_superuser:
        org_id = organization_id
    else:
        org_id = current_user.organization_id
    
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID required"
        )
    
    org = db.query(Organization).filter(Organization.id == org_id).first()
    
    findings = []
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    
    # Get vulnerabilities
    if not finding_type or finding_type == "vulnerability":
        vuln_query = db.query(Vulnerability).filter(Vulnerability.organization_id == org_id)
        if severity:
            vuln_query = vuln_query.filter(Vulnerability.severity == severity)
        if source:
            vuln_query = vuln_query.filter(Vulnerability.detected_by == source)
        if since:
            vuln_query = vuln_query.filter(Vulnerability.created_at >= since)
        
        for vuln in vuln_query.limit(limit).all():
            finding = UnifiedFinding(
                type=ResultType.VULNERABILITY,
                source=vuln.detected_by or "nuclei",
                target=vuln.asset.value if vuln.asset else "",
                host=vuln.asset.value if vuln.asset else "",
                ip=vuln.ip_address,
                url=vuln.url,
                title=vuln.title,
                description=vuln.description,
                severity=severity_map.get(vuln.severity.value if vuln.severity else "info", Severity.INFO),
                template_id=vuln.template_id,
                cve_id=vuln.cve_id,
                cvss_score=vuln.cvss_score,
                tags=vuln.tags or [],
                references=vuln.references or [],
                timestamp=vuln.first_detected_at or vuln.created_at,
                first_seen=vuln.first_detected_at,
                last_seen=vuln.last_detected_at,
                organization_id=org_id,
                asset_id=vuln.asset_id,
                scan_id=vuln.scan_id,
            )
            findings.append(finding)
    
    # Get port findings
    if not finding_type or finding_type == "port":
        # Get assets for this org
        asset_ids = [a.id for a in db.query(Asset).filter(Asset.organization_id == org_id).all()]
        
        port_query = db.query(PortService).filter(PortService.asset_id.in_(asset_ids))
        if source:
            port_query = port_query.filter(PortService.discovered_by == source)
        if since:
            port_query = port_query.filter(PortService.created_at >= since)
        
        remaining = limit - len(findings)
        for port in port_query.limit(remaining).all():
            asset = port.asset
            finding = UnifiedFinding(
                type=ResultType.PORT,
                source=port.discovered_by or "naabu",
                target=asset.value if asset else "",
                host=asset.value if asset else "",
                ip=asset.ip_address if asset else None,
                port=port.port,
                protocol=port.protocol.value if port.protocol else "tcp",
                title=f"Port {port.port}/{port.protocol.value if port.protocol else 'tcp'} Open",
                service_name=port.service_name,
                service_product=port.service_product,
                service_version=port.service_version,
                banner=port.banner,
                state=port.state.value if port.state else "open",
                is_risky=port.is_risky or False,
                risk_reason=port.risk_reason,
                severity=Severity.MEDIUM if port.is_risky else Severity.INFO,
                timestamp=port.first_seen or port.created_at,
                first_seen=port.first_seen,
                last_seen=port.last_seen,
                organization_id=org_id,
                asset_id=port.asset_id,
            )
            
            # Apply severity filter
            if severity and finding.severity.value != severity:
                continue
            
            findings.append(finding)
    
    # Build export format
    severity_breakdown = {s.value: 0 for s in Severity}
    type_breakdown = {}
    source_breakdown = {}
    
    for f in findings:
        severity_breakdown[f.severity.value] = severity_breakdown.get(f.severity.value, 0) + 1
        type_breakdown[f.type.value] = type_breakdown.get(f.type.value, 0) + 1
        source_breakdown[f.source] = source_breakdown.get(f.source, 0) + 1
    
    export = ASMExportFormat(
        organization=org.name if org else None,
        organization_id=org_id,
        findings=findings,
        total_count=len(findings),
        severity_breakdown=severity_breakdown,
        type_breakdown=type_breakdown,
        source_breakdown=source_breakdown,
    )
    
    return export.model_dump(mode="json")


# =============================================================================
# H-ISAC Format Export Endpoints
# =============================================================================

@router.get("/{scan_id}/export/hisac", response_model=List[Dict])
def export_scan_hisac(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export scan results in H-ISAC format.
    
    Returns JSON Lines compatible output matching the H-ISAC reconnaissance
    scripts format:
    
    {"ip_or_fqdn": "...", "port": 443, "protocol": "tcp", "data": [...]}
    
    This format is compatible with:
    - get_masscan
    - get_massdns
    - get_whoxy
    - Other H-ISAC recon scripts
    """
    from app.schemas.hisac_format import HISACResult
    from app.models.vulnerability import Vulnerability
    from app.models.port_service import PortService
    
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
    
    results = []
    
    # Export vulnerability findings
    vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan.id).all()
    for vuln in vulns:
        result = HISACResult(
            ip_or_fqdn=vuln.asset.value if vuln.asset else vuln.ip_address or "",
            port=0,
            protocol="vuln",
            data=[{
                "template_id": vuln.template_id,
                "severity": vuln.severity.value if vuln.severity else "info",
                "title": vuln.title,
                "cve_id": vuln.cve_id,
                "cvss_score": vuln.cvss_score,
                "matched_at": vuln.url,
            }],
            source="nuclei",
        )
        results.append(result.model_dump(mode="json", exclude_none=True))
    
    # Export port findings (for port scans)
    if scan.scan_type == ScanType.PORT_SCAN:
        for target in scan.targets or []:
            asset = db.query(Asset).filter(
                Asset.organization_id == scan.organization_id,
                Asset.value == target
            ).first()
            if asset:
                ports = db.query(PortService).filter(PortService.asset_id == asset.id).all()
                for port in ports:
                    result = HISACResult(
                        ip_or_fqdn=asset.ip_address or asset.value,
                        port=port.port,
                        protocol=port.protocol.value if port.protocol else "tcp",
                        data=[{
                            "status": port.state.value if port.state else "open",
                            "service": port.service_name,
                            "product": port.service_product,
                            "version": port.service_version,
                            "banner": port.banner,
                        }],
                        source=port.discovered_by or "naabu",
                    )
                    # Clean up None values in data
                    result.data = [{k: v for k, v in d.items() if v is not None} for d in result.data]
                    results.append(result.model_dump(mode="json", exclude_none=True))
    
    return results


@router.get("/export/hisac", response_model=List[Dict])
def export_all_hisac(
    organization_id: Optional[int] = None,
    protocol: Optional[str] = Query(None, description="Filter by protocol: tcp, dns, whois, vuln, etc."),
    since: Optional[datetime] = Query(None, description="Filter findings after this date"),
    limit: int = Query(1000, ge=1, le=10000, description="Maximum results"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Export all findings in H-ISAC format.
    
    Returns JSON Lines compatible output that can be piped to other H-ISAC tools
    or used for integration with external systems.
    """
    from app.schemas.hisac_format import HISACResult
    from app.models.vulnerability import Vulnerability
    from app.models.port_service import PortService
    
    # Determine organization scope
    if current_user.is_superuser:
        org_id = organization_id
    else:
        org_id = current_user.organization_id
    
    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Organization ID required"
        )
    
    results = []
    
    # Get vulnerabilities (protocol = "vuln")
    if not protocol or protocol == "vuln":
        vuln_query = db.query(Vulnerability).filter(Vulnerability.organization_id == org_id)
        if since:
            vuln_query = vuln_query.filter(Vulnerability.created_at >= since)
        
        for vuln in vuln_query.limit(limit).all():
            result = HISACResult(
                ip_or_fqdn=vuln.asset.value if vuln.asset else vuln.ip_address or "",
                port=0,
                protocol="vuln",
                data=[{
                    "template_id": vuln.template_id,
                    "severity": vuln.severity.value if vuln.severity else "info",
                    "title": vuln.title,
                    "cve_id": vuln.cve_id,
                    "cvss_score": vuln.cvss_score,
                    "matched_at": vuln.url,
                }],
                source="nuclei",
            )
            results.append(result.model_dump(mode="json", exclude_none=True))
    
    # Get ports (protocol = "tcp" or "udp")
    if not protocol or protocol in ["tcp", "udp"]:
        asset_ids = [a.id for a in db.query(Asset).filter(Asset.organization_id == org_id).all()]
        
        port_query = db.query(PortService).filter(PortService.asset_id.in_(asset_ids))
        if protocol:
            from app.models.port_service import Protocol as PortProtocol
            port_query = port_query.filter(PortService.protocol == PortProtocol(protocol))
        if since:
            port_query = port_query.filter(PortService.created_at >= since)
        
        remaining = limit - len(results)
        for port in port_query.limit(remaining).all():
            asset = port.asset
            result = HISACResult(
                ip_or_fqdn=asset.ip_address or asset.value if asset else "",
                port=port.port,
                protocol=port.protocol.value if port.protocol else "tcp",
                data=[{
                    "status": port.state.value if port.state else "open",
                    "service": port.service_name,
                    "product": port.service_product,
                    "version": port.service_version,
                    "banner": port.banner,
                }],
                source=port.discovered_by or "naabu",
            )
            result.data = [{k: v for k, v in d.items() if v is not None} for d in result.data]
            results.append(result.model_dump(mode="json", exclude_none=True))
    
    return results


@router.post("/import/hisac", response_model=Dict)
def import_hisac_results(
    organization_id: int,
    results: List[Dict],
    source: Optional[str] = Query(None, description="Source tool name"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Import H-ISAC format results into the ASM database.
    
    Accepts JSON array of H-ISAC format objects:
    [{"ip_or_fqdn": "...", "port": 443, "protocol": "tcp", "data": [...]}]
    
    This allows importing results from:
    - H-ISAC reconnaissance scripts
    - Other ASM tools using the same format
    - Manual data entry in H-ISAC format
    """
    from app.schemas.hisac_format import HISACResult, hisac_to_asm
    from app.schemas.data_sources import FindingCategory
    
    if not check_org_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    imported = 0
    errors = []
    
    for i, raw_result in enumerate(results):
        try:
            # Parse H-ISAC result
            hisac = HISACResult(**raw_result)
            hisac.organization_id = organization_id
            
            # Convert to ASM model
            asm_finding = hisac_to_asm(hisac, source_hint=source)
            
            # Import based on category
            if asm_finding.category == FindingCategory.PORT:
                # Create or update port service
                asset = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == asm_finding.hostname or asm_finding.ip_address
                ).first()
                
                if not asset:
                    # Create asset
                    asset = Asset(
                        organization_id=organization_id,
                        asset_type="ip" if asm_finding.ip_address else "domain",
                        value=asm_finding.ip_address or asm_finding.hostname,
                        ip_address=asm_finding.ip_address,
                        is_active=True,
                    )
                    db.add(asset)
                    db.flush()
                
                # Create port service
                from app.models.port_service import PortService, Protocol as PortProtocol, PortState as PSState
                existing_port = db.query(PortService).filter(
                    PortService.asset_id == asset.id,
                    PortService.port == asm_finding.port,
                    PortService.protocol == asm_finding.protocol
                ).first()
                
                if not existing_port:
                    port_service = PortService(
                        asset_id=asset.id,
                        port=asm_finding.port,
                        protocol=asm_finding.protocol,
                        service_name=asm_finding.service_name,
                        service_product=asm_finding.service_product,
                        service_version=asm_finding.service_version,
                        banner=asm_finding.banner,
                        state=asm_finding.port_state or PSState.OPEN,
                        discovered_by=source or "hisac_import",
                    )
                    db.add(port_service)
                    imported += 1
            
            # Add more category handlers as needed
            
        except Exception as e:
            errors.append({"index": i, "error": str(e)})
    
    db.commit()
    
    return {
        "success": True,
        "imported": imported,
        "total": len(results),
        "errors": errors,
    }











