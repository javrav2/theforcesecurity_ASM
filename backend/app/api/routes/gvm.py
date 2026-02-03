"""
GVM/OpenVAS Scanner API Routes

Endpoints for running deep vulnerability scans using GVM.
"""

import logging
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User
from app.services.gvm_scanner_service import get_gvm_service
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gvm", tags=["GVM Scanner"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class ScanRequest(BaseModel):
    """Request to run a GVM scan."""
    targets: List[str]
    scan_name: Optional[str] = None
    wait_for_completion: bool = False
    timeout: int = 7200


class ScanStatusResponse(BaseModel):
    """Scan status response."""
    task_id: str
    status: str
    progress: int


class ScanResult(BaseModel):
    """Scan result response."""
    status: str
    task_id: Optional[str] = None
    report_id: Optional[str] = None
    targets_scanned: Optional[int] = None
    vulnerabilities_found: Optional[int] = None
    vulnerabilities_stored: Optional[int] = None
    severity_breakdown: Optional[dict] = None
    error: Optional[str] = None


class ConfigItem(BaseModel):
    """Configuration item."""
    id: str
    name: str


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/status")
async def get_gvm_status():
    """
    Check if GVM is available and configured.
    """
    service = get_gvm_service()
    
    return {
        "enabled": settings.GVM_ENABLED,
        "available": service.is_available(),
        "socket_path": settings.GVM_SOCKET_PATH,
        "default_config": settings.GVM_SCAN_CONFIG,
    }


@router.get("/configs", response_model=List[ConfigItem])
async def list_scan_configs(
    current_user: User = Depends(get_current_user)
):
    """
    List available scan configurations.
    
    Common configurations:
    - Discovery: Quick host enumeration
    - Full and fast: Comprehensive scan (recommended)
    - Full and fast ultimate: Most thorough scan
    """
    service = get_gvm_service()
    
    if not service.is_available():
        raise HTTPException(
            status_code=503,
            detail="GVM is not available. Enable GVM_ENABLED and ensure GVM is running."
        )
    
    configs = service.get_scan_configs()
    return [ConfigItem(**c) for c in configs]


@router.get("/port-lists", response_model=List[ConfigItem])
async def list_port_lists(
    current_user: User = Depends(get_current_user)
):
    """
    List available port lists for scanning.
    """
    service = get_gvm_service()
    
    if not service.is_available():
        raise HTTPException(
            status_code=503,
            detail="GVM is not available"
        )
    
    port_lists = service.get_port_lists()
    return [ConfigItem(**p) for p in port_lists]


@router.post("/scan", response_model=ScanResult)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """
    Start a GVM vulnerability scan.
    
    Args:
        targets: List of IP addresses or hostnames to scan
        scan_name: Optional name for the scan
        wait_for_completion: If true, wait for scan to complete
        timeout: Maximum wait time in seconds (if waiting)
    
    GVM scans are comprehensive but can take 30 minutes to 2+ hours
    depending on the number of targets and scan configuration.
    """
    service = get_gvm_service()
    
    if not service.is_available():
        raise HTTPException(
            status_code=503,
            detail="GVM is not available. Enable GVM_ENABLED and ensure GVM is running."
        )
    
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    if not request.targets:
        raise HTTPException(
            status_code=400,
            detail="At least one target is required"
        )
    
    if request.wait_for_completion:
        # Run synchronously
        result = service.scan(
            targets=request.targets,
            organization_id=org_id,
            scan_name=request.scan_name,
            wait=True,
            timeout=request.timeout
        )
    else:
        # Start scan in background
        result = service.scan(
            targets=request.targets,
            organization_id=org_id,
            scan_name=request.scan_name,
            wait=False
        )
    
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])
    
    return ScanResult(**result)


@router.get("/task/{task_id}/status", response_model=ScanStatusResponse)
async def get_task_status(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get the status of a running scan task.
    """
    service = get_gvm_service()
    
    if not service.is_available():
        raise HTTPException(
            status_code=503,
            detail="GVM is not available"
        )
    
    status_info = service.get_task_status(task_id)
    
    return ScanStatusResponse(
        task_id=task_id,
        status=status_info.get("status", "unknown"),
        progress=status_info.get("progress", 0)
    )


@router.get("/report/{report_id}")
async def get_scan_report(
    report_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get the detailed findings from a scan report.
    """
    service = get_gvm_service()
    
    if not service.is_available():
        raise HTTPException(
            status_code=503,
            detail="GVM is not available"
        )
    
    findings = service.get_report(report_id)
    
    # Summary by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "log": 0}
    for f in findings:
        sev = f.get("severity", "log")
        if sev in severity_counts:
            severity_counts[sev] += 1
    
    return {
        "report_id": report_id,
        "total_findings": len(findings),
        "severity_breakdown": severity_counts,
        "findings": findings[:100],  # Limit to first 100 for response size
        "truncated": len(findings) > 100,
    }


@router.delete("/task/{task_id}")
async def delete_task(
    task_id: str,
    target_id: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """
    Delete a scan task and optionally its target.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403,
            detail="Only admins can delete tasks"
        )
    
    service = get_gvm_service()
    
    if not service.is_available():
        raise HTTPException(
            status_code=503,
            detail="GVM is not available"
        )
    
    if target_id:
        service.cleanup(task_id, target_id)
    
    return {"status": "deleted", "task_id": task_id}
