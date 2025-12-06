"""
API routes for Nuclei vulnerability scanning.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_active_user, require_analyst
from app.models.user import User

router = APIRouter(prefix="/nuclei", tags=["nuclei"])


class NucleiScanRequest(BaseModel):
    """Request to run a Nuclei scan."""
    organization_id: int = Field(..., description="Organization ID")
    targets: List[str] = Field(..., description="List of targets to scan")
    severity: Optional[List[str]] = Field(None, description="Severity levels to scan for")
    tags: Optional[List[str]] = Field(None, description="Template tags to use")
    templates: Optional[List[str]] = Field(None, description="Specific templates to use")
    rate_limit: int = Field(150, description="Rate limit for requests per second")


class NucleiScanResponse(BaseModel):
    """Response from Nuclei scan."""
    scan_id: str
    status: str
    message: str


class NucleiFinding(BaseModel):
    """A single Nuclei finding."""
    id: int
    template_id: str
    name: str
    severity: str
    host: str
    matched_at: str
    description: Optional[str] = None
    reference: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    created_at: str


@router.get("/status")
async def get_nuclei_status():
    """Check if Nuclei is installed and get version info."""
    import shutil
    import subprocess
    
    nuclei_path = shutil.which('nuclei')
    if not nuclei_path:
        return {
            "installed": False,
            "error": "Nuclei not found in PATH"
        }
    
    try:
        result = subprocess.run(
            ['nuclei', '-version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        version = result.stdout.strip() or result.stderr.strip()
        return {
            "installed": True,
            "path": nuclei_path,
            "version": version
        }
    except Exception as e:
        return {
            "installed": True,
            "path": nuclei_path,
            "error": str(e)
        }


@router.get("/templates/tags")
async def get_template_tags(
    current_user: User = Depends(get_current_active_user)
):
    """Get available Nuclei template tags."""
    return {
        "severity": ["critical", "high", "medium", "low", "info"],
        "categories": [
            "cve", "rce", "sqli", "xss", "lfi", "ssrf", "redirect",
            "exposure", "misconfiguration", "takeover", "default-login",
            "file-upload", "idor", "auth-bypass", "injection"
        ]
    }


@router.post("/scan", response_model=NucleiScanResponse)
async def run_nuclei_scan(
    request: NucleiScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run a Nuclei vulnerability scan on specified targets.
    
    The scan runs in the background and results are stored in the database.
    """
    import uuid
    
    # Check organization access
    if current_user.role.value != "admin" and current_user.organization_id != request.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    scan_id = str(uuid.uuid4())
    
    # TODO: Implement actual Nuclei scanning in background task
    # background_tasks.add_task(run_nuclei_background, scan_id, request, db)
    
    return NucleiScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Scan queued for {len(request.targets)} targets"
    )


@router.get("/findings")
async def get_nuclei_findings(
    organization_id: Optional[int] = None,
    severity: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get Nuclei scan findings."""
    # TODO: Implement actual findings retrieval from database
    return {
        "findings": [],
        "total": 0,
        "skip": skip,
        "limit": limit
    }


@router.get("/scan/{scan_id}")
async def get_scan_status(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get status of a specific Nuclei scan."""
    # TODO: Implement scan status retrieval
    return {
        "scan_id": scan_id,
        "status": "unknown",
        "message": "Scan status not found"
    }


@router.post("/templates/update")
async def update_nuclei_templates(
    current_user: User = Depends(require_analyst)
):
    """Update Nuclei templates to latest version."""
    import subprocess
    
    try:
        result = subprocess.run(
            ['nuclei', '-update-templates'],
            capture_output=True,
            text=True,
            timeout=300
        )
        return {
            "success": True,
            "output": result.stdout,
            "error": result.stderr if result.returncode != 0 else None
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Template update timed out after 5 minutes"
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@router.get("/tools/status")
async def get_tools_status(
    current_user: User = Depends(get_current_active_user)
):
    """Check status of all ProjectDiscovery tools."""
    import shutil
    
    tools = ['nuclei', 'subfinder', 'httpx', 'dnsx', 'naabu', 'katana', 'waybackurls']
    status = {}
    
    for tool in tools:
        path = shutil.which(tool)
        status[tool] = {
            "installed": path is not None,
            "path": path
        }
    
    return {"tools": status}
