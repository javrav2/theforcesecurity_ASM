"""
GitHub Secret Scanning API Routes

Endpoints for scanning GitHub repositories for exposed secrets.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User
from app.services.github_secret_service import get_github_secret_service
from app.core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/github-secrets", tags=["GitHub Secrets"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class ScanOrganizationRequest(BaseModel):
    """Request to scan a GitHub organization."""
    organization: str
    max_repos: int = 100


class ScanRepositoryRequest(BaseModel):
    """Request to scan a specific repository."""
    repository_url: str


class ScanUserRequest(BaseModel):
    """Request to scan a GitHub user's repositories."""
    username: str
    max_repos: int = 50


class SecretFinding(BaseModel):
    """A single secret finding."""
    type: str
    description: str
    severity: str
    repository: str
    file: Optional[str] = None
    line: Optional[int] = None
    commit: Optional[str] = None
    match: str
    url: Optional[str] = None
    found_at: str


class ScanResult(BaseModel):
    """Result of a secret scan."""
    target: str
    repos_scanned: Optional[int] = None
    secrets_found: int
    secrets: list
    error: Optional[str] = None


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/status")
async def get_service_status():
    """
    Check if GitHub secret scanning is available.
    """
    service = get_github_secret_service()
    
    return {
        "available": service.is_available(),
        "enabled": settings.GITHUB_SECRET_SCAN_ENABLED,
        "token_configured": bool(settings.GITHUB_TOKEN),
        "patterns": len(service.github is not None and 28 or 0),  # Number of secret patterns
    }


@router.post("/scan/organization", response_model=ScanResult)
async def scan_organization(
    request: ScanOrganizationRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """
    Scan a GitHub organization for exposed secrets.
    
    Scans all public repositories in the organization and looks for:
    - AWS credentials
    - API keys (Google, Stripe, Slack, etc.)
    - Database connection strings
    - Private keys (SSH, RSA, PGP)
    - Hardcoded passwords
    """
    service = get_github_secret_service()
    
    if not service.is_available():
        raise HTTPException(
            status_code=503,
            detail="GitHub scanning not available. Configure GITHUB_TOKEN."
        )
    
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    result = service.scan_organization(
        org_name=request.organization,
        organization_id=org_id,
        max_repos=request.max_repos
    )
    
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    
    return ScanResult(
        target=request.organization,
        repos_scanned=result.get("repos_scanned"),
        secrets_found=result.get("secrets_found", 0),
        secrets=result.get("secrets", []),
    )


@router.post("/scan/repository", response_model=ScanResult)
async def scan_repository(
    request: ScanRepositoryRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Scan a specific GitHub repository for exposed secrets.
    
    Provide the full repository URL (e.g., https://github.com/owner/repo).
    """
    service = get_github_secret_service()
    
    if not service.is_available():
        raise HTTPException(
            status_code=503,
            detail="GitHub scanning not available. Configure GITHUB_TOKEN."
        )
    
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    result = service.scan_repository(
        repo_url=request.repository_url,
        organization_id=org_id
    )
    
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    
    return ScanResult(
        target=result.get("repository", request.repository_url),
        secrets_found=result.get("secrets_found", 0),
        secrets=result.get("secrets", []),
    )


@router.post("/scan/user", response_model=ScanResult)
async def scan_user_repos(
    request: ScanUserRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Scan a GitHub user's public repositories for exposed secrets.
    """
    service = get_github_secret_service()
    
    if not service.is_available():
        raise HTTPException(
            status_code=503,
            detail="GitHub scanning not available. Configure GITHUB_TOKEN."
        )
    
    org_id = current_user.organization_id if hasattr(current_user, 'organization_id') else None
    if not org_id:
        raise HTTPException(
            status_code=400,
            detail="User must belong to an organization"
        )
    
    result = service.scan_user(
        username=request.username,
        organization_id=org_id,
        max_repos=request.max_repos
    )
    
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    
    return ScanResult(
        target=request.username,
        repos_scanned=result.get("repos_scanned"),
        secrets_found=result.get("secrets_found", 0),
        secrets=result.get("secrets", []),
    )


@router.get("/patterns")
async def list_secret_patterns(
    current_user: User = Depends(get_current_user)
):
    """
    List all secret patterns that are scanned for.
    """
    from app.services.github_secret_service import SECRET_PATTERNS
    
    patterns = []
    for name, config in SECRET_PATTERNS.items():
        patterns.append({
            "name": name,
            "description": config["description"],
            "severity": config["severity"].value,
        })
    
    return {
        "patterns": patterns,
        "count": len(patterns)
    }
