"""
API routes for WaybackURLs functionality.

Provides endpoints to fetch historical URLs from the Wayback Machine
for domains and subdomains using the tomnomnom/waybackurls tool.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_active_user, require_analyst
from app.models.user import User
from app.services.waybackurls_service import WaybackURLsService

router = APIRouter(prefix="/waybackurls", tags=["waybackurls"])


class SingleDomainRequest(BaseModel):
    """Request to fetch wayback URLs for a single domain."""
    domain: str = Field(..., description="Domain to fetch URLs for")
    no_subs: bool = Field(False, description="If true, don't include subdomain URLs")
    timeout: int = Field(120, description="Timeout in seconds")


class SingleDomainResponse(BaseModel):
    """Response from single domain wayback URL fetch."""
    domain: str
    success: bool
    url_count: int
    unique_paths_count: int
    interesting_count: int
    file_extensions: dict
    urls: List[str]
    unique_paths: List[str]
    interesting_urls: List[str]
    elapsed_time: float
    error: Optional[str] = None


class BatchDomainsRequest(BaseModel):
    """Request to fetch wayback URLs for multiple domains."""
    domains: List[str] = Field(..., description="List of domains to fetch URLs for")
    no_subs: bool = Field(False, description="If true, don't include subdomain URLs")
    timeout: int = Field(120, description="Timeout per domain in seconds")
    max_concurrent: int = Field(5, description="Maximum concurrent requests")


class DomainSummary(BaseModel):
    """Summary for a single domain in batch results."""
    domain: str
    success: bool
    url_count: int
    interesting_count: int
    elapsed_time: float
    error: Optional[str] = None


class BatchDomainsResponse(BaseModel):
    """Response from batch domain wayback URL fetch."""
    domains_scanned: int
    total_urls: int
    total_interesting: int
    file_extensions: dict
    domain_results: List[DomainSummary]
    all_urls: List[str]
    interesting_urls: List[str]


class OrganizationRequest(BaseModel):
    """Request to fetch wayback URLs for an organization's assets."""
    organization_id: int = Field(..., description="Organization ID")
    include_subdomains: bool = Field(True, description="Include subdomains in scan")
    timeout_per_domain: int = Field(120, description="Timeout per domain in seconds")
    max_concurrent: int = Field(3, description="Maximum concurrent requests")


class OrganizationResponse(BaseModel):
    """Response from organization wayback URL fetch."""
    organization_id: int
    domains_scanned: int
    total_urls: int
    total_interesting: int
    file_extensions: dict
    domain_results: List[dict]
    all_urls: List[str]
    interesting_urls: List[str]


@router.get("/status")
async def get_waybackurls_status():
    """Check if waybackurls tool is installed and available."""
    import shutil
    installed = shutil.which('waybackurls') is not None
    
    return {
        "tool": "waybackurls",
        "installed": installed,
        "description": "Fetch historical URLs from the Wayback Machine",
        "source": "https://github.com/tomnomnom/waybackurls"
    }


@router.post("/fetch", response_model=SingleDomainResponse)
async def fetch_single_domain(
    request: SingleDomainRequest,
    current_user: User = Depends(require_analyst)
):
    """
    Fetch historical URLs for a single domain from the Wayback Machine.
    
    This uses the waybackurls tool to fetch all known URLs for a domain.
    Useful for discovering:
    - Old/forgotten endpoints
    - API endpoints
    - Sensitive files that may have been exposed
    - Attack surface over time
    """
    service = WaybackURLsService()
    
    result = await service.fetch_urls(
        domain=request.domain,
        no_subs=request.no_subs,
        timeout=request.timeout
    )
    
    return SingleDomainResponse(
        domain=result.domain,
        success=result.success,
        url_count=len(result.urls),
        unique_paths_count=len(result.unique_paths),
        interesting_count=len(result.interesting_urls),
        file_extensions=result.file_extensions,
        urls=result.urls[:1000],  # Limit to 1000 URLs in response
        unique_paths=result.unique_paths[:500],
        interesting_urls=result.interesting_urls[:500],
        elapsed_time=result.elapsed_time,
        error=result.error
    )


@router.post("/fetch/batch", response_model=BatchDomainsResponse)
async def fetch_batch_domains(
    request: BatchDomainsRequest,
    current_user: User = Depends(require_analyst)
):
    """
    Fetch historical URLs for multiple domains from the Wayback Machine.
    
    Useful for scanning all discovered subdomains at once.
    """
    if len(request.domains) > 100:
        raise HTTPException(
            status_code=400,
            detail="Maximum 100 domains per batch request"
        )
    
    service = WaybackURLsService()
    
    results = await service.fetch_urls_batch(
        domains=request.domains,
        no_subs=request.no_subs,
        timeout=request.timeout,
        max_concurrent=request.max_concurrent
    )
    
    # Aggregate results
    all_urls = set()
    all_interesting = set()
    all_extensions = {}
    domain_results = []
    
    for result in results:
        if result.success:
            all_urls.update(result.urls)
            all_interesting.update(result.interesting_urls)
            for ext, count in result.file_extensions.items():
                all_extensions[ext] = all_extensions.get(ext, 0) + count
        
        domain_results.append(DomainSummary(
            domain=result.domain,
            success=result.success,
            url_count=len(result.urls),
            interesting_count=len(result.interesting_urls),
            elapsed_time=result.elapsed_time,
            error=result.error
        ))
    
    return BatchDomainsResponse(
        domains_scanned=len(request.domains),
        total_urls=len(all_urls),
        total_interesting=len(all_interesting),
        file_extensions=dict(sorted(all_extensions.items(), key=lambda x: x[1], reverse=True)),
        domain_results=domain_results,
        all_urls=sorted(list(all_urls))[:5000],  # Limit to 5000 URLs
        interesting_urls=sorted(list(all_interesting))[:1000]
    )


@router.post("/fetch/organization", response_model=OrganizationResponse)
async def fetch_organization_domains(
    request: OrganizationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Fetch historical URLs for all domains/subdomains in an organization.
    
    This will:
    1. Get all domains and subdomains for the organization
    2. Run waybackurls on each one
    3. Aggregate and return all discovered URLs
    """
    # Check organization access
    if current_user.role.value != "admin" and current_user.organization_id != request.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    service = WaybackURLsService(db=db)
    
    result = await service.fetch_for_organization(
        organization_id=request.organization_id,
        include_subdomains=request.include_subdomains,
        timeout_per_domain=request.timeout_per_domain,
        max_concurrent=request.max_concurrent
    )
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    return OrganizationResponse(**result)


@router.get("/interesting-patterns")
async def get_interesting_patterns():
    """Get list of patterns used to identify interesting URLs."""
    service = WaybackURLsService()
    
    return {
        "interesting_extensions": sorted(list(service.INTERESTING_EXTENSIONS)),
        "interesting_patterns": service.INTERESTING_PATTERNS,
        "description": "URLs matching these patterns are flagged as potentially interesting"
    }











