"""
API routes for SNI IP Ranges discovery.

Provides endpoints for:
1. Syncing SNI data from kaeferjaeger.gay
2. Searching for organization assets across cloud providers
3. Managing data sync schedules
"""

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.models.user import User
from app.services.sni_scanner_service import (
    get_sni_service,
    SNIScannerService,
    CLOUD_PROVIDERS,
)
from app.services.sni_s3_service import (
    get_sni_s3_service,
    SNIS3Service,
    SNIIndexBuilder,
)

router = APIRouter(prefix="/sni-discovery", tags=["SNI Discovery"])


# Request/Response schemas
class SNISyncRequest(BaseModel):
    """Request to sync SNI data."""
    providers: Optional[List[str]] = Field(
        None, 
        description="Specific providers to sync. If empty, syncs all."
    )
    force: bool = Field(
        False,
        description="Force re-download even if data is recent"
    )


class SNISearchRequest(BaseModel):
    """Request to search SNI data."""
    query: str = Field(..., min_length=2, description="Search query (domain, keyword)")
    search_type: str = Field(
        "contains",
        description="Search type: exact, contains, endswith, regex"
    )
    providers: Optional[List[str]] = Field(
        None,
        description="Limit to specific cloud providers"
    )
    max_results: int = Field(
        1000,
        ge=1,
        le=50000,
        description="Maximum results to return"
    )


class SNIOrgSearchRequest(BaseModel):
    """Request for comprehensive organization search."""
    organization_name: str = Field(
        ...,
        min_length=2,
        description="Organization name to search (e.g., 'rockwellautomation')"
    )
    primary_domain: Optional[str] = Field(
        None,
        description="Primary domain to search for subdomains (e.g., 'rockwellautomation.com')"
    )
    keywords: List[str] = Field(
        default_factory=list,
        description="Additional keywords to search (e.g., ['rockwell', 'ra-'])"
    )


class SNIRecord(BaseModel):
    """Single SNI record."""
    ip: str
    port: int
    sni: str
    cloud_provider: str


class SNISearchResponse(BaseModel):
    """Response from SNI search."""
    query: str
    success: bool
    total_records: int
    domains: List[str]
    subdomains: List[str]
    ips: List[str]
    by_cloud_provider: dict
    elapsed_time: float
    error: Optional[str] = None


class SNIStatsResponse(BaseModel):
    """Response with SNI data statistics."""
    data_dir: str
    index_loaded: bool
    unique_domains: int
    providers: dict


class CloudProviderInfo(BaseModel):
    """Information about a cloud provider."""
    key: str
    name: str
    base_url: str
    files: List[str]


# Routes

@router.get("/providers", response_model=List[CloudProviderInfo])
async def list_providers(
    current_user: User = Depends(get_current_user),
):
    """
    List available cloud providers for SNI discovery.
    
    Returns information about each provider whose IP ranges are scanned.
    """
    return [
        CloudProviderInfo(
            key=key,
            name=config["name"],
            base_url=config["base_url"],
            files=config["files"],
        )
        for key, config in CLOUD_PROVIDERS.items()
    ]


@router.get("/stats", response_model=SNIStatsResponse)
async def get_stats(
    current_user: User = Depends(get_current_user),
):
    """
    Get statistics about loaded SNI data.
    
    Shows which providers have data, file sizes, and last sync times.
    """
    service = get_sni_service()
    stats = service.get_stats()
    return SNIStatsResponse(**stats)


@router.post("/sync")
async def sync_sni_data(
    request: SNISyncRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
):
    """
    Sync SNI data from kaeferjaeger.gay.
    
    Downloads the SNI IP ranges data for specified or all cloud providers.
    This runs in the background as files can be large.
    
    The data source scans cloud provider IP ranges and collects SSL/TLS
    certificate information, revealing domains hosted on cloud infrastructure.
    
    Source: https://kaeferjaeger.gay/?dir=sni-ip-ranges
    """
    service = get_sni_service()
    
    if request.providers:
        # Validate providers
        invalid = [p for p in request.providers if p not in CLOUD_PROVIDERS]
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid providers: {invalid}. Valid: {list(CLOUD_PROVIDERS.keys())}"
            )
    
    async def do_sync():
        if request.providers:
            results = {}
            for provider in request.providers:
                results[provider] = await service.download_provider_data(
                    provider, request.force
                )
            return results
        else:
            return await service.sync_all_providers(request.force)
    
    # Run sync in background
    background_tasks.add_task(do_sync)
    
    return {
        "status": "started",
        "message": "SNI data sync started in background",
        "providers": request.providers or list(CLOUD_PROVIDERS.keys()),
        "force": request.force,
    }


@router.post("/sync/foreground")
async def sync_sni_data_foreground(
    request: SNISyncRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Sync SNI data synchronously (blocking).
    
    Same as /sync but waits for completion. Use for smaller syncs or testing.
    """
    service = get_sni_service()
    
    if request.providers:
        invalid = [p for p in request.providers if p not in CLOUD_PROVIDERS]
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid providers: {invalid}"
            )
        
        results = {}
        for provider in request.providers:
            results[provider] = await service.download_provider_data(
                provider, request.force
            )
        return {"status": "completed", "results": results}
    else:
        results = await service.sync_all_providers(request.force)
        return {"status": "completed", "results": results}


@router.post("/search", response_model=SNISearchResponse)
async def search_sni(
    request: SNISearchRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Search SNI data for matching domains.
    
    Search types:
    - **exact**: Exact domain match
    - **contains**: Domain contains the query string
    - **endswith**: Domain ends with query (useful for *.domain.com)
    - **regex**: Regular expression match
    
    Examples:
    - Search for "rockwellautomation" with type "contains" finds all domains
      containing that string across all cloud providers.
    - Search for ".rockwellautomation.com" with type "endswith" finds all
      subdomains of that domain.
    """
    service = get_sni_service()
    
    result = await service.search(
        query=request.query,
        search_type=request.search_type,
        providers=request.providers,
        max_results=request.max_results,
    )
    
    return SNISearchResponse(
        query=result.query,
        success=result.success,
        total_records=result.total_records,
        domains=result.domains,
        subdomains=result.subdomains,
        ips=result.ips,
        by_cloud_provider=result.by_cloud_provider,
        elapsed_time=result.elapsed_time,
        error=result.error,
    )


@router.post("/search/organization", response_model=SNISearchResponse)
async def search_organization(
    request: SNIOrgSearchRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Comprehensive organization search across all cloud providers.
    
    This performs multiple searches to find all assets belonging to an organization:
    
    1. All subdomains of the primary domain (if provided)
    2. All domains containing the organization name
    3. All domains matching provided keywords
    
    Results are deduplicated and aggregated across all cloud providers.
    
    Example for Rockwell Automation:
    - organization_name: "rockwellautomation"
    - primary_domain: "rockwellautomation.com"
    - keywords: ["rockwell", "ra-", "allen-bradley"]
    """
    service = get_sni_service()
    
    result = await service.search_organization(
        org_name=request.organization_name,
        primary_domain=request.primary_domain,
        keywords=request.keywords,
    )
    
    return SNISearchResponse(
        query=result.query,
        success=result.success,
        total_records=result.total_records,
        domains=result.domains,
        subdomains=result.subdomains,
        ips=result.ips,
        by_cloud_provider=result.by_cloud_provider,
        elapsed_time=result.elapsed_time,
        error=result.error,
    )


@router.post("/import-to-assets")
async def import_sni_results_to_assets(
    request: SNIOrgSearchRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Search SNI data and import discovered domains/IPs as assets.
    
    This combines search with asset creation:
    1. Performs organization search
    2. Creates Asset records for discovered domains and subdomains
    3. Adds cloud provider as a tag
    4. Sets source to 'sni-ip-ranges'
    
    Assets are created in the background to avoid timeout for large result sets.
    """
    from app.models.asset import Asset
    from app.models.organization import Organization
    
    service = get_sni_service()
    
    # First, perform the search
    result = await service.search_organization(
        org_name=request.organization_name,
        primary_domain=request.primary_domain,
        keywords=request.keywords,
    )
    
    if not result.success:
        raise HTTPException(status_code=500, detail=result.error)
    
    # Get or create organization
    org = db.query(Organization).filter(
        Organization.name.ilike(f"%{request.organization_name}%")
    ).first()
    
    if not org:
        # Create organization if it doesn't exist
        org = Organization(
            name=request.organization_name,
            primary_domain=request.primary_domain,
        )
        db.add(org)
        db.commit()
        db.refresh(org)
    
    async def import_assets():
        """Background task to import assets."""
        from app.db.database import SessionLocal
        
        local_db = SessionLocal()
        try:
            created = 0
            updated = 0
            
            # Import domains
            for domain in result.domains:
                existing = local_db.query(Asset).filter(
                    Asset.name == domain,
                    Asset.organization_id == org.id,
                ).first()
                
                if existing:
                    # Update with cloud provider info
                    if not existing.tags:
                        existing.tags = []
                    if "cloud-hosted" not in existing.tags:
                        existing.tags.append("cloud-hosted")
                    existing.source = "sni-ip-ranges"
                    updated += 1
                else:
                    asset = Asset(
                        name=domain,
                        asset_type="domain",
                        organization_id=org.id,
                        source="sni-ip-ranges",
                        tags=["cloud-hosted"],
                        is_active=True,
                    )
                    local_db.add(asset)
                    created += 1
            
            # Import subdomains
            for subdomain in result.subdomains:
                existing = local_db.query(Asset).filter(
                    Asset.name == subdomain,
                    Asset.organization_id == org.id,
                ).first()
                
                if existing:
                    if not existing.tags:
                        existing.tags = []
                    if "cloud-hosted" not in existing.tags:
                        existing.tags.append("cloud-hosted")
                    existing.source = "sni-ip-ranges"
                    updated += 1
                else:
                    asset = Asset(
                        name=subdomain,
                        asset_type="subdomain",
                        organization_id=org.id,
                        source="sni-ip-ranges",
                        tags=["cloud-hosted"],
                        is_active=True,
                    )
                    local_db.add(asset)
                    created += 1
            
            # Import IPs
            for ip in result.ips[:1000]:  # Limit IPs to avoid too many
                existing = local_db.query(Asset).filter(
                    Asset.name == ip,
                    Asset.organization_id == org.id,
                ).first()
                
                if not existing:
                    asset = Asset(
                        name=ip,
                        asset_type="ip",
                        organization_id=org.id,
                        source="sni-ip-ranges",
                        tags=["cloud-hosted"],
                        is_active=True,
                    )
                    local_db.add(asset)
                    created += 1
            
            local_db.commit()
            
        except Exception as e:
            local_db.rollback()
            raise
        finally:
            local_db.close()
    
    # Start background import
    background_tasks.add_task(import_assets)
    
    return {
        "status": "importing",
        "message": "Assets are being imported in background",
        "search_results": {
            "domains": len(result.domains),
            "subdomains": len(result.subdomains),
            "ips": len(result.ips),
            "total_records": result.total_records,
            "by_cloud_provider": result.by_cloud_provider,
        },
        "organization_id": org.id,
    }


# =============================================================================
# S3-Backed Index Routes (Fast Lookups)
# =============================================================================

@router.get("/s3/stats")
async def get_s3_stats(
    current_user: User = Depends(get_current_user),
):
    """
    Get statistics about the S3-backed SNI index.
    
    This is the pre-processed index for fast lookups.
    """
    service = get_sni_s3_service()
    return await service.get_stats()


@router.post("/s3/sync")
async def sync_s3_index(
    force: bool = False,
    current_user: User = Depends(get_current_user),
):
    """
    Sync the S3 index to local cache.
    
    Downloads the pre-processed index from S3 for fast local searches.
    """
    service = get_sni_s3_service()
    success = await service.sync_from_s3(force=force)
    
    if success:
        stats = await service.get_stats()
        return {
            "status": "synced",
            "message": "S3 index synced to local cache",
            "stats": stats
        }
    else:
        return {
            "status": "failed",
            "message": "Failed to sync S3 index. Check S3 configuration.",
        }


@router.post("/s3/search", response_model=SNISearchResponse)
async def search_s3_index(
    request: SNISearchRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Fast search on S3-backed index (binary search, <100ms).
    
    This uses the pre-processed index stored in S3 for fast lookups.
    Call /s3/sync first if index is not loaded.
    """
    service = get_sni_s3_service()
    
    result = await service.search(
        query=request.query,
        search_type=request.search_type,
        max_results=request.max_results,
    )
    
    return SNISearchResponse(
        query=result.query,
        success=result.error is None,
        total_records=result.total_records,
        domains=result.domains,
        subdomains=result.subdomains,
        ips=result.ips,
        by_cloud_provider={p: len(d) for p, d in result.by_provider.items()},
        elapsed_time=result.elapsed_time,
        error=result.error,
    )


@router.post("/s3/search/organization", response_model=SNISearchResponse)
async def search_s3_organization(
    request: SNIOrgSearchRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Fast organization search on S3-backed index.
    
    Searches for:
    1. Subdomains of primary domain
    2. Domains containing org name
    3. Domains matching keywords
    
    All with fast binary search on cached index.
    """
    service = get_sni_s3_service()
    
    result = await service.search_organization(
        org_name=request.organization_name,
        primary_domain=request.primary_domain,
        keywords=request.keywords,
    )
    
    return SNISearchResponse(
        query=result.query,
        success=result.error is None,
        total_records=result.total_records,
        domains=result.domains,
        subdomains=result.subdomains,
        ips=result.ips,
        by_cloud_provider={p: len(d) for p, d in result.by_provider.items()},
        elapsed_time=result.elapsed_time,
        error=result.error,
    )


@router.post("/s3/build-index")
async def build_s3_index(
    providers: Optional[List[str]] = None,
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(get_current_user),
):
    """
    Build the S3 index from source data (kaeferjaeger.gay).
    
    Downloads data from all cloud providers, processes into searchable index,
    and uploads to S3. This is typically run weekly.
    
    Runs in background as it takes 5-15 minutes.
    """
    import os
    
    s3_bucket = os.getenv("SNI_S3_BUCKET") or os.getenv("CC_S3_BUCKET")
    if not s3_bucket:
        raise HTTPException(
            status_code=400,
            detail="SNI_S3_BUCKET or CC_S3_BUCKET environment variable not set"
        )
    
    if providers:
        invalid = [p for p in providers if p not in CLOUD_PROVIDERS]
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid providers: {invalid}"
            )
    
    async def do_build():
        builder = SNIIndexBuilder(s3_bucket=s3_bucket)
        return await builder.build_and_upload(providers=providers)
    
    if background_tasks:
        background_tasks.add_task(do_build)
        return {
            "status": "building",
            "message": "S3 index build started in background",
            "s3_bucket": s3_bucket,
            "providers": providers or list(CLOUD_PROVIDERS.keys()),
        }
    else:
        result = await do_build()
        return {
            "status": "completed",
            "result": result
        }

