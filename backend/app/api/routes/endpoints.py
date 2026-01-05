"""
API routes for endpoint and parameter discovery.

Uses ParamSpider and ffuf to discover:
- URL endpoints/paths
- URL parameters
- JavaScript files

Results are stored on the Asset record.
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_analyst
from app.models.user import User
from app.models.asset import Asset, AssetType
from app.services.paramspider_service import ParamSpiderService, ParamSpiderResult
from app.services.ffuf_service import FfufService, FfufScanResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


# Request/Response Schemas
class EndpointDiscoveryRequest(BaseModel):
    """Request to discover endpoints for an asset."""
    asset_id: Optional[int] = Field(None, description="Asset ID to scan")
    domain: Optional[str] = Field(None, description="Domain/subdomain to scan (if no asset_id)")
    organization_id: int = Field(..., description="Organization ID")
    
    # Scan options
    use_paramspider: bool = Field(True, description="Use ParamSpider for parameter discovery")
    use_ffuf: bool = Field(True, description="Use ffuf for directory fuzzing")
    
    # ParamSpider options
    paramspider_level: str = Field("high", description="ParamSpider crawl level")
    
    # ffuf options
    ffuf_use_quick_wordlist: bool = Field(True, description="Use built-in quick wordlist")
    ffuf_extensions: Optional[List[str]] = Field(None, description="File extensions to test")
    
    # Whether to update asset record
    update_asset: bool = Field(True, description="Update asset record with discovered data")


class EndpointDiscoveryResult(BaseModel):
    """Single endpoint discovery result."""
    path: str
    source: str  # paramspider, ffuf, katana
    status_code: Optional[int] = None
    content_length: Optional[int] = None


class ParameterResult(BaseModel):
    """Discovered parameter."""
    name: str
    source: str
    sample_url: Optional[str] = None


class EndpointDiscoveryResponse(BaseModel):
    """Response from endpoint discovery."""
    domain: str
    asset_id: Optional[int] = None
    
    # Discovered data
    endpoints: List[str]
    parameters: List[str]
    js_files: List[str]
    
    # Statistics
    total_endpoints: int
    total_parameters: int
    total_js_files: int
    
    # Source details
    paramspider_urls: int = 0
    ffuf_endpoints: int = 0
    
    # Timing
    elapsed_time: float
    
    # Status
    success: bool
    errors: List[str] = []


class BulkEndpointDiscoveryRequest(BaseModel):
    """Request to discover endpoints for multiple domains."""
    organization_id: int
    domains: Optional[List[str]] = Field(None, description="List of domains to scan")
    asset_ids: Optional[List[int]] = Field(None, description="List of asset IDs to scan")
    scan_all_org_domains: bool = Field(False, description="Scan all domains/subdomains in org")
    max_domains: int = Field(50, ge=1, le=500)
    
    use_paramspider: bool = True
    use_ffuf: bool = True
    update_assets: bool = True


class BulkEndpointDiscoveryResponse(BaseModel):
    """Response from bulk endpoint discovery."""
    domains_scanned: int
    total_endpoints: int
    total_parameters: int
    results: List[EndpointDiscoveryResponse]
    elapsed_time: float


# Helper functions
async def run_endpoint_discovery(
    domain: str,
    use_paramspider: bool = True,
    use_ffuf: bool = True,
    paramspider_level: str = "high",
    ffuf_use_quick_wordlist: bool = True,
    ffuf_extensions: Optional[List[str]] = None,
) -> EndpointDiscoveryResponse:
    """Run endpoint discovery on a domain."""
    start_time = datetime.utcnow()
    
    all_endpoints = set()
    all_parameters = set()
    all_js_files = set()
    errors = []
    
    paramspider_urls = 0
    ffuf_endpoints = 0
    
    # Run ParamSpider
    if use_paramspider:
        try:
            ps_service = ParamSpiderService()
            if ps_service.is_available():
                result = await ps_service.scan_domain(domain, level=paramspider_level)
                if result.success:
                    all_endpoints.update(result.endpoints)
                    all_parameters.update(result.parameters)
                    all_js_files.update(result.js_files)
                    paramspider_urls = len(result.urls)
                elif result.error:
                    errors.append(f"ParamSpider: {result.error}")
            else:
                errors.append("ParamSpider not installed")
        except Exception as e:
            errors.append(f"ParamSpider error: {str(e)}")
    
    # Run ffuf
    if use_ffuf:
        try:
            ffuf_service = FfufService()
            if ffuf_service.is_available():
                result = await ffuf_service.scan_host(
                    domain,
                    use_quick_wordlist=ffuf_use_quick_wordlist,
                    extensions=ffuf_extensions,
                )
                if result.success:
                    all_endpoints.update(result.endpoints)
                    ffuf_endpoints = len(result.endpoints)
                elif result.error:
                    errors.append(f"ffuf: {result.error}")
            else:
                errors.append("ffuf not installed")
        except Exception as e:
            errors.append(f"ffuf error: {str(e)}")
    
    elapsed = (datetime.utcnow() - start_time).total_seconds()
    
    return EndpointDiscoveryResponse(
        domain=domain,
        endpoints=sorted(list(all_endpoints)),
        parameters=sorted(list(all_parameters)),
        js_files=sorted(list(all_js_files)),
        total_endpoints=len(all_endpoints),
        total_parameters=len(all_parameters),
        total_js_files=len(all_js_files),
        paramspider_urls=paramspider_urls,
        ffuf_endpoints=ffuf_endpoints,
        elapsed_time=elapsed,
        success=len(errors) == 0 or len(all_endpoints) > 0 or len(all_parameters) > 0,
        errors=errors,
    )


def update_asset_endpoints(
    db: Session,
    asset: Asset,
    endpoints: List[str],
    parameters: List[str],
    js_files: List[str],
) -> None:
    """Update asset record with discovered endpoints/parameters."""
    # Merge with existing data
    existing_endpoints = set(asset.endpoints or [])
    existing_params = set(asset.parameters or [])
    existing_js = set(asset.js_files or [])
    
    existing_endpoints.update(endpoints)
    existing_params.update(parameters)
    existing_js.update(js_files)
    
    asset.endpoints = sorted(list(existing_endpoints))
    asset.parameters = sorted(list(existing_params))
    asset.js_files = sorted(list(existing_js))
    asset.updated_at = datetime.utcnow()
    
    db.add(asset)
    db.commit()
    
    logger.info(
        f"Updated asset {asset.id} ({asset.value}): "
        f"{len(asset.endpoints)} endpoints, "
        f"{len(asset.parameters)} parameters"
    )


# API Routes
@router.post("/discover", response_model=EndpointDiscoveryResponse)
async def discover_endpoints(
    request: EndpointDiscoveryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Discover endpoints and parameters for a domain/subdomain.
    
    Uses:
    - ParamSpider: Mines parameters from web archives (Wayback Machine)
    - ffuf: Fast directory fuzzing with common wordlist
    
    Results are stored on the asset record for later reference.
    """
    # Get domain to scan
    asset = None
    domain = request.domain
    
    if request.asset_id:
        asset = db.query(Asset).filter(Asset.id == request.asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        if asset.organization_id != request.organization_id:
            raise HTTPException(status_code=403, detail="Asset not in specified organization")
        domain = asset.value
    
    if not domain:
        raise HTTPException(status_code=400, detail="Either asset_id or domain is required")
    
    # Run discovery
    result = await run_endpoint_discovery(
        domain=domain,
        use_paramspider=request.use_paramspider,
        use_ffuf=request.use_ffuf,
        paramspider_level=request.paramspider_level,
        ffuf_use_quick_wordlist=request.ffuf_use_quick_wordlist,
        ffuf_extensions=request.ffuf_extensions,
    )
    result.asset_id = asset.id if asset else None
    
    # Update asset record
    if request.update_asset and asset:
        update_asset_endpoints(
            db=db,
            asset=asset,
            endpoints=result.endpoints,
            parameters=result.parameters,
            js_files=result.js_files,
        )
    elif request.update_asset and domain:
        # Find or create asset
        asset = db.query(Asset).filter(
            Asset.organization_id == request.organization_id,
            Asset.value == domain,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        ).first()
        
        if asset:
            update_asset_endpoints(
                db=db,
                asset=asset,
                endpoints=result.endpoints,
                parameters=result.parameters,
                js_files=result.js_files,
            )
            result.asset_id = asset.id
    
    return result


@router.post("/discover/bulk", response_model=BulkEndpointDiscoveryResponse)
async def discover_endpoints_bulk(
    request: BulkEndpointDiscoveryRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Discover endpoints for multiple domains/assets.
    
    Can scan:
    - Specific domains (via domains list)
    - Specific assets (via asset_ids list)
    - All domains/subdomains in organization (via scan_all_org_domains)
    """
    start_time = datetime.utcnow()
    domains_to_scan = []
    asset_map = {}  # domain -> asset
    
    # Collect domains to scan
    if request.domains:
        domains_to_scan.extend(request.domains)
    
    if request.asset_ids:
        assets = db.query(Asset).filter(
            Asset.id.in_(request.asset_ids),
            Asset.organization_id == request.organization_id,
        ).all()
        for asset in assets:
            domains_to_scan.append(asset.value)
            asset_map[asset.value] = asset
    
    if request.scan_all_org_domains:
        assets = db.query(Asset).filter(
            Asset.organization_id == request.organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        ).limit(request.max_domains).all()
        for asset in assets:
            if asset.value not in domains_to_scan:
                domains_to_scan.append(asset.value)
                asset_map[asset.value] = asset
    
    # Limit domains
    domains_to_scan = domains_to_scan[:request.max_domains]
    
    if not domains_to_scan:
        raise HTTPException(status_code=400, detail="No domains to scan")
    
    logger.info(f"Starting bulk endpoint discovery for {len(domains_to_scan)} domains")
    
    # Run discovery concurrently
    results = []
    semaphore = asyncio.Semaphore(5)  # Max 5 concurrent scans
    
    async def scan_domain(domain: str):
        async with semaphore:
            return await run_endpoint_discovery(
                domain=domain,
                use_paramspider=request.use_paramspider,
                use_ffuf=request.use_ffuf,
            )
    
    tasks = [scan_domain(d) for d in domains_to_scan]
    scan_results = await asyncio.gather(*tasks, return_exceptions=True)
    
    total_endpoints = 0
    total_parameters = 0
    
    for domain, result in zip(domains_to_scan, scan_results):
        if isinstance(result, Exception):
            results.append(EndpointDiscoveryResponse(
                domain=domain,
                endpoints=[],
                parameters=[],
                js_files=[],
                total_endpoints=0,
                total_parameters=0,
                total_js_files=0,
                elapsed_time=0,
                success=False,
                errors=[str(result)],
            ))
            continue
        
        results.append(result)
        total_endpoints += result.total_endpoints
        total_parameters += result.total_parameters
        
        # Update asset if requested
        if request.update_assets and domain in asset_map:
            update_asset_endpoints(
                db=db,
                asset=asset_map[domain],
                endpoints=result.endpoints,
                parameters=result.parameters,
                js_files=result.js_files,
            )
    
    elapsed = (datetime.utcnow() - start_time).total_seconds()
    
    return BulkEndpointDiscoveryResponse(
        domains_scanned=len(domains_to_scan),
        total_endpoints=total_endpoints,
        total_parameters=total_parameters,
        results=results,
        elapsed_time=elapsed,
    )


@router.get("/asset/{asset_id}")
async def get_asset_endpoints(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Get discovered endpoints and parameters for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return {
        "asset_id": asset.id,
        "domain": asset.value,
        "endpoints": asset.endpoints or [],
        "parameters": asset.parameters or [],
        "js_files": asset.js_files or [],
        "total_endpoints": len(asset.endpoints or []),
        "total_parameters": len(asset.parameters or []),
        "total_js_files": len(asset.js_files or []),
    }


@router.get("/tools/status")
async def get_tools_status():
    """Check if endpoint discovery tools are available."""
    ps_service = ParamSpiderService()
    ffuf_service = FfufService()
    
    return {
        "paramspider": {
            "installed": ps_service.is_available(),
            "path": ps_service.paramspider_path,
        },
        "ffuf": {
            "installed": ffuf_service.is_available(),
            "path": ffuf_service.ffuf_path,
            "wordlist": ffuf_service.wordlist_path,
        },
    }

