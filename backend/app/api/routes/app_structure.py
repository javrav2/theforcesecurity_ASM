"""
API routes for Application Structure aggregation.

Aggregates discovered paths, URLs, parameters, and JS files from:
- Katana (deep web crawling with JS parsing)
- ParamSpider (URL parameter discovery)
- WaybackURLs (historical URL discovery)
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.api.deps import get_db, get_current_active_user, require_analyst
from app.models.user import User
from app.models.scan import Scan, ScanType, ScanStatus

router = APIRouter(prefix="/app-structure", tags=["app-structure"])


class AppStructureItem(BaseModel):
    """Individual item in the application structure."""
    value: str
    type: str  # path, url, parameter, js_file, api_endpoint
    source: str  # katana, paramspider, waybackurls
    scan_id: int
    domain: Optional[str] = None
    created_at: Optional[str] = None


class AppStructureSummary(BaseModel):
    """Summary statistics for application structure."""
    total_paths: int
    total_urls: int
    total_parameters: int
    total_js_files: int
    total_api_endpoints: int
    total_interesting_urls: int
    scans_included: int


class AppStructureResponse(BaseModel):
    """Response containing aggregated application structure."""
    summary: AppStructureSummary
    paths: List[str]
    urls: List[str]
    parameters: List[str]
    js_files: List[str]
    api_endpoints: List[str]
    interesting_urls: List[str]
    file_extensions: Dict[str, int]
    source_breakdown: Dict[str, Dict[str, int]]


class AppStructureDetailedResponse(BaseModel):
    """Detailed response with items and their sources."""
    summary: AppStructureSummary
    items: List[AppStructureItem]
    has_more: bool
    total_count: int


@router.get("/summary")
async def get_app_structure_summary(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
) -> AppStructureSummary:
    """
    Get summary statistics for discovered application structure.
    
    Returns counts of paths, URLs, parameters, and JS files discovered
    across all Katana, ParamSpider, and WaybackURLs scans.
    """
    # Build query for relevant scan types
    query = db.query(Scan).filter(
        Scan.scan_type.in_([ScanType.KATANA, ScanType.PARAMSPIDER, ScanType.WAYBACKURLS]),
        Scan.status == ScanStatus.COMPLETED
    )
    
    if organization_id:
        query = query.filter(Scan.organization_id == organization_id)
    elif current_user.organization_id and current_user.role.value != "admin":
        query = query.filter(Scan.organization_id == current_user.organization_id)
    
    scans = query.all()
    
    # Aggregate data
    all_paths = set()
    all_urls = set()
    all_params = set()
    all_js = set()
    all_api = set()
    all_interesting = set()
    
    for scan in scans:
        results = scan.results or {}
        
        # Katana results
        if scan.scan_type == ScanType.KATANA:
            all_paths.update(results.get("endpoints", []))
            all_urls.update(results.get("urls", []))
            all_params.update(results.get("parameters", []))
            all_js.update(results.get("js_files", []))
            all_api.update(results.get("api_endpoints", []))
        
        # ParamSpider results
        elif scan.scan_type == ScanType.PARAMSPIDER:
            all_paths.update(results.get("endpoints", []))
            all_urls.update(results.get("urls", []))
            all_params.update(results.get("parameters", []))
            all_js.update(results.get("js_files", []))
        
        # WaybackURLs results
        elif scan.scan_type == ScanType.WAYBACKURLS:
            all_paths.update(results.get("unique_paths", []))
            all_urls.update(results.get("urls", []))
            all_interesting.update(results.get("interesting_urls", []))
    
    return AppStructureSummary(
        total_paths=len(all_paths),
        total_urls=len(all_urls),
        total_parameters=len(all_params),
        total_js_files=len(all_js),
        total_api_endpoints=len(all_api),
        total_interesting_urls=len(all_interesting),
        scans_included=len(scans)
    )


@router.get("/")
async def get_app_structure(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    item_type: Optional[str] = Query(None, description="Filter by type: path, url, parameter, js_file, api_endpoint, interesting"),
    search: Optional[str] = Query(None, description="Search filter"),
    limit: int = Query(1000, le=5000, description="Maximum items per category"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
) -> AppStructureResponse:
    """
    Get aggregated application structure from all relevant scans.
    
    Combines results from:
    - Katana: endpoints, JS files, parameters, API endpoints
    - ParamSpider: endpoints, URLs, parameters, JS files
    - WaybackURLs: historical URLs, unique paths, interesting URLs
    """
    # Build query for relevant scan types
    query = db.query(Scan).filter(
        Scan.scan_type.in_([ScanType.KATANA, ScanType.PARAMSPIDER, ScanType.WAYBACKURLS]),
        Scan.status == ScanStatus.COMPLETED
    ).order_by(desc(Scan.completed_at))
    
    if organization_id:
        query = query.filter(Scan.organization_id == organization_id)
    elif current_user.organization_id and current_user.role.value != "admin":
        query = query.filter(Scan.organization_id == current_user.organization_id)
    
    scans = query.all()
    
    # Aggregate data
    all_paths = set()
    all_urls = set()
    all_params = set()
    all_js = set()
    all_api = set()
    all_interesting = set()
    all_extensions: Dict[str, int] = {}
    
    source_breakdown = {
        "katana": {"paths": 0, "urls": 0, "parameters": 0, "js_files": 0, "api_endpoints": 0},
        "paramspider": {"paths": 0, "urls": 0, "parameters": 0, "js_files": 0},
        "waybackurls": {"paths": 0, "urls": 0, "interesting": 0}
    }
    
    for scan in scans:
        results = scan.results or {}
        
        # Katana results
        if scan.scan_type == ScanType.KATANA:
            endpoints = results.get("endpoints", [])
            urls = results.get("urls", [])
            params = results.get("parameters", [])
            js = results.get("js_files", [])
            api = results.get("api_endpoints", [])
            
            all_paths.update(endpoints)
            all_urls.update(urls)
            all_params.update(params)
            all_js.update(js)
            all_api.update(api)
            
            source_breakdown["katana"]["paths"] += len(endpoints)
            source_breakdown["katana"]["urls"] += len(urls)
            source_breakdown["katana"]["parameters"] += len(params)
            source_breakdown["katana"]["js_files"] += len(js)
            source_breakdown["katana"]["api_endpoints"] += len(api)
        
        # ParamSpider results
        elif scan.scan_type == ScanType.PARAMSPIDER:
            endpoints = results.get("endpoints", [])
            urls = results.get("urls", [])
            params = results.get("parameters", [])
            js = results.get("js_files", [])
            
            all_paths.update(endpoints)
            all_urls.update(urls)
            all_params.update(params)
            all_js.update(js)
            
            source_breakdown["paramspider"]["paths"] += len(endpoints)
            source_breakdown["paramspider"]["urls"] += len(urls)
            source_breakdown["paramspider"]["parameters"] += len(params)
            source_breakdown["paramspider"]["js_files"] += len(js)
        
        # WaybackURLs results
        elif scan.scan_type == ScanType.WAYBACKURLS:
            paths = results.get("unique_paths", [])
            urls = results.get("urls", [])
            interesting = results.get("interesting_urls", [])
            extensions = results.get("file_extensions", {})
            
            all_paths.update(paths)
            all_urls.update(urls)
            all_interesting.update(interesting)
            
            for ext, count in extensions.items():
                all_extensions[ext] = all_extensions.get(ext, 0) + count
            
            source_breakdown["waybackurls"]["paths"] += len(paths)
            source_breakdown["waybackurls"]["urls"] += len(urls)
            source_breakdown["waybackurls"]["interesting"] += len(interesting)
    
    # Apply search filter if provided
    def filter_items(items: set, search_term: str) -> list:
        if not search_term:
            return sorted(list(items))[:limit]
        return sorted([i for i in items if search_term.lower() in i.lower()])[:limit]
    
    # Build response based on requested item_type
    paths = filter_items(all_paths, search) if not item_type or item_type == "path" else []
    urls = filter_items(all_urls, search) if not item_type or item_type == "url" else []
    params = filter_items(all_params, search) if not item_type or item_type == "parameter" else []
    js_files = filter_items(all_js, search) if not item_type or item_type == "js_file" else []
    api_endpoints = filter_items(all_api, search) if not item_type or item_type == "api_endpoint" else []
    interesting = filter_items(all_interesting, search) if not item_type or item_type == "interesting" else []
    
    return AppStructureResponse(
        summary=AppStructureSummary(
            total_paths=len(all_paths),
            total_urls=len(all_urls),
            total_parameters=len(all_params),
            total_js_files=len(all_js),
            total_api_endpoints=len(all_api),
            total_interesting_urls=len(all_interesting),
            scans_included=len(scans)
        ),
        paths=paths,
        urls=urls,
        parameters=params,
        js_files=js_files,
        api_endpoints=api_endpoints,
        interesting_urls=interesting,
        file_extensions=dict(sorted(all_extensions.items(), key=lambda x: x[1], reverse=True)[:50]),
        source_breakdown=source_breakdown
    )


@router.get("/by-domain/{domain}")
async def get_app_structure_by_domain(
    domain: str,
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
) -> AppStructureResponse:
    """
    Get application structure for a specific domain.
    
    Filters results to only include data from scans targeting the specified domain.
    """
    # Build query for relevant scan types with domain filter
    query = db.query(Scan).filter(
        Scan.scan_type.in_([ScanType.KATANA, ScanType.PARAMSPIDER, ScanType.WAYBACKURLS]),
        Scan.status == ScanStatus.COMPLETED
    ).order_by(desc(Scan.completed_at))
    
    if organization_id:
        query = query.filter(Scan.organization_id == organization_id)
    elif current_user.organization_id and current_user.role.value != "admin":
        query = query.filter(Scan.organization_id == current_user.organization_id)
    
    scans = query.all()
    
    # Filter scans that target the specific domain
    domain_scans = []
    for scan in scans:
        targets = scan.targets or []
        if any(domain.lower() in str(t).lower() for t in targets):
            domain_scans.append(scan)
    
    # Aggregate data (same as above but for filtered scans)
    all_paths = set()
    all_urls = set()
    all_params = set()
    all_js = set()
    all_api = set()
    all_interesting = set()
    all_extensions: Dict[str, int] = {}
    
    source_breakdown = {
        "katana": {"paths": 0, "urls": 0, "parameters": 0, "js_files": 0, "api_endpoints": 0},
        "paramspider": {"paths": 0, "urls": 0, "parameters": 0, "js_files": 0},
        "waybackurls": {"paths": 0, "urls": 0, "interesting": 0}
    }
    
    for scan in domain_scans:
        results = scan.results or {}
        
        if scan.scan_type == ScanType.KATANA:
            endpoints = results.get("endpoints", [])
            urls = results.get("urls", [])
            params = results.get("parameters", [])
            js = results.get("js_files", [])
            api = results.get("api_endpoints", [])
            
            all_paths.update(endpoints)
            all_urls.update(urls)
            all_params.update(params)
            all_js.update(js)
            all_api.update(api)
            
            source_breakdown["katana"]["paths"] += len(endpoints)
            source_breakdown["katana"]["urls"] += len(urls)
            source_breakdown["katana"]["parameters"] += len(params)
            source_breakdown["katana"]["js_files"] += len(js)
            source_breakdown["katana"]["api_endpoints"] += len(api)
        
        elif scan.scan_type == ScanType.PARAMSPIDER:
            endpoints = results.get("endpoints", [])
            urls = results.get("urls", [])
            params = results.get("parameters", [])
            js = results.get("js_files", [])
            
            all_paths.update(endpoints)
            all_urls.update(urls)
            all_params.update(params)
            all_js.update(js)
            
            source_breakdown["paramspider"]["paths"] += len(endpoints)
            source_breakdown["paramspider"]["urls"] += len(urls)
            source_breakdown["paramspider"]["parameters"] += len(params)
            source_breakdown["paramspider"]["js_files"] += len(js)
        
        elif scan.scan_type == ScanType.WAYBACKURLS:
            paths = results.get("unique_paths", [])
            urls = results.get("urls", [])
            interesting = results.get("interesting_urls", [])
            extensions = results.get("file_extensions", {})
            
            all_paths.update(paths)
            all_urls.update(urls)
            all_interesting.update(interesting)
            
            for ext, count in extensions.items():
                all_extensions[ext] = all_extensions.get(ext, 0) + count
            
            source_breakdown["waybackurls"]["paths"] += len(paths)
            source_breakdown["waybackurls"]["urls"] += len(urls)
            source_breakdown["waybackurls"]["interesting"] += len(interesting)
    
    return AppStructureResponse(
        summary=AppStructureSummary(
            total_paths=len(all_paths),
            total_urls=len(all_urls),
            total_parameters=len(all_params),
            total_js_files=len(all_js),
            total_api_endpoints=len(all_api),
            total_interesting_urls=len(all_interesting),
            scans_included=len(domain_scans)
        ),
        paths=sorted(list(all_paths))[:1000],
        urls=sorted(list(all_urls))[:1000],
        parameters=sorted(list(all_params)),
        js_files=sorted(list(all_js)),
        api_endpoints=sorted(list(all_api)),
        interesting_urls=sorted(list(all_interesting))[:500],
        file_extensions=dict(sorted(all_extensions.items(), key=lambda x: x[1], reverse=True)[:50]),
        source_breakdown=source_breakdown
    )


@router.get("/by-asset/{asset_id}")
async def get_app_structure_by_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
) -> AppStructureResponse:
    """
    Get application structure for a specific asset.
    
    Filters all discovered paths, URLs, parameters, and JS files to only include
    items that contain the asset's domain/value in the URL string.
    
    This allows mapping scan results directly to individual assets.
    """
    from app.models.asset import Asset
    
    # Get the asset
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    # Check organization access
    if current_user.role.value != "admin":
        if asset.organization_id != current_user.organization_id:
            raise HTTPException(status_code=403, detail="Access denied")
    
    # Get the asset value (domain/subdomain) for filtering
    asset_value = asset.value.lower()
    
    # Also check root domain for subdomain assets
    root_domain = asset.root_domain.lower() if asset.root_domain else None
    
    # Build query for relevant scan types
    query = db.query(Scan).filter(
        Scan.scan_type.in_([ScanType.KATANA, ScanType.PARAMSPIDER, ScanType.WAYBACKURLS]),
        Scan.status == ScanStatus.COMPLETED,
        Scan.organization_id == asset.organization_id
    ).order_by(desc(Scan.completed_at))
    
    scans = query.all()
    
    # Helper function to check if a URL/path belongs to this asset
    def matches_asset(url_or_path: str) -> bool:
        url_lower = url_or_path.lower()
        # Check if asset value is in the URL
        if asset_value in url_lower:
            return True
        return False
    
    # Aggregate and filter data
    all_paths = set()
    all_urls = set()
    all_params = set()
    all_js = set()
    all_api = set()
    all_interesting = set()
    all_extensions: Dict[str, int] = {}
    
    source_breakdown = {
        "katana": {"paths": 0, "urls": 0, "parameters": 0, "js_files": 0, "api_endpoints": 0},
        "paramspider": {"paths": 0, "urls": 0, "parameters": 0, "js_files": 0},
        "waybackurls": {"paths": 0, "urls": 0, "interesting": 0}
    }
    
    scans_with_data = 0
    
    for scan in scans:
        results = scan.results or {}
        scan_has_data = False
        
        if scan.scan_type == ScanType.KATANA:
            # Filter endpoints/paths
            endpoints = [e for e in results.get("endpoints", []) if matches_asset(e)]
            urls = [u for u in results.get("urls", []) if matches_asset(u)]
            # Parameters are just names, so include all if any URL matches
            params = results.get("parameters", []) if urls else []
            js = [j for j in results.get("js_files", []) if matches_asset(j)]
            api = [a for a in results.get("api_endpoints", []) if matches_asset(a)]
            
            if endpoints or urls or js or api:
                scan_has_data = True
                all_paths.update(endpoints)
                all_urls.update(urls)
                all_params.update(params)
                all_js.update(js)
                all_api.update(api)
                
                source_breakdown["katana"]["paths"] += len(endpoints)
                source_breakdown["katana"]["urls"] += len(urls)
                source_breakdown["katana"]["parameters"] += len(params)
                source_breakdown["katana"]["js_files"] += len(js)
                source_breakdown["katana"]["api_endpoints"] += len(api)
        
        elif scan.scan_type == ScanType.PARAMSPIDER:
            endpoints = [e for e in results.get("endpoints", []) if matches_asset(e)]
            urls = [u for u in results.get("urls", []) if matches_asset(u)]
            params = results.get("parameters", []) if urls else []
            js = [j for j in results.get("js_files", []) if matches_asset(j)]
            
            if endpoints or urls or js:
                scan_has_data = True
                all_paths.update(endpoints)
                all_urls.update(urls)
                all_params.update(params)
                all_js.update(js)
                
                source_breakdown["paramspider"]["paths"] += len(endpoints)
                source_breakdown["paramspider"]["urls"] += len(urls)
                source_breakdown["paramspider"]["parameters"] += len(params)
                source_breakdown["paramspider"]["js_files"] += len(js)
        
        elif scan.scan_type == ScanType.WAYBACKURLS:
            paths = [p for p in results.get("unique_paths", []) if matches_asset(p)]
            urls = [u for u in results.get("urls", []) if matches_asset(u)]
            interesting = [i for i in results.get("interesting_urls", []) if matches_asset(i)]
            
            if paths or urls or interesting:
                scan_has_data = True
                all_paths.update(paths)
                all_urls.update(urls)
                all_interesting.update(interesting)
                
                # Calculate file extensions from filtered URLs
                for url in urls:
                    if '.' in url.split('/')[-1]:
                        ext = '.' + url.split('.')[-1].split('?')[0].split('#')[0][:10]
                        if ext and len(ext) < 10:
                            all_extensions[ext] = all_extensions.get(ext, 0) + 1
                
                source_breakdown["waybackurls"]["paths"] += len(paths)
                source_breakdown["waybackurls"]["urls"] += len(urls)
                source_breakdown["waybackurls"]["interesting"] += len(interesting)
        
        if scan_has_data:
            scans_with_data += 1
    
    return AppStructureResponse(
        summary=AppStructureSummary(
            total_paths=len(all_paths),
            total_urls=len(all_urls),
            total_parameters=len(all_params),
            total_js_files=len(all_js),
            total_api_endpoints=len(all_api),
            total_interesting_urls=len(all_interesting),
            scans_included=scans_with_data
        ),
        paths=sorted(list(all_paths))[:1000],
        urls=sorted(list(all_urls))[:1000],
        parameters=sorted(list(all_params)),
        js_files=sorted(list(all_js)),
        api_endpoints=sorted(list(all_api)),
        interesting_urls=sorted(list(all_interesting))[:500],
        file_extensions=dict(sorted(all_extensions.items(), key=lambda x: x[1], reverse=True)[:50]),
        source_breakdown=source_breakdown
    )


@router.get("/scans")
async def get_app_structure_scans(
    organization_id: Optional[int] = Query(None, description="Filter by organization"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
) -> List[Dict[str, Any]]:
    """
    Get list of scans that contribute to application structure.
    
    Returns metadata about Katana, ParamSpider, and WaybackURLs scans.
    """
    query = db.query(Scan).filter(
        Scan.scan_type.in_([ScanType.KATANA, ScanType.PARAMSPIDER, ScanType.WAYBACKURLS]),
        Scan.status == ScanStatus.COMPLETED
    ).order_by(desc(Scan.completed_at))
    
    if organization_id:
        query = query.filter(Scan.organization_id == organization_id)
    elif current_user.organization_id and current_user.role.value != "admin":
        query = query.filter(Scan.organization_id == current_user.organization_id)
    
    scans = query.limit(100).all()
    
    result = []
    for scan in scans:
        results = scan.results or {}
        
        # Count items based on scan type
        item_counts = {}
        if scan.scan_type == ScanType.KATANA:
            item_counts = {
                "endpoints": len(results.get("endpoints", [])),
                "urls": len(results.get("urls", [])),
                "parameters": len(results.get("parameters", [])),
                "js_files": len(results.get("js_files", [])),
                "api_endpoints": len(results.get("api_endpoints", []))
            }
        elif scan.scan_type == ScanType.PARAMSPIDER:
            item_counts = {
                "endpoints": len(results.get("endpoints", [])),
                "urls": len(results.get("urls", [])),
                "parameters": len(results.get("parameters", [])),
                "js_files": len(results.get("js_files", []))
            }
        elif scan.scan_type == ScanType.WAYBACKURLS:
            item_counts = {
                "unique_paths": len(results.get("unique_paths", [])),
                "urls": len(results.get("urls", [])),
                "interesting_urls": len(results.get("interesting_urls", []))
            }
        
        result.append({
            "id": scan.id,
            "name": scan.name,
            "scan_type": scan.scan_type.value,
            "targets": scan.targets,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "organization_id": scan.organization_id,
            "item_counts": item_counts
        })
    
    return result
