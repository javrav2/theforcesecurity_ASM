"""Asset routes for attack surface management."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.port_service import PortService, PortState
from app.models.user import User
from app.schemas.asset import (
    AssetCreate, AssetUpdate, AssetResponse, 
    AssetPortsSummary, PortServiceSummary
)
from app.api.deps import get_current_active_user, require_analyst

router = APIRouter(prefix="/assets", tags=["Assets"])


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.is_superuser:
        return True
    return user.organization_id == org_id


def build_asset_response(asset: Asset) -> dict:
    """Build asset response with port service information.
    
    Explicitly builds the response dict to avoid SQLAlchemy internal state
    and handle missing database columns gracefully.
    """
    # Build port service summaries
    port_summaries = []
    try:
        for ps in asset.port_services:
            port_summaries.append(PortServiceSummary(
                id=ps.id,
                port=ps.port,
                protocol=ps.protocol.value,
                service=ps.service_name,
                product=ps.service_product,
                version=ps.service_version,
                state=ps.state.value,
                is_ssl=ps.is_ssl,
                is_risky=ps.is_risky,
                port_string=ps.port_string
            ))
    except Exception:
        port_summaries = []
    
    # Build technology summaries
    tech_summaries = []
    try:
        for tech in asset.technologies:
            tech_summaries.append({
                "name": tech.name,
                "slug": tech.slug,
                "categories": tech.categories or [],
                "version": None
            })
    except Exception:
        tech_summaries = []
    
    # Helper to safely get attribute with default
    def safe_get(attr: str, default=None):
        try:
            val = getattr(asset, attr, default)
            return val if val is not None else default
        except Exception:
            return default
    
    # Build response explicitly to avoid _sa_instance_state and missing columns
    return {
        "id": asset.id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "value": asset.value,
        "organization_id": asset.organization_id,
        "parent_id": safe_get("parent_id"),
        "status": asset.status,
        "description": safe_get("description"),
        "tags": safe_get("tags", []),
        "metadata_": safe_get("metadata_", {}),
        "discovery_source": safe_get("discovery_source"),
        "first_seen": safe_get("first_seen"),
        "last_seen": safe_get("last_seen"),
        "risk_score": safe_get("risk_score", 0),
        "criticality": safe_get("criticality", "medium"),
        "is_monitored": safe_get("is_monitored", True),
        "http_status": safe_get("http_status"),
        "http_title": safe_get("http_title"),
        "dns_records": safe_get("dns_records", {}),
        "ip_address": safe_get("ip_address"),
        "latitude": safe_get("latitude"),
        "longitude": safe_get("longitude"),
        "city": safe_get("city"),
        "country": safe_get("country"),
        "country_code": safe_get("country_code"),
        "isp": safe_get("isp"),
        "asn": safe_get("asn"),
        "in_scope": safe_get("in_scope", True),
        "is_owned": safe_get("is_owned", False),
        "is_live": safe_get("is_live", False),
        "netblock_id": safe_get("netblock_id"),
        "endpoints": safe_get("endpoints", []),
        "parameters": safe_get("parameters", []),
        "js_files": safe_get("js_files", []),
        "created_at": safe_get("created_at"),
        "updated_at": safe_get("updated_at"),
        # Computed fields
        "port_services": port_summaries,
        "technologies": tech_summaries,
        "open_ports_count": len([p for p in port_summaries if hasattr(p, 'state') and p.state == 'open']),
        "risky_ports_count": len([p for p in port_summaries if hasattr(p, 'is_risky') and p.is_risky]),
    }


@router.get("/", response_model=List[AssetResponse])
def list_assets(
    organization_id: Optional[int] = None,
    asset_type: Optional[AssetType] = None,
    status: Optional[AssetStatus] = None,
    search: Optional[str] = None,
    has_open_ports: Optional[bool] = None,
    has_risky_ports: Optional[bool] = None,
    include_cidr: bool = Query(False, description="Include IP_RANGE/CIDR assets (excluded by default)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List assets with filtering options. By default excludes IP_RANGE/CIDR blocks (use netblocks endpoint for those)."""
    query = db.query(Asset)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return []
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Apply filters
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    else:
        # By default, exclude IP_RANGE (CIDR blocks) - these are managed in netblocks
        if not include_cidr:
            query = query.filter(Asset.asset_type != AssetType.IP_RANGE)
    
    if status:
        query = query.filter(Asset.status == status)
    if search:
        query = query.filter(
            (Asset.name.ilike(f"%{search}%")) | 
            (Asset.value.ilike(f"%{search}%"))
        )
    
    assets = query.order_by(Asset.created_at.desc()).offset(skip).limit(limit).all()
    
    # Filter by port criteria if specified
    if has_open_ports is not None or has_risky_ports is not None:
        filtered_assets = []
        for asset in assets:
            open_count = len([p for p in asset.port_services if p.state == PortState.OPEN])
            risky_count = len([p for p in asset.port_services if p.is_risky])
            
            if has_open_ports is not None:
                if has_open_ports and open_count == 0:
                    continue
                if not has_open_ports and open_count > 0:
                    continue
            
            if has_risky_ports is not None:
                if has_risky_ports and risky_count == 0:
                    continue
                if not has_risky_ports and risky_count > 0:
                    continue
            
            filtered_assets.append(asset)
        assets = filtered_assets
    
    return assets


@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    asset_data: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new asset."""
    # Check organization access
    if not check_org_access(current_user, asset_data.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Check for duplicate
    existing = db.query(Asset).filter(
        Asset.organization_id == asset_data.organization_id,
        Asset.asset_type == asset_data.asset_type,
        Asset.value == asset_data.value
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Asset with this type and value already exists"
        )
    
    new_asset = Asset(**asset_data.model_dump())
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)
    
    return new_asset


@router.post("/bulk", response_model=List[AssetResponse], status_code=status.HTTP_201_CREATED)
def create_assets_bulk(
    assets_data: List[AssetCreate],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create multiple assets at once."""
    created_assets = []
    
    for asset_data in assets_data:
        # Check organization access
        if not check_org_access(current_user, asset_data.organization_id):
            continue
        
        # Check for duplicate
        existing = db.query(Asset).filter(
            Asset.organization_id == asset_data.organization_id,
            Asset.asset_type == asset_data.asset_type,
            Asset.value == asset_data.value
        ).first()
        
        if not existing:
            new_asset = Asset(**asset_data.model_dump())
            db.add(new_asset)
            created_assets.append(new_asset)
    
    db.commit()
    for asset in created_assets:
        db.refresh(asset)
    
    return created_assets


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get asset by ID with port services and technologies."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )

    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    # Build full response with port services and technologies
    return build_asset_response(asset)


@router.get("/{asset_id}/ports", response_model=AssetPortsSummary)
def get_asset_ports(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get detailed port information for an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Build port summaries
    port_summaries = []
    services = set()
    tcp_count = 0
    udp_count = 0
    open_count = 0
    filtered_count = 0
    risky_count = 0
    
    for ps in sorted(asset.port_services, key=lambda x: x.port):
        port_summaries.append(PortServiceSummary(
            id=ps.id,
            port=ps.port,
            protocol=ps.protocol.value,
            service=ps.service_name,
            product=ps.service_product,
            version=ps.service_version,
            state=ps.state.value,
            is_ssl=ps.is_ssl,
            is_risky=ps.is_risky,
            port_string=ps.port_string
        ))
        
        if ps.service_name:
            services.add(ps.service_name)
        
        if ps.protocol.value == "tcp":
            tcp_count += 1
        elif ps.protocol.value == "udp":
            udp_count += 1
        
        if ps.state == PortState.OPEN:
            open_count += 1
        elif ps.state in [PortState.FILTERED, PortState.OPEN_FILTERED]:
            filtered_count += 1
        
        if ps.is_risky:
            risky_count += 1
    
    return AssetPortsSummary(
        asset_id=asset.id,
        asset_value=asset.value,
        total_ports=len(asset.port_services),
        open_ports=open_count,
        filtered_ports=filtered_count,
        risky_ports=risky_count,
        tcp_ports=tcp_count,
        udp_ports=udp_count,
        services=sorted(list(services)),
        ports=port_summaries
    )


@router.put("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    asset_data: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Update fields
    update_data = asset_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(asset, field, value)
    
    asset.last_seen = datetime.utcnow()
    
    db.commit()
    db.refresh(asset)
    
    return asset


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    db.delete(asset)
    db.commit()
    
    return None


@router.get("/stats/summary")
def get_assets_summary(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get asset statistics summary including port information."""
    query = db.query(Asset)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return {"total": 0, "by_type": {}, "by_status": {}, "ports": {}}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    assets = query.all()
    
    # Calculate stats
    by_type = {}
    by_status = {}
    total_ports = 0
    total_open_ports = 0
    total_risky_ports = 0
    assets_with_ports = 0
    assets_with_risky_ports = 0
    
    for asset in assets:
        type_key = asset.asset_type.value
        status_key = asset.status.value
        
        by_type[type_key] = by_type.get(type_key, 0) + 1
        by_status[status_key] = by_status.get(status_key, 0) + 1
        
        # Port stats
        asset_ports = len(asset.port_services)
        if asset_ports > 0:
            assets_with_ports += 1
            total_ports += asset_ports
            
            open_count = len([p for p in asset.port_services if p.state == PortState.OPEN])
            risky_count = len([p for p in asset.port_services if p.is_risky])
            
            total_open_ports += open_count
            total_risky_ports += risky_count
            
            if risky_count > 0:
                assets_with_risky_ports += 1
    
    return {
        "total": len(assets),
        "by_type": by_type,
        "by_status": by_status,
        "ports": {
            "total_ports": total_ports,
            "open_ports": total_open_ports,
            "risky_ports": total_risky_ports,
            "assets_with_ports": assets_with_ports,
            "assets_with_risky_ports": assets_with_risky_ports
        }
    }


@router.post("/enrich-geolocation")
async def enrich_assets_geolocation(
    organization_id: Optional[int] = None,
    force: bool = Query(False, description="Re-enrich assets that already have geo data"),
    limit: int = Query(50, ge=1, le=200, description="Maximum assets to enrich"),
    provider: Optional[str] = Query(None, description="Geo provider: ip-api, ipinfo, whoisxml"),
    ipinfo_token: Optional[str] = Query(None, description="IPInfo.io API token"),
    whoisxml_api_key: Optional[str] = Query(None, description="WhoisXML API key"),
    include_ips: bool = Query(True, description="Also enrich IP address assets"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Enrich assets with geo-location data by resolving hostnames and looking up IP locations.
    
    Supported providers:
    - ip-api: Free, no API key required (45 req/min)
    - ipinfo: Free tier 50k/month, optional token for higher limits
    - whoisxml: Requires API key (https://ip-geolocation.whoisxmlapi.com)
    
    Example with WhoisXML:
    POST /api/assets/enrich-geolocation?whoisxml_api_key=at_xxx&provider=whoisxml
    """
    from app.services.geolocation_service import get_geolocation_service, GeoProvider
    
    geo_service = get_geolocation_service()
    
    # Configure API keys if provided
    if ipinfo_token or whoisxml_api_key:
        geo_service.set_api_keys(
            ipinfo_token=ipinfo_token,
            whoisxml_api_key=whoisxml_api_key
        )
    
    # Parse provider
    geo_provider = None
    if provider:
        provider_map = {
            "ip-api": GeoProvider.IP_API,
            "ipinfo": GeoProvider.IPINFO,
            "whoisxml": GeoProvider.WHOISXML,
        }
        geo_provider = provider_map.get(provider.lower())
    
    query = db.query(Asset)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return {"enriched": 0, "total": 0, "message": "No organization access"}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Include domains, subdomains, and optionally IP addresses
    asset_types = [AssetType.DOMAIN, AssetType.SUBDOMAIN]
    if include_ips:
        asset_types.append(AssetType.IP_ADDRESS)
    query = query.filter(Asset.asset_type.in_(asset_types))
    
    # Optionally skip assets that already have geo data
    if not force:
        query = query.filter(
            (Asset.latitude == None) | (Asset.latitude == "")
        )
    
    assets = query.limit(limit).all()
    
    if not assets:
        return {"enriched": 0, "total": 0, "message": "No assets to enrich"}
    
    enriched_count = 0
    countries_found = {}
    
    for asset in assets:
        try:
            # For IP addresses, look up directly; for hostnames, resolve first
            if asset.asset_type == AssetType.IP_ADDRESS:
                geo_data = await geo_service.lookup_ip(asset.value, geo_provider)
            else:
                geo_data = await geo_service.lookup_hostname(asset.value, geo_provider)
            
            if geo_data:
                asset.ip_address = geo_data.get("ip_address")
                asset.latitude = geo_data.get("latitude")
                asset.longitude = geo_data.get("longitude")
                asset.city = geo_data.get("city")
                asset.country = geo_data.get("country")
                asset.country_code = geo_data.get("country_code")
                asset.isp = geo_data.get("isp")
                asset.asn = geo_data.get("asn")
                enriched_count += 1
                
                # Track countries
                country = geo_data.get("country") or geo_data.get("country_code")
                if country:
                    countries_found[country] = countries_found.get(country, 0) + 1
        except Exception as e:
            # Log but continue with other assets
            pass
    
    db.commit()
    
    return {
        "enriched": enriched_count,
        "total": len(assets),
        "countries": countries_found,
        "provider_used": provider or "ip-api",
        "message": f"Successfully enriched {enriched_count} of {len(assets)} assets with geo-location data"
    }


@router.get("/geo-stats")
def get_assets_geo_stats(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get geo-location statistics for assets - used by the map component."""
    query = db.query(Asset)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return {"total": 0, "with_geo": 0, "without_geo": 0, "by_country": {}}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    assets = query.all()
    
    total = len(assets)
    with_geo = 0
    without_geo = 0
    by_country = {}
    by_city = {}
    
    for asset in assets:
        if asset.latitude and asset.longitude:
            with_geo += 1
            country = asset.country or asset.country_code or "Unknown"
            by_country[country] = by_country.get(country, 0) + 1
            
            if asset.city:
                city_key = f"{asset.city}, {country}"
                by_city[city_key] = by_city.get(city_key, 0) + 1
        else:
            without_geo += 1
    
    return {
        "total": total,
        "with_geo": with_geo,
        "without_geo": without_geo,
        "by_country": dict(sorted(by_country.items(), key=lambda x: x[1], reverse=True)),
        "by_city": dict(sorted(by_city.items(), key=lambda x: x[1], reverse=True)[:20]),
        "coverage_percent": round(with_geo / total * 100, 1) if total > 0 else 0
    }


@router.post("/{asset_id}/enrich-geolocation", response_model=AssetResponse)
async def enrich_single_asset_geolocation(
    asset_id: int,
    provider: Optional[str] = Query(None, description="Geo provider: ip-api, ipinfo, whoisxml"),
    ipinfo_token: Optional[str] = Query(None, description="IPInfo.io API token"),
    whoisxml_api_key: Optional[str] = Query(None, description="WhoisXML API key"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Enrich a single asset with geo-location data."""
    from app.services.geolocation_service import get_geolocation_service, GeoProvider
    
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not check_org_access(current_user, asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    geo_service = get_geolocation_service()
    
    # Configure API keys if provided
    if ipinfo_token or whoisxml_api_key:
        geo_service.set_api_keys(
            ipinfo_token=ipinfo_token,
            whoisxml_api_key=whoisxml_api_key
        )
    
    # Parse provider
    geo_provider = None
    if provider:
        provider_map = {
            "ip-api": GeoProvider.IP_API,
            "ipinfo": GeoProvider.IPINFO,
            "whoisxml": GeoProvider.WHOISXML,
        }
        geo_provider = provider_map.get(provider.lower())
    
    # For IP addresses, look up directly; for hostnames, resolve first
    if asset.asset_type == AssetType.IP_ADDRESS:
        geo_data = await geo_service.lookup_ip(asset.value, geo_provider)
    else:
        geo_data = await geo_service.lookup_hostname(asset.value, geo_provider)
    
    if geo_data:
        asset.ip_address = geo_data.get("ip_address")
        asset.latitude = geo_data.get("latitude")
        asset.longitude = geo_data.get("longitude")
        asset.city = geo_data.get("city")
        asset.country = geo_data.get("country")
        asset.country_code = geo_data.get("country_code")
        asset.isp = geo_data.get("isp")
        asset.asn = geo_data.get("asn")
        db.commit()
        db.refresh(asset)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not resolve geo-location for this asset"
        )
    
    return asset


from pydantic import BaseModel

class HttpxProbeResult(BaseModel):
    """Result from httpx probe."""
    host: str  # e.g. "example.com" or "sub.example.com"
    url: Optional[str] = None  # Full URL if available
    status_code: Optional[int] = None
    title: Optional[str] = None
    webserver: Optional[str] = None  # e.g. "nginx", "IIS:10.0"
    technologies: Optional[List[str]] = None  # e.g. ["Bootstrap", "jQuery"]
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    ip: Optional[str] = None


class HttpxImportRequest(BaseModel):
    """Request to import httpx probe results."""
    organization_id: int
    results: List[HttpxProbeResult]


@router.post("/import-httpx-results")
def import_httpx_results(
    import_data: HttpxImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Import httpx probe results to update asset http_status, http_title, is_live status,
    and optionally associate technologies.
    
    Example httpx output that can be parsed:
    https://example.com [200] [Example Page] [nginx,Bootstrap,jQuery]
    
    Expected input format:
    {
        "organization_id": 1,
        "results": [
            {"host": "example.com", "status_code": 200, "title": "Example", "technologies": ["nginx"]}
        ]
    }
    """
    if not check_org_access(current_user, import_data.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    updated_count = 0
    not_found_count = 0
    
    for result in import_data.results:
        # Strip protocol and path to get just the hostname
        hostname = result.host
        if hostname.startswith("https://"):
            hostname = hostname[8:]
        elif hostname.startswith("http://"):
            hostname = hostname[7:]
        hostname = hostname.split("/")[0].split(":")[0]  # Remove path and port
        
        # Find the asset
        asset = db.query(Asset).filter(
            Asset.organization_id == import_data.organization_id,
            Asset.value == hostname
        ).first()
        
        if not asset:
            not_found_count += 1
            continue
        
        # Update asset with probe results
        if result.status_code is not None:
            asset.http_status = result.status_code
            # Mark as live if we got any HTTP response
            asset.is_live = True
        
        if result.title:
            asset.http_title = result.title
        
        if result.ip:
            asset.ip_address = result.ip
        
        # Store additional HTTP info in metadata
        if result.webserver or result.content_type:
            http_info = asset.http_headers or {}
            if result.webserver:
                http_info['server'] = result.webserver
            if result.content_type:
                http_info['content-type'] = result.content_type
            asset.http_headers = http_info
        
        asset.last_seen = datetime.utcnow()
        updated_count += 1
        
        # TODO: Associate technologies if provided
        # This would require looking up or creating Technology records
    
    db.commit()
    
    return {
        "updated": updated_count,
        "not_found": not_found_count,
        "total": len(import_data.results),
        "message": f"Updated {updated_count} assets with HTTP probe results"
    }


@router.post("/probe-live")
async def probe_assets_live(
    organization_id: int,
    asset_type: Optional[AssetType] = Query(None, description="Filter by asset type"),
    limit: int = Query(50, ge=1, le=200, description="Max assets to probe"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run httpx probe on assets to check if they're live and get HTTP status.
    Updates is_live, http_status, and http_title fields.
    """
    from app.services.projectdiscovery_service import get_projectdiscovery_service
    
    if not check_org_access(current_user, organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Get assets to probe
    query = db.query(Asset).filter(Asset.organization_id == organization_id)
    
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    else:
        # Default to domains and subdomains
        query = query.filter(Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]))
    
    assets = query.limit(limit).all()
    
    if not assets:
        return {"probed": 0, "live": 0, "message": "No assets to probe"}
    
    # Extract hostnames
    targets = [asset.value for asset in assets]
    
    # Run httpx probe
    pd_service = get_projectdiscovery_service()
    results = await pd_service.run_httpx(targets, timeout=10, follow_redirects=True)
    
    # Create a lookup map
    results_map = {r.host: r for r in results}
    
    # Update assets
    live_count = 0
    for asset in assets:
        if asset.value in results_map:
            result = results_map[asset.value]
            asset.is_live = True
            asset.http_status = result.status_code
            asset.http_title = result.title
            if result.ip:
                asset.ip_address = result.ip
            asset.last_seen = datetime.utcnow()
            live_count += 1
        else:
            # Asset didn't respond - could mark as not live
            # For now, leave unchanged to allow retry
            pass
    
    db.commit()
    
    return {
        "probed": len(assets),
        "live": live_count,
        "message": f"Found {live_count} live assets out of {len(assets)} probed"
    }
