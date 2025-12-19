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
    """Build asset response with port service information."""
    # Build port service summaries
    port_summaries = []
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
    
    # Build technology summaries
    tech_summaries = []
    for tech in asset.technologies:
        tech_summaries.append({
            "name": tech.name,
            "slug": tech.slug,
            "categories": tech.categories or [],
            "version": None
        })
    
    return {
        **asset.__dict__,
        "port_services": port_summaries,
        "technologies": tech_summaries,
        "open_ports_count": len([p for p in asset.port_services if p.state == PortState.OPEN]),
        "risky_ports_count": len([p for p in asset.port_services if p.is_risky])
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
    """Get asset by ID."""
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
    
    return asset


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
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Enrich assets with geo-location data by resolving hostnames and looking up IP locations.
    
    Uses ip-api.com (free, 45 requests/minute) to look up geo-location data.
    """
    from app.services.geolocation_service import get_geolocation_service
    
    query = db.query(Asset)
    
    # Organization filter
    if current_user.is_superuser:
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
    else:
        if not current_user.organization_id:
            return {"enriched": 0, "total": 0, "message": "No organization access"}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Only enrich domains and subdomains (resolvable hostnames)
    query = query.filter(Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]))
    
    # Optionally skip assets that already have geo data
    if not force:
        query = query.filter(
            (Asset.latitude == None) | (Asset.latitude == "")
        )
    
    assets = query.limit(limit).all()
    
    if not assets:
        return {"enriched": 0, "total": 0, "message": "No assets to enrich"}
    
    geo_service = get_geolocation_service()
    enriched_count = 0
    
    for asset in assets:
        try:
            geo_data = await geo_service.lookup_hostname(asset.value)
            
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
        except Exception as e:
            # Log but continue with other assets
            pass
    
    db.commit()
    
    return {
        "enriched": enriched_count,
        "total": len(assets),
        "message": f"Successfully enriched {enriched_count} of {len(assets)} assets with geo-location data"
    }


@router.post("/{asset_id}/enrich-geolocation", response_model=AssetResponse)
async def enrich_single_asset_geolocation(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Enrich a single asset with geo-location data."""
    from app.services.geolocation_service import get_geolocation_service
    
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
    geo_data = await geo_service.lookup_hostname(asset.value)
    
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
