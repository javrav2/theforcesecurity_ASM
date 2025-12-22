"""Netblock/CIDR routes for IP range management."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.database import get_db
from app.models.netblock import Netblock
from app.models.organization import Organization
from app.models.api_config import APIConfig
from app.models.user import User
from app.schemas.netblock import (
    NetblockCreate, 
    NetblockUpdate, 
    NetblockResponse,
    NetblockSummary,
    NetblockDiscoveryRequest,
    NetblockDiscoveryResponse
)
from app.api.deps import get_current_active_user, require_analyst, require_admin
from app.services.whoisxml_netblock_service import get_whoisxml_netblock_service

router = APIRouter(prefix="/netblocks", tags=["Netblocks"])


@router.get("/", response_model=List[NetblockResponse])
def list_netblocks(
    organization_id: Optional[int] = None,
    is_owned: Optional[bool] = None,
    in_scope: Optional[bool] = None,
    ip_version: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List netblocks with filtering options."""
    query = db.query(Netblock)
    
    # Organization filter
    if organization_id:
        query = query.filter(Netblock.organization_id == organization_id)
    elif not current_user.is_superuser:
        if current_user.organization_id:
            query = query.filter(Netblock.organization_id == current_user.organization_id)
        else:
            return []
    
    # Apply filters
    if is_owned is not None:
        query = query.filter(Netblock.is_owned == is_owned)
    if in_scope is not None:
        query = query.filter(Netblock.in_scope == in_scope)
    if ip_version:
        query = query.filter(Netblock.ip_version == ip_version)
    
    netblocks = query.order_by(Netblock.is_owned.desc(), Netblock.ip_count.desc()).offset(skip).limit(limit).all()
    return netblocks


@router.get("/summary", response_model=NetblockSummary)
def get_netblock_summary(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get summary statistics for netblocks."""
    query = db.query(Netblock)
    
    if organization_id:
        query = query.filter(Netblock.organization_id == organization_id)
    elif not current_user.is_superuser:
        if current_user.organization_id:
            query = query.filter(Netblock.organization_id == current_user.organization_id)
    
    netblocks = query.all()
    
    summary = NetblockSummary(
        total_netblocks=len(netblocks),
        owned_netblocks=sum(1 for n in netblocks if n.is_owned),
        in_scope_netblocks=sum(1 for n in netblocks if n.in_scope),
        out_of_scope_netblocks=sum(1 for n in netblocks if not n.in_scope),
        total_ips=sum(n.ip_count or 0 for n in netblocks),
        owned_ips=sum(n.ip_count or 0 for n in netblocks if n.is_owned),
        in_scope_ips=sum(n.ip_count or 0 for n in netblocks if n.in_scope),
        ipv4_netblocks=sum(1 for n in netblocks if n.ip_version == "ipv4"),
        ipv6_netblocks=sum(1 for n in netblocks if n.ip_version == "ipv6"),
        scanned_netblocks=sum(1 for n in netblocks if n.last_scanned),
        unscanned_netblocks=sum(1 for n in netblocks if not n.last_scanned),
    )
    
    return summary


@router.post("/discover", response_model=NetblockDiscoveryResponse)
async def discover_netblocks(
    request: NetblockDiscoveryRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Discover netblocks for an organization using WhoisXML API.
    
    Searches for IP ranges associated with the organization names provided.
    """
    # Verify organization exists
    org = db.query(Organization).filter(Organization.id == request.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Get WhoisXML API key
    api_config = db.query(APIConfig).filter(
        APIConfig.organization_id == request.organization_id,
        APIConfig.service_name == "whoisxml",
        APIConfig.is_active == True
    ).first()
    
    if not api_config:
        raise HTTPException(
            status_code=400,
            detail="WhoisXML API key not configured. Go to Settings to add it."
        )
    
    try:
        api_key = api_config.get_api_key()
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail="WhoisXML API key decryption failed. Please re-enter your API key in Settings. The encryption key may have changed."
        )
    
    if not api_key:
        raise HTTPException(status_code=400, detail="WhoisXML API key is invalid")
    
    # Run discovery
    service = get_whoisxml_netblock_service(api_key)
    
    try:
        discovery_result = await service.discover_netblocks(
            organization_name=org.name,
            search_terms=request.search_terms,
            include_variations=request.include_variations
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Discovery failed: {str(e)}")
    
    # Save netblocks to database
    created_count = 0
    for nb_data in discovery_result.get("netblocks", []):
        # Check if netblock already exists
        existing = db.query(Netblock).filter(
            Netblock.organization_id == request.organization_id,
            Netblock.inetnum == nb_data["inetnum"]
        ).first()
        
        if existing:
            # Update existing netblock
            existing.is_owned = nb_data["is_owned"]
            existing.ownership_confidence = nb_data["ownership_confidence"]
            existing.last_verified = datetime.utcnow()
        else:
            # Helper to convert empty strings to None
            def clean_str(val):
                if val is None or val == "":
                    return None
                return str(val) if val else None
            
            # Create new netblock
            netblock = Netblock(
                organization_id=request.organization_id,
                inetnum=nb_data["inetnum"],
                start_ip=nb_data["start_ip"],
                end_ip=nb_data["end_ip"],
                cidr_notation=clean_str(nb_data.get("cidr_notation")),
                ip_count=nb_data.get("ip_count", 0),
                ip_version=nb_data.get("ip_version", "ipv4"),
                is_owned=nb_data.get("is_owned", False),
                in_scope=nb_data.get("in_scope", True),
                ownership_confidence=nb_data.get("ownership_confidence", 0),
                asn=clean_str(nb_data.get("asn")),
                as_name=clean_str(nb_data.get("as_name")),
                as_type=clean_str(nb_data.get("as_type")),
                route=clean_str(nb_data.get("route")),
                as_domain=clean_str(nb_data.get("as_domain")),
                netname=clean_str(nb_data.get("netname")),
                nethandle=clean_str(nb_data.get("nethandle")),
                description=clean_str(nb_data.get("description")),
                country=clean_str(nb_data.get("country")),
                city=clean_str(nb_data.get("city")),
                address=clean_str(nb_data.get("address")),
                org_name=clean_str(nb_data.get("org_name")),
                org_email=clean_str(nb_data.get("org_email")),
                org_phone=clean_str(nb_data.get("org_phone")),
                org_country=clean_str(nb_data.get("org_country")),
                org_city=clean_str(nb_data.get("org_city")),
                org_postal_code=clean_str(nb_data.get("org_postal_code")),
                discovery_source="whoisxml",
            )
            db.add(netblock)
            created_count += 1
    
    db.commit()
    
    # Update API usage
    api_config.usage_count += 1
    api_config.last_used = datetime.utcnow()
    db.commit()
    
    return NetblockDiscoveryResponse(
        organization_id=request.organization_id,
        search_terms=request.search_terms,
        netblocks_found=discovery_result["total_found"],
        netblocks_created=created_count,
        owned_count=discovery_result["owned_count"],
        total_ips=discovery_result["total_ips"],
        details=[{
            "ipv4_count": discovery_result["ipv4_count"],
            "ipv6_count": discovery_result["ipv6_count"],
            "owned_ips": discovery_result["owned_ips"],
            "duplicates_removed": discovery_result["duplicates_removed"],
        }]
    )


@router.post("/", response_model=NetblockResponse, status_code=status.HTTP_201_CREATED)
def create_netblock(
    netblock_data: NetblockCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new netblock manually."""
    # Verify organization
    org = db.query(Organization).filter(Organization.id == netblock_data.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Check for duplicates
    existing = db.query(Netblock).filter(
        Netblock.organization_id == netblock_data.organization_id,
        Netblock.inetnum == netblock_data.inetnum
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail="Netblock already exists")
    
    netblock = Netblock(**netblock_data.model_dump())
    db.add(netblock)
    db.commit()
    db.refresh(netblock)
    
    return netblock


@router.get("/{netblock_id}", response_model=NetblockResponse)
def get_netblock(
    netblock_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get netblock by ID."""
    netblock = db.query(Netblock).filter(Netblock.id == netblock_id).first()
    
    if not netblock:
        raise HTTPException(status_code=404, detail="Netblock not found")
    
    # Check access
    if not current_user.is_superuser and current_user.organization_id != netblock.organization_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    return netblock


@router.put("/{netblock_id}", response_model=NetblockResponse)
def update_netblock(
    netblock_id: int,
    netblock_data: NetblockUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update netblock (primarily for toggling in_scope and is_owned flags)."""
    netblock = db.query(Netblock).filter(Netblock.id == netblock_id).first()
    
    if not netblock:
        raise HTTPException(status_code=404, detail="Netblock not found")
    
    # Update fields
    update_data = netblock_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(netblock, field, value)
    
    db.commit()
    db.refresh(netblock)
    
    return netblock


@router.put("/{netblock_id}/toggle-scope", response_model=NetblockResponse)
def toggle_netblock_scope(
    netblock_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Toggle the in_scope flag for a netblock."""
    netblock = db.query(Netblock).filter(Netblock.id == netblock_id).first()
    
    if not netblock:
        raise HTTPException(status_code=404, detail="Netblock not found")
    
    netblock.in_scope = not netblock.in_scope
    db.commit()
    db.refresh(netblock)
    
    return netblock


@router.put("/{netblock_id}/toggle-ownership", response_model=NetblockResponse)
def toggle_netblock_ownership(
    netblock_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Toggle the is_owned flag for a netblock."""
    netblock = db.query(Netblock).filter(Netblock.id == netblock_id).first()
    
    if not netblock:
        raise HTTPException(status_code=404, detail="Netblock not found")
    
    netblock.is_owned = not netblock.is_owned
    db.commit()
    db.refresh(netblock)
    
    return netblock


@router.delete("/{netblock_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_netblock(
    netblock_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete a netblock (admin only)."""
    netblock = db.query(Netblock).filter(Netblock.id == netblock_id).first()
    
    if not netblock:
        raise HTTPException(status_code=404, detail="Netblock not found")
    
    db.delete(netblock)
    db.commit()


@router.post("/bulk-scope", response_model=dict)
def bulk_update_scope(
    netblock_ids: List[int],
    in_scope: bool,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Bulk update in_scope flag for multiple netblocks."""
    updated = db.query(Netblock).filter(Netblock.id.in_(netblock_ids)).update(
        {Netblock.in_scope: in_scope},
        synchronize_session=False
    )
    db.commit()
    
    return {"updated": updated, "in_scope": in_scope}


