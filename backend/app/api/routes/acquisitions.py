"""API routes for M&A / Acquisitions management."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.db.database import get_db
from app.models.acquisition import Acquisition, AcquisitionStatus, AcquisitionType
from app.models.organization import Organization
from app.models.asset import Asset
from app.models.api_config import APIConfig
from app.models.user import User
from app.api.deps import get_current_active_user, require_analyst


router = APIRouter(prefix="/acquisitions", tags=["Acquisitions"])


# Pydantic schemas
class AcquisitionCreate(BaseModel):
    """Schema for creating an acquisition."""
    organization_id: int
    target_name: str = Field(..., min_length=1, max_length=255)
    target_domain: Optional[str] = None
    target_domains: List[str] = []
    target_description: Optional[str] = None
    target_industry: Optional[str] = None
    target_country: Optional[str] = None
    target_city: Optional[str] = None
    target_founded_year: Optional[int] = None
    target_employees: Optional[int] = None
    acquisition_type: AcquisitionType = AcquisitionType.ACQUISITION
    status: AcquisitionStatus = AcquisitionStatus.COMPLETED
    announced_date: Optional[datetime] = None
    closed_date: Optional[datetime] = None
    deal_value: Optional[float] = None
    deal_currency: str = "USD"
    website_url: Optional[str] = None
    linkedin_url: Optional[str] = None
    integration_notes: Optional[str] = None


class AcquisitionUpdate(BaseModel):
    """Schema for updating an acquisition."""
    target_name: Optional[str] = None
    target_domain: Optional[str] = None
    target_domains: Optional[List[str]] = None
    target_description: Optional[str] = None
    target_industry: Optional[str] = None
    target_country: Optional[str] = None
    status: Optional[AcquisitionStatus] = None
    is_integrated: Optional[bool] = None
    integration_notes: Optional[str] = None


class AcquisitionResponse(BaseModel):
    """Response schema for an acquisition."""
    id: int
    organization_id: int
    target_name: str
    target_domain: Optional[str]
    target_domains: List[str]
    target_description: Optional[str]
    target_industry: Optional[str]
    target_country: Optional[str]
    target_city: Optional[str]
    target_founded_year: Optional[int]
    target_employees: Optional[int]
    acquisition_type: str
    status: str
    announced_date: Optional[datetime]
    closed_date: Optional[datetime]
    deal_value: Optional[float]
    deal_currency: str
    is_integrated: bool
    integration_notes: Optional[str]
    domains_discovered: int
    domains_in_scope: int
    tracxn_id: Optional[str]
    website_url: Optional[str]
    linkedin_url: Optional[str]
    source: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


@router.get("/", response_model=List[AcquisitionResponse])
def list_acquisitions(
    organization_id: Optional[int] = None,
    status: Optional[AcquisitionStatus] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List acquisitions for an organization."""
    query = db.query(Acquisition)
    
    if organization_id:
        query = query.filter(Acquisition.organization_id == organization_id)
    
    if status:
        query = query.filter(Acquisition.status == status)
    
    acquisitions = query.order_by(Acquisition.announced_date.desc()).offset(skip).limit(limit).all()
    
    # Convert to response format
    return [
        AcquisitionResponse(
            id=a.id,
            organization_id=a.organization_id,
            target_name=a.target_name,
            target_domain=a.target_domain,
            target_domains=a.target_domains or [],
            target_description=a.target_description,
            target_industry=a.target_industry,
            target_country=a.target_country,
            target_city=a.target_city,
            target_founded_year=a.target_founded_year,
            target_employees=a.target_employees,
            acquisition_type=a.acquisition_type.value if a.acquisition_type else "unknown",
            status=a.status.value if a.status else "unknown",
            announced_date=a.announced_date,
            closed_date=a.closed_date,
            deal_value=a.deal_value,
            deal_currency=a.deal_currency or "USD",
            is_integrated=a.is_integrated or False,
            integration_notes=a.integration_notes,
            domains_discovered=a.domains_discovered or 0,
            domains_in_scope=a.domains_in_scope or 0,
            tracxn_id=a.tracxn_id,
            website_url=a.website_url,
            linkedin_url=a.linkedin_url,
            source=a.source or "manual",
            created_at=a.created_at,
            updated_at=a.updated_at,
        )
        for a in acquisitions
    ]


@router.get("/summary")
def get_acquisitions_summary(
    organization_id: int = 1,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get summary statistics for acquisitions."""
    acquisitions = db.query(Acquisition).filter(
        Acquisition.organization_id == organization_id
    ).all()
    
    total_domains = sum(a.domains_discovered or 0 for a in acquisitions)
    in_scope_domains = sum(a.domains_in_scope or 0 for a in acquisitions)
    
    return {
        "total_acquisitions": len(acquisitions),
        "completed": len([a for a in acquisitions if a.status == AcquisitionStatus.COMPLETED]),
        "pending": len([a for a in acquisitions if a.status == AcquisitionStatus.PENDING]),
        "integrated": len([a for a in acquisitions if a.is_integrated]),
        "total_domains_discovered": total_domains,
        "total_domains_in_scope": in_scope_domains,
    }


@router.get("/{acquisition_id}")
def get_acquisition(
    acquisition_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get a single acquisition by ID."""
    acquisition = db.query(Acquisition).filter(Acquisition.id == acquisition_id).first()
    
    if not acquisition:
        raise HTTPException(status_code=404, detail="Acquisition not found")
    
    return acquisition.to_dict()


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_acquisition(
    data: AcquisitionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new acquisition record."""
    # Verify organization exists
    org = db.query(Organization).filter(Organization.id == data.organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Check for duplicate
    existing = db.query(Acquisition).filter(
        Acquisition.organization_id == data.organization_id,
        Acquisition.target_name == data.target_name
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Acquisition '{data.target_name}' already exists"
        )
    
    acquisition = Acquisition(
        organization_id=data.organization_id,
        target_name=data.target_name,
        target_domain=data.target_domain,
        target_domains=data.target_domains or [],
        target_description=data.target_description,
        target_industry=data.target_industry,
        target_country=data.target_country,
        target_city=data.target_city,
        target_founded_year=data.target_founded_year,
        target_employees=data.target_employees,
        acquisition_type=data.acquisition_type,
        status=data.status,
        announced_date=data.announced_date,
        closed_date=data.closed_date,
        deal_value=data.deal_value,
        deal_currency=data.deal_currency,
        website_url=data.website_url,
        linkedin_url=data.linkedin_url,
        integration_notes=data.integration_notes,
        source="manual",
        domains_discovered=len(data.target_domains) if data.target_domains else 0,
    )
    
    db.add(acquisition)
    db.commit()
    db.refresh(acquisition)
    
    return acquisition.to_dict()


@router.put("/{acquisition_id}")
def update_acquisition(
    acquisition_id: int,
    data: AcquisitionUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update an acquisition record."""
    acquisition = db.query(Acquisition).filter(Acquisition.id == acquisition_id).first()
    
    if not acquisition:
        raise HTTPException(status_code=404, detail="Acquisition not found")
    
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(acquisition, field, value)
    
    if data.target_domains is not None:
        acquisition.domains_discovered = len(data.target_domains)
    
    db.commit()
    db.refresh(acquisition)
    
    return acquisition.to_dict()


@router.delete("/{acquisition_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_acquisition(
    acquisition_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete an acquisition record."""
    acquisition = db.query(Acquisition).filter(Acquisition.id == acquisition_id).first()
    
    if not acquisition:
        raise HTTPException(status_code=404, detail="Acquisition not found")
    
    db.delete(acquisition)
    db.commit()


@router.post("/{acquisition_id}/add-domain")
def add_domain_to_acquisition(
    acquisition_id: int,
    domain: str = Query(..., description="Domain to add"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Add a domain to an acquisition's domain list."""
    acquisition = db.query(Acquisition).filter(Acquisition.id == acquisition_id).first()
    
    if not acquisition:
        raise HTTPException(status_code=404, detail="Acquisition not found")
    
    acquisition.add_domain(domain)
    db.commit()
    db.refresh(acquisition)
    
    return {
        "message": f"Domain '{domain}' added to acquisition",
        "domains": acquisition.target_domains,
        "domains_discovered": acquisition.domains_discovered
    }


@router.post("/import-from-tracxn")
async def import_from_tracxn(
    organization_id: int = 1,
    organization_name: str = Query(..., description="Acquirer name to search"),
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Import acquisitions from Tracxn API.
    
    Requires Tracxn API key to be configured in settings.
    """
    from app.services.tracxn_service import fetch_acquisitions_for_org
    
    # Get Tracxn API key
    tracxn_config = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.service_name == "tracxn"
    ).first()
    
    api_key = tracxn_config.get_api_key() if tracxn_config else None
    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="Tracxn API key not configured. Add it in Settings > External Discovery."
        )
    
    # Fetch acquisitions from Tracxn
    result = await fetch_acquisitions_for_org(
        org_name=organization_name,
        api_key=api_key,
        limit=limit
    )
    
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    
    imported = 0
    skipped = 0
    acquisitions_data = result.get("acquisitions", [])
    
    for acq_data in acquisitions_data:
        # Check if already exists
        existing = None
        if acq_data.get("tracxn_id"):
            existing = db.query(Acquisition).filter(
                Acquisition.tracxn_id == acq_data["tracxn_id"]
            ).first()
        
        if not existing:
            existing = db.query(Acquisition).filter(
                Acquisition.organization_id == organization_id,
                Acquisition.target_name == acq_data.get("target_name")
            ).first()
        
        if existing:
            skipped += 1
            continue
        
        # Create new acquisition
        acquisition = Acquisition(
            organization_id=organization_id,
            target_name=acq_data.get("target_name"),
            target_domain=acq_data.get("target_domain"),
            target_domains=[acq_data["target_domain"]] if acq_data.get("target_domain") else [],
            target_description=acq_data.get("target_description"),
            target_industry=acq_data.get("target_industry"),
            target_country=acq_data.get("target_country"),
            target_city=acq_data.get("target_city"),
            target_founded_year=acq_data.get("target_founded_year"),
            target_employees=acq_data.get("target_employees"),
            acquisition_type=AcquisitionType.ACQUISITION,
            status=AcquisitionStatus.COMPLETED,
            announced_date=acq_data.get("announced_date"),
            closed_date=acq_data.get("closed_date"),
            deal_value=acq_data.get("deal_value"),
            deal_currency=acq_data.get("deal_currency", "USD"),
            tracxn_id=acq_data.get("tracxn_id"),
            website_url=acq_data.get("website_url"),
            linkedin_url=acq_data.get("linkedin_url"),
            source="tracxn",
            metadata_={"raw": acq_data.get("raw_data", {})},
            domains_discovered=1 if acq_data.get("target_domain") else 0,
        )
        
        db.add(acquisition)
        imported += 1
    
    db.commit()
    
    return {
        "message": f"Import complete",
        "organization": organization_name,
        "total_found": len(acquisitions_data),
        "imported": imported,
        "skipped": skipped,
    }


@router.post("/{acquisition_id}/discover-domains")
async def discover_domains_for_acquisition(
    acquisition_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Discover domains related to an acquisition using Whoxy reverse WHOIS.
    
    Uses the target domain's registrant information to find related domains.
    """
    acquisition = db.query(Acquisition).filter(Acquisition.id == acquisition_id).first()
    
    if not acquisition:
        raise HTTPException(status_code=404, detail="Acquisition not found")
    
    if not acquisition.target_domain:
        raise HTTPException(
            status_code=400, 
            detail="Acquisition has no target domain set. Add a domain first."
        )
    
    # Get Whoxy API key
    whoxy_config = db.query(APIConfig).filter(
        APIConfig.organization_id == acquisition.organization_id,
        APIConfig.service_name == "whoxy"
    ).first()
    
    whoxy_api_key = whoxy_config.get_api_key() if whoxy_config else None
    if not whoxy_api_key:
        raise HTTPException(
            status_code=400,
            detail="Whoxy API key not configured. Add it in Settings > External Discovery."
        )
    
    from app.services.whoxy_service import WhoxyService
    
    service = WhoxyService(whoxy_api_key)
    
    # First get WHOIS data for the target domain
    whois_data = await service.get_domain_whois(acquisition.target_domain)
    
    if "error" in whois_data:
        return {
            "message": "Could not fetch WHOIS data",
            "error": whois_data.get("error"),
            "domains_found": 0
        }
    
    # Extract registrant email for reverse lookup
    registrant_email = whois_data.get("registrant_email")
    
    if not registrant_email:
        return {
            "message": "No registrant email found in WHOIS data",
            "domains_found": 0
        }
    
    # Do reverse WHOIS by email
    reverse_result = await service.reverse_whois_by_email(registrant_email)
    
    domains_found = reverse_result.get("domains", [])
    
    # Add domains to acquisition
    for domain_data in domains_found:
        domain_name = domain_data.get("domain_name") or domain_data.get("domain")
        if domain_name:
            acquisition.add_domain(domain_name)
    
    # Also create assets for discovered domains
    assets_created = 0
    for domain_data in domains_found:
        domain_name = domain_data.get("domain_name") or domain_data.get("domain")
        if not domain_name:
            continue
        
        # Check if asset already exists
        existing = db.query(Asset).filter(
            Asset.organization_id == acquisition.organization_id,
            Asset.value == domain_name
        ).first()
        
        if not existing:
            from app.models.asset import AssetType, AssetStatus
            
            asset = Asset(
                organization_id=acquisition.organization_id,
                name=domain_name,
                value=domain_name,
                asset_type=AssetType.DOMAIN,
                status=AssetStatus.DISCOVERED,
                discovery_source=f"acquisition:{acquisition.target_name}",
                association_reason=f"M&A: {acquisition.target_name}",
                in_scope=True,
                metadata_={
                    "acquisition_id": acquisition.id,
                    "acquisition_name": acquisition.target_name,
                    "whoxy_data": domain_data
                }
            )
            db.add(asset)
            assets_created += 1
    
    acquisition.domains_in_scope = assets_created
    db.commit()
    db.refresh(acquisition)
    
    return {
        "message": f"Domain discovery complete for {acquisition.target_name}",
        "registrant_email": registrant_email,
        "domains_found": len(domains_found),
        "domains_total": acquisition.domains_discovered,
        "assets_created": assets_created,
        "target_domains": acquisition.target_domains
    }


@router.get("/{acquisition_id}/assets")
def get_acquisition_assets(
    acquisition_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get all assets linked to an acquisition."""
    acquisition = db.query(Acquisition).filter(Acquisition.id == acquisition_id).first()
    
    if not acquisition:
        raise HTTPException(status_code=404, detail="Acquisition not found")
    
    # Find assets by acquisition metadata or by domain matching
    assets = db.query(Asset).filter(
        Asset.organization_id == acquisition.organization_id,
        Asset.value.in_(acquisition.target_domains or [])
    ).all()
    
    return {
        "acquisition_id": acquisition_id,
        "acquisition_name": acquisition.target_name,
        "total_assets": len(assets),
        "assets": [
            {
                "id": a.id,
                "name": a.name,
                "value": a.value,
                "asset_type": a.asset_type.value if a.asset_type else None,
                "in_scope": a.in_scope,
                "is_live": a.is_live,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in assets
        ]
    }
