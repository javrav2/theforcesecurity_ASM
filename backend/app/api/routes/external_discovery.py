"""
API routes for external discovery services.

Provides endpoints to:
- Configure API keys for external services
- Run discovery using external intelligence sources
- View available services and their status
"""

import time
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_active_user, require_analyst, require_admin
from app.models.user import User
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.api_config import APIConfig, ExternalService
from app.schemas.external_discovery import (
    APIConfigCreate,
    APIConfigUpdate,
    APIConfigResponse,
    APIConfigListResponse,
    ExternalDiscoveryRequest,
    ExternalDiscoveryResponse,
    SingleSourceRequest,
    SingleSourceResponse,
    SourceResult,
    AvailableServicesResponse,
    PAID_SERVICES_INFO,
    FREE_SERVICES_INFO,
)
from app.services.external_discovery_service import ExternalDiscoveryService
from app.services.technology_scan_service import run_technology_scan_for_hosts

router = APIRouter(prefix="/external-discovery", tags=["external-discovery"])


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.role.value == "admin":
        return True
    return user.organization_id == org_id


def mask_api_key(key: str) -> str:
    """Mask API key for display."""
    if not key:
        return None
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


# =============================================================================
# API Configuration Management
# =============================================================================

@router.get("/services", response_model=AvailableServicesResponse)
def list_available_services(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all available external discovery services."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Get configured services
    configs = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.is_active == True
    ).all()
    
    configured = [c.service_name for c in configs]
    
    return AvailableServicesResponse(
        paid_services=PAID_SERVICES_INFO,
        free_services=FREE_SERVICES_INFO,
        configured_services=configured
    )


@router.get("/configs/{organization_id}", response_model=APIConfigListResponse)
def list_api_configs(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all API configurations for an organization."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    configs = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id
    ).all()
    
    # All available service names
    available = [s["name"] for s in PAID_SERVICES_INFO]
    
    responses = []
    for config in configs:
        resp = APIConfigResponse(
            id=config.id,
            organization_id=config.organization_id,
            service_name=config.service_name,
            api_user=config.api_user,
            config=config.config,
            is_active=config.is_active,
            is_valid=config.is_valid,
            last_used=config.last_used,
            usage_count=config.usage_count,
            daily_usage=config.daily_usage,
            last_error=config.last_error,
            created_at=config.created_at,
            updated_at=config.updated_at,
            api_key_masked=mask_api_key(config.get_api_key()) if config.api_key_encrypted else None
        )
        responses.append(resp)
    
    return APIConfigListResponse(
        configs=responses,
        available_services=available
    )


@router.post("/configs/{organization_id}", response_model=APIConfigResponse)
def create_api_config(
    organization_id: int,
    config: APIConfigCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create or update an API configuration."""
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Check if config already exists for this service
    existing = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.service_name == config.service_name
    ).first()
    
    if existing:
        # Update existing
        existing.set_api_key(config.api_key)
        if config.api_user:
            existing.api_user = config.api_user
        if config.api_secret:
            existing.set_api_secret(config.api_secret)
        if config.config:
            existing.config = config.config
        existing.is_active = True
        existing.is_valid = True
        existing.last_error = None
        db.commit()
        db.refresh(existing)
        db_config = existing
    else:
        # Create new
        db_config = APIConfig(
            organization_id=organization_id,
            service_name=config.service_name,
            api_user=config.api_user,
            config=config.config or {}
        )
        db_config.set_api_key(config.api_key)
        if config.api_secret:
            db_config.set_api_secret(config.api_secret)
        
        db.add(db_config)
        db.commit()
        db.refresh(db_config)
    
    return APIConfigResponse(
        id=db_config.id,
        organization_id=db_config.organization_id,
        service_name=db_config.service_name,
        api_user=db_config.api_user,
        config=db_config.config,
        is_active=db_config.is_active,
        is_valid=db_config.is_valid,
        last_used=db_config.last_used,
        usage_count=db_config.usage_count,
        daily_usage=db_config.daily_usage,
        last_error=db_config.last_error,
        created_at=db_config.created_at,
        updated_at=db_config.updated_at,
        api_key_masked=mask_api_key(db_config.get_api_key())
    )


@router.put("/configs/{config_id}", response_model=APIConfigResponse)
def update_api_config(
    config_id: int,
    updates: APIConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Update an API configuration."""
    config = db.query(APIConfig).filter(APIConfig.id == config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Config not found")
    
    if not check_org_access(current_user, config.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    if updates.api_key:
        config.set_api_key(updates.api_key)
    if updates.api_user is not None:
        config.api_user = updates.api_user
    if updates.api_secret:
        config.set_api_secret(updates.api_secret)
    if updates.config is not None:
        config.config = updates.config
    if updates.is_active is not None:
        config.is_active = updates.is_active
    
    db.commit()
    db.refresh(config)
    
    return APIConfigResponse(
        id=config.id,
        organization_id=config.organization_id,
        service_name=config.service_name,
        api_user=config.api_user,
        config=config.config,
        is_active=config.is_active,
        is_valid=config.is_valid,
        last_used=config.last_used,
        usage_count=config.usage_count,
        daily_usage=config.daily_usage,
        last_error=config.last_error,
        created_at=config.created_at,
        updated_at=config.updated_at,
        api_key_masked=mask_api_key(config.get_api_key())
    )


@router.delete("/configs/{config_id}")
def delete_api_config(
    config_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete an API configuration."""
    config = db.query(APIConfig).filter(APIConfig.id == config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Config not found")
    
    if not check_org_access(current_user, config.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    db.delete(config)
    db.commit()
    
    return {"message": "Config deleted successfully"}


# =============================================================================
# External Discovery
# =============================================================================

@router.post("/run", response_model=ExternalDiscoveryResponse)
async def run_external_discovery(
    request: ExternalDiscoveryRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run external discovery for a domain using all available sources.
    
    This will query multiple external services to discover:
    - Subdomains (crt.sh, VirusTotal, OTX, Wayback, RapidDNS)
    - Related domains (M365 federation, Whoxy reverse WHOIS)
    - IP ranges (WhoisXML by organization name)
    
    Example domain: rockwellautomation.com
    """
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    start_time = time.time()
    
    # Initialize discovery service
    service = ExternalDiscoveryService(db, request.organization_id)
    
    # Run full discovery
    results = await service.full_discovery(
        domain=request.domain,
        include_paid=request.include_paid_sources,
        include_free=request.include_free_sources,
        organization_names=request.organization_names,
        registration_emails=request.registration_emails
    )
    
    # Aggregate results
    aggregated = service.aggregate_results(results, request.domain)
    
    # Build source results
    source_results = []
    for source, result in results.items():
        source_results.append(SourceResult(
            source=result.source,
            success=result.success,
            domains_found=len(result.domains),
            subdomains_found=len(result.subdomains),
            ips_found=len(result.ip_addresses),
            cidrs_found=len(result.ip_ranges),
            elapsed_time=result.elapsed_time,
            error=result.error
        ))
    
    # Create assets if requested
    assets_created = 0
    assets_skipped = 0
    created_hosts: list[str] = []
    
    if request.create_assets:
        # Create domain assets
        for domain in aggregated["domains"]:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == domain,
                Asset.asset_type == AssetType.DOMAIN
            ).first()
            
            if existing:
                if request.skip_existing:
                    assets_skipped += 1
                    continue
            else:
                asset = Asset(
                    name=domain,
                    asset_type=AssetType.DOMAIN,
                    value=domain,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source="external_discovery",
                    tags=["external-discovery"],
                )
                db.add(asset)
                assets_created += 1
                created_hosts.append(domain)
        
        # Create subdomain assets
        for subdomain in aggregated["subdomains"]:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == subdomain,
                Asset.asset_type == AssetType.SUBDOMAIN
            ).first()
            
            if existing:
                if request.skip_existing:
                    assets_skipped += 1
                    continue
            else:
                asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    value=subdomain,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source="external_discovery",
                    tags=["external-discovery"],
                )
                db.add(asset)
                assets_created += 1
                created_hosts.append(subdomain)
        
        # Create IP assets
        for ip in aggregated["ip_addresses"]:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == ip,
                Asset.asset_type == AssetType.IP_ADDRESS
            ).first()
            
            if existing:
                if request.skip_existing:
                    assets_skipped += 1
                    continue
            else:
                asset = Asset(
                    name=ip,
                    asset_type=AssetType.IP_ADDRESS,
                    value=ip,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source="external_discovery",
                    tags=["external-discovery"],
                )
                db.add(asset)
                assets_created += 1
        
        # Create IP range assets
        for cidr in aggregated["ip_ranges"]:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == cidr,
                Asset.asset_type == AssetType.IP_RANGE
            ).first()
            
            if existing:
                if request.skip_existing:
                    assets_skipped += 1
                    continue
            else:
                asset = Asset(
                    name=cidr,
                    asset_type=AssetType.IP_RANGE,
                    value=cidr,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source="external_discovery",
                    tags=["external-discovery"],
                )
                db.add(asset)
                assets_created += 1
        
        db.commit()

        # Optional: schedule lightweight tech scan on a subset of newly created hosts
        if request.run_technology_scan and created_hosts:
            background_tasks.add_task(
                run_technology_scan_for_hosts,
                organization_id=request.organization_id,
                hosts=created_hosts,
                max_hosts=request.max_technology_scan,
            )
    
    return ExternalDiscoveryResponse(
        domain=request.domain,
        organization_id=request.organization_id,
        total_domains=len(aggregated["domains"]),
        total_subdomains=len(aggregated["subdomains"]),
        total_ips=len(aggregated["ip_addresses"]),
        total_cidrs=len(aggregated["ip_ranges"]),
        source_results=source_results,
        domains=list(aggregated["domains"]),
        subdomains=list(aggregated["subdomains"]),
        ip_addresses=list(aggregated["ip_addresses"]),
        ip_ranges=list(aggregated["ip_ranges"]),
        assets_created=assets_created,
        assets_skipped=assets_skipped,
        total_elapsed_time=time.time() - start_time
    )


@router.post("/run/source", response_model=SingleSourceResponse)
async def run_single_source(
    request: SingleSourceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run discovery using a single external source.
    
    Available sources:
    - crtsh: Certificate transparency logs
    - virustotal: VirusTotal subdomain database
    - otx: AlienVault OTX passive DNS
    - wayback: Wayback Machine historical data
    - rapiddns: RapidDNS subdomain lookup
    - m365: Microsoft 365 federation discovery
    """
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    service = ExternalDiscoveryService(db, request.organization_id)
    
    # Map source names to methods
    source_methods = {
        "crtsh": service.discover_crtsh,
        "virustotal": service.discover_virustotal,
        "otx": service.discover_otx,
        "wayback": service.discover_wayback,
        "rapiddns": service.discover_rapiddns,
        "m365": service.discover_m365,
    }
    
    if request.source not in source_methods:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown source: {request.source}. Available: {list(source_methods.keys())}"
        )
    
    # Run the source
    result = await source_methods[request.source](request.domain)
    
    # Create assets if requested
    assets_created = 0
    if request.create_assets and result.success:
        for subdomain in result.subdomains:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == subdomain
            ).first()
            
            if not existing:
                asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    value=subdomain,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source=request.source,
                    tags=[f"source:{request.source}"],
                )
                db.add(asset)
                assets_created += 1
        
        for domain in result.domains:
            existing = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == domain
            ).first()
            
            if not existing:
                asset = Asset(
                    name=domain,
                    asset_type=AssetType.DOMAIN,
                    value=domain,
                    organization_id=request.organization_id,
                    status=AssetStatus.DISCOVERED,
                    discovery_source=request.source,
                    tags=[f"source:{request.source}"],
                )
                db.add(asset)
                assets_created += 1
        
        db.commit()
    
    return SingleSourceResponse(
        source=result.source,
        domain=request.domain,
        success=result.success,
        domains=result.domains,
        subdomains=result.subdomains,
        ip_addresses=result.ip_addresses,
        ip_ranges=result.ip_ranges,
        error=result.error,
        elapsed_time=result.elapsed_time,
        assets_created=assets_created
    )


@router.post("/test/{service_name}")
async def test_api_config(
    service_name: str,
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Test an API configuration by making a simple request.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    config = db.query(APIConfig).filter(
        APIConfig.organization_id == organization_id,
        APIConfig.service_name == service_name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail="API config not found")
    
    service = ExternalDiscoveryService(db, organization_id)
    
    # Test with a simple domain
    test_domain = "example.com"
    
    test_methods = {
        "virustotal": lambda: service.discover_virustotal(test_domain),
        "otx": lambda: service.discover_otx(test_domain),
    }
    
    if service_name not in test_methods:
        return {
            "service": service_name,
            "success": True,
            "message": "API key stored (no test available for this service)"
        }
    
    result = await test_methods[service_name]()
    
    # Update config validity
    config.is_valid = result.success
    if not result.success:
        config.last_error = result.error
    else:
        config.last_error = None
    db.commit()
    
    return {
        "service": service_name,
        "success": result.success,
        "error": result.error,
        "message": "API key is valid" if result.success else f"API key test failed: {result.error}"
    }















