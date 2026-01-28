"""Discovery routes for attack surface management."""

import asyncio
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User
from app.models.organization import Organization
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.asset import Asset, AssetType, AssetStatus
from app.schemas.discovery import (
    DiscoveryRequest,
    DiscoveryResultResponse,
    DiscoveryProgressResponse,
    TechnologyScanRequest,
    TechnologyScanResultResponse,
    DNSRecordResponse,
    SubdomainResponse
)
from app.services.discovery_service import DiscoveryService
from app.services.dns_service import DNSService
from app.services.subdomain_service import SubdomainService
from app.services.wappalyzer_service import WappalyzerService
from app.api.deps import get_current_active_user, require_analyst

router = APIRouter(prefix="/discovery", tags=["Discovery"])


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.is_superuser:
        return True
    return user.organization_id == org_id


@router.post("/full", response_model=DiscoveryResultResponse)
async def start_full_discovery(
    request: DiscoveryRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Start a full discovery scan for a domain.
    
    This will:
    1. Enumerate DNS records for the domain
    2. Discover subdomains via certificate transparency and brute-forcing
    3. Resolve all hosts to IP addresses
    4. Probe HTTP/HTTPS endpoints
    5. Fingerprint technologies using Wappalyzer patterns
    
    Example: Discover attack surface for rockwellautomation.com
    """
    # Check organization access
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Verify organization exists
    org = db.query(Organization).filter(Organization.id == request.organization_id).first()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization not found"
        )
    
    # Create scan record
    scan = Scan(
        name=f"Discovery: {request.domain}",
        scan_type=ScanType.DISCOVERY,
        organization_id=request.organization_id,
        targets=[request.domain],
        config={
            "include_subdomains": request.include_subdomains,
            "include_technology_scan": request.include_technology_scan
        },
        started_by=current_user.username,
        status=ScanStatus.PENDING
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Run discovery (for smaller domains, run synchronously for immediate results)
    # For production, use background_tasks or Celery
    discovery_service = DiscoveryService(db)
    
    try:
        result = await discovery_service.discover_domain(
            domain=request.domain,
            organization_id=request.organization_id,
            scan_id=scan.id,
            include_technology_scan=request.include_technology_scan,
            subdomain_wordlist=request.custom_wordlist
        )
        
        return DiscoveryResultResponse(
            success=result.success,
            domain=result.domain,
            scan_id=scan.id,
            duration_seconds=result.duration_seconds,
            assets_discovered=len(result.assets),
            technologies_detected=len(result.technologies),
            errors=result.errors,
            summary={
                "total_assets": len(result.assets),
                "total_technologies": len(result.technologies),
                "asset_types": _count_asset_types(result.assets)
            }
        )
        
    except Exception as e:
        # Update scan as failed
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Discovery failed: {str(e)}"
        )


@router.get("/progress/{scan_id}", response_model=DiscoveryProgressResponse)
def get_discovery_progress(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get progress of a running discovery scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if not check_org_access(current_user, scan.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return DiscoveryProgressResponse(
        scan_id=scan.id,
        current_step=scan.current_step or "",
        progress=scan.progress,
        assets_found=scan.assets_discovered,
        technologies_found=scan.technologies_found,
        errors=[]
    )


@router.post("/dns/{domain}", response_model=List[DNSRecordResponse])
def enumerate_dns(
    domain: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Enumerate DNS records for a domain.
    
    Returns A, AAAA, MX, NS, TXT, CNAME, and SOA records.
    """
    dns_service = DNSService()
    records = dns_service.enumerate_domain(domain)
    
    result = []
    dns_dict = records.to_dict()
    
    for record_type, values in dns_dict.items():
        if values:
            result.append(DNSRecordResponse(
                record_type=record_type,
                values=values if isinstance(values, list) else [values]
            ))
    
    return result


@router.post("/subdomains/{domain}", response_model=List[SubdomainResponse])
async def enumerate_subdomains(
    domain: str,
    use_crtsh: bool = True,
    organization_id: Optional[int] = None,
    create_assets: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Enumerate subdomains for a domain.
    
    Uses certificate transparency logs (crt.sh) and common subdomain brute-forcing.
    
    If organization_id is provided and create_assets is True (default), discovered
    subdomains will be automatically added to the assets table.
    """
    from app.api.routes.external_discovery import extract_root_domain
    
    subdomain_service = SubdomainService()
    results = await subdomain_service.enumerate_subdomains(
        domain=domain,
        use_crtsh=use_crtsh
    )
    
    # Create assets for discovered subdomains if organization_id is provided
    assets_created = 0
    if organization_id and create_assets:
        # First, ensure the parent domain exists as an asset
        parent_domain_asset = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.value == domain,
            Asset.asset_type == AssetType.DOMAIN
        ).first()
        
        if not parent_domain_asset:
            # Create the parent domain asset
            parent_domain_asset = Asset(
                name=domain,
                asset_type=AssetType.DOMAIN,
                value=domain,
                root_domain=extract_root_domain(domain),
                organization_id=organization_id,
                status=AssetStatus.DISCOVERED,
                discovery_source="subdomain_enumeration",
                tags=["discovery"],
            )
            db.add(parent_domain_asset)
            db.commit()
            db.refresh(parent_domain_asset)
            assets_created += 1
        
        # Create subdomain assets
        for r in results:
            if r.subdomain == domain:
                continue  # Skip the parent domain itself
                
            existing = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == r.subdomain,
                Asset.asset_type == AssetType.SUBDOMAIN
            ).first()
            
            if not existing:
                subdomain_asset = Asset(
                    name=r.subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    value=r.subdomain,
                    root_domain=extract_root_domain(r.subdomain),
                    organization_id=organization_id,
                    parent_id=parent_domain_asset.id,
                    status=AssetStatus.VERIFIED if r.is_alive else AssetStatus.DISCOVERED,
                    discovery_source=r.source,
                    tags=["discovery", "subdomain-enum"],
                )
                # Store resolved IPs
                if r.ip_addresses:
                    subdomain_asset.ip_address = r.ip_addresses[0]
                    subdomain_asset.ip_addresses = r.ip_addresses
                    if not subdomain_asset.metadata_:
                        subdomain_asset.metadata_ = {}
                    subdomain_asset.metadata_["dns_resolved_at"] = datetime.utcnow().isoformat()
                
                db.add(subdomain_asset)
                assets_created += 1
        
        if assets_created > 0:
            db.commit()
    
    return [
        SubdomainResponse(
            subdomain=r.subdomain,
            ip_addresses=r.ip_addresses,
            source=r.source,
            is_alive=r.is_alive
        )
        for r in results
    ]


@router.post("/technology", response_model=List[TechnologyScanResultResponse])
async def scan_technologies(
    request: TechnologyScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Scan URLs for web technologies using Wappalyzer patterns.
    
    Detects CMS, frameworks, JavaScript libraries, analytics tools, and more.
    """
    wappalyzer = WappalyzerService()
    results = []
    
    for url in request.urls:
        try:
            technologies = await wappalyzer.analyze_url(url)
            results.append(TechnologyScanResultResponse(
                url=url,
                technologies=[
                    {
                        "name": t.name,
                        "slug": t.slug,
                        "version": t.version,
                        "confidence": t.confidence,
                        "categories": t.categories,
                        "website": t.website,
                        "cpe": t.cpe
                    }
                    for t in technologies
                ]
            ))
        except Exception as e:
            results.append(TechnologyScanResultResponse(
                url=url,
                technologies=[],
                error=str(e)
            ))
    
    return results


@router.get("/assets/{domain}/technologies")
def get_domain_technologies(
    domain: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all technologies detected for a domain and its assets.
    """
    # Find the domain asset
    domain_asset = db.query(Asset).filter(
        Asset.asset_type == AssetType.DOMAIN,
        Asset.value == domain
    ).first()
    
    if not domain_asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found"
        )
    
    if not check_org_access(current_user, domain_asset.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Get all child assets with technologies
    all_techs = {}
    
    def collect_technologies(asset):
        for tech in asset.technologies:
            if tech.name not in all_techs:
                all_techs[tech.name] = {
                    "name": tech.name,
                    "slug": tech.slug,
                    "categories": tech.categories,
                    "cpe": tech.cpe,
                    "found_on": []
                }
            all_techs[tech.name]["found_on"].append(asset.value)
        
        for child in asset.children:
            collect_technologies(child)
    
    collect_technologies(domain_asset)
    
    return {
        "domain": domain,
        "total_technologies": len(all_techs),
        "technologies": list(all_techs.values())
    }


def _count_asset_types(assets: list) -> dict:
    """Count assets by type."""
    counts = {}
    for asset in assets:
        asset_type = asset.get("type", "unknown")
        counts[asset_type] = counts.get(asset_type, 0) + 1
    return counts


@router.post("/login-portals")
async def detect_login_portals(
    domain: str,
    organization_id: int = 1,
    include_subdomains: bool = True,
    use_wayback: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Detect login portals, admin panels, and authentication endpoints.
    
    This scans a domain for:
    - Login pages (/login, /signin, /auth)
    - Admin panels (/admin, /wp-admin, /administrator)
    - Webmail portals (/webmail, /owa)
    - API authentication endpoints
    - Database admin tools (phpMyAdmin, etc.)
    
    Uses:
    - Subfinder for subdomain enumeration
    - HTTPX for probing live hosts
    - Waybackurls for historical URL discovery
    - Pattern matching for login-related paths
    """
    from app.services.login_portal_service import scan_domain_for_login_portals
    
    # Verify organization exists
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    # Run the scan
    result = await scan_domain_for_login_portals(
        domain=domain,
        include_subdomains=include_subdomains,
        use_wayback=use_wayback
    )
    
    # Store detected portals as assets with metadata
    if result.get("portals"):
        for portal in result["portals"]:
            # Check if asset already exists
            existing = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == portal.get("url")
            ).first()
            
            if not existing:
                asset = Asset(
                    organization_id=organization_id,
                    value=portal.get("url"),
                    asset_type=AssetType.URL,
                    hostname=domain,
                    is_active=portal.get("verified", False),
                    discovery_method="login_portal_scan",
                    metadata_={
                        "portal_type": portal.get("portal_type"),
                        "status_code": portal.get("status_code"),
                        "title": portal.get("title"),
                        "detected_at": portal.get("detected_at"),
                        "is_login_portal": True
                    }
                )
                db.add(asset)
        
        db.commit()
    
    return {
        "success": True,
        "domain": domain,
        "portals_found": result.get("login_portals_found", 0),
        "portals": result.get("portals", []),
        "stats": {
            "subdomains_checked": result.get("total_subdomains", 0),
            "live_hosts": result.get("live_hosts", 0),
            "wayback_urls_checked": result.get("wayback_urls", 0),
            "elapsed_seconds": result.get("elapsed_seconds", 0)
        }
    }


@router.get("/login-portals/{organization_id}")
async def get_login_portals(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all detected login portals for an organization.
    """
    portals = db.query(Asset).filter(
        Asset.organization_id == organization_id,
        Asset.metadata_.contains({"is_login_portal": True})
    ).all()
    
    result = []
    for portal in portals:
        metadata = portal.metadata_ or {}
        result.append({
            "id": portal.id,
            "url": portal.value,
            "hostname": portal.hostname,
            "portal_type": metadata.get("portal_type", "Unknown"),
            "status_code": metadata.get("status_code"),
            "title": metadata.get("title"),
            "is_active": portal.is_active,
            "detected_at": metadata.get("detected_at"),
            "first_seen": portal.first_seen.isoformat() if portal.first_seen else None
        })
    
    # Group by portal type
    by_type = {}
    for p in result:
        ptype = p["portal_type"]
        if ptype not in by_type:
            by_type[ptype] = []
        by_type[ptype].append(p)
    
    return {
        "total": len(result),
        "by_type": by_type,
        "portals": result
    }
