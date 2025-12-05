"""Nuclei and ProjectDiscovery tools routes."""

import asyncio
from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.user import User
from app.models.organization import Organization
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.scan_profile import ScanProfile, ProfileType, DEFAULT_PROFILES
from app.models.asset import Asset, AssetType
from app.models.vulnerability import Vulnerability, Severity, VulnerabilityStatus
from app.schemas.scan_profile import (
    ScanProfileCreate,
    ScanProfileUpdate,
    ScanProfileResponse,
    NucleiScanRequest,
    NucleiScanResultResponse,
    NucleiFindingResponse,
    ToolStatusResponse
)
from app.services.nuclei_service import NucleiService, SEVERITY_RISK_SCORES
from app.services.nuclei_findings_service import NucleiFindingsService
from app.services.projectdiscovery_service import ProjectDiscoveryService
from app.api.deps import get_current_active_user, require_analyst, require_admin

router = APIRouter(prefix="/nuclei", tags=["Nuclei & ProjectDiscovery"])


def check_org_access(user: User, org_id: int) -> bool:
    """Check if user has access to organization."""
    if user.is_superuser:
        return True
    return user.organization_id == org_id


# ==================== TOOL STATUS ====================

@router.get("/tools/status", response_model=ToolStatusResponse)
def check_tool_status(
    current_user: User = Depends(get_current_active_user)
):
    """Check which ProjectDiscovery tools are installed."""
    nuclei = NucleiService()
    pd_tools = ProjectDiscoveryService()
    
    pd_status = pd_tools.check_tools()
    
    return ToolStatusResponse(
        nuclei=nuclei.check_installation(),
        subfinder=pd_status.get("subfinder", False),
        httpx=pd_status.get("httpx", False),
        dnsx=pd_status.get("dnsx", False),
        naabu=pd_status.get("naabu", False),
        katana=pd_status.get("katana", False),
    )


@router.post("/tools/update-templates")
def update_nuclei_templates(
    current_user: User = Depends(require_admin)
):
    """Update Nuclei templates to latest version."""
    nuclei = NucleiService()
    success = nuclei.update_templates()
    
    if success:
        return {"message": "Nuclei templates updated successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update Nuclei templates"
        )


# ==================== SCAN PROFILES ====================

@router.get("/profiles", response_model=List[ScanProfileResponse])
def list_scan_profiles(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all scan profiles."""
    query = db.query(ScanProfile)
    if not include_inactive:
        query = query.filter(ScanProfile.is_active == True)
    
    profiles = query.all()
    
    # Create default profiles if none exist
    if not profiles:
        for profile_data in DEFAULT_PROFILES:
            profile = ScanProfile(**profile_data)
            db.add(profile)
        db.commit()
        profiles = db.query(ScanProfile).all()
    
    return profiles


@router.post("/profiles", response_model=ScanProfileResponse, status_code=status.HTTP_201_CREATED)
def create_scan_profile(
    profile_data: ScanProfileCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Create a new scan profile."""
    # Check for duplicate name
    existing = db.query(ScanProfile).filter(ScanProfile.name == profile_data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Profile with this name already exists"
        )
    
    profile = ScanProfile(**profile_data.model_dump())
    db.add(profile)
    db.commit()
    db.refresh(profile)
    
    return profile


@router.get("/profiles/{profile_id}", response_model=ScanProfileResponse)
def get_scan_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get scan profile by ID."""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Profile not found"
        )
    
    return profile


@router.put("/profiles/{profile_id}", response_model=ScanProfileResponse)
def update_scan_profile(
    profile_id: int,
    profile_data: ScanProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Update a scan profile."""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Profile not found"
        )
    
    update_data = profile_data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(profile, field, value)
    
    db.commit()
    db.refresh(profile)
    
    return profile


@router.delete("/profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan_profile(
    profile_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """Delete a scan profile."""
    profile = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Profile not found"
        )
    
    if profile.is_default:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete default profile"
        )
    
    db.delete(profile)
    db.commit()
    
    return None


# ==================== NUCLEI SCANS ====================

@router.post("/scan", response_model=NucleiScanResultResponse)
async def run_nuclei_scan(
    request: NucleiScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Run a Nuclei vulnerability scan.
    
    This will:
    1. Scan all specified targets using Nuclei
    2. Create vulnerability records for findings
    3. Add labels/tags to associated assets
    4. Return a summary of results
    """
    # Check organization access
    if not check_org_access(current_user, request.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Get scan profile
    profile = None
    if request.profile_id:
        profile = db.query(ScanProfile).filter(ScanProfile.id == request.profile_id).first()
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Profile not found"
            )
    else:
        # Use default profile
        profile = db.query(ScanProfile).filter(ScanProfile.is_default == True).first()
    
    # Create scan record
    scan = Scan(
        name=f"Nuclei Scan: {len(request.targets)} targets",
        scan_type=ScanType.VULNERABILITY,
        organization_id=request.organization_id,
        targets=request.targets,
        config={
            "profile_id": profile.id if profile else None,
            "severity": request.severity or (profile.nuclei_severity if profile else ["critical", "high"]),
            "tags": request.tags or (profile.nuclei_tags if profile else []),
        },
        started_by=current_user.username,
        status=ScanStatus.RUNNING,
        started_at=datetime.utcnow()
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    
    # Build scan parameters
    severity = request.severity or (profile.nuclei_severity if profile else ["critical", "high"])
    tags = request.tags or (profile.nuclei_tags if profile else [])
    exclude_tags = request.exclude_tags or (profile.nuclei_exclude_tags if profile else [])
    
    # Run Nuclei scan
    nuclei = NucleiService()
    
    if not nuclei.check_installation():
        scan.status = ScanStatus.FAILED
        scan.error_message = "Nuclei is not installed"
        scan.completed_at = datetime.utcnow()
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nuclei scanner is not installed. Please install it first."
        )
    
    try:
        result = await nuclei.scan_targets(
            targets=request.targets,
            severity=severity,
            tags=tags if tags else None,
            exclude_tags=exclude_tags if exclude_tags else None,
            rate_limit=profile.nuclei_rate_limit if profile else 150,
            bulk_size=profile.nuclei_bulk_size if profile else 25,
            concurrency=profile.nuclei_concurrency if profile else 25,
            timeout=profile.nuclei_timeout if profile else 10,
        )
        
        # Use NucleiFindingsService to import findings
        findings_service = NucleiFindingsService(db)
        import_summary = findings_service.import_scan_results(
            scan_result=result,
            organization_id=request.organization_id,
            scan_id=scan.id,
            create_assets=True,
            create_labels=request.create_labels
        )
        
        vulnerabilities_created = import_summary["findings_created"]
        
        # Update scan record
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.vulnerabilities_found = vulnerabilities_created
        scan.results = result.summary
        
        db.commit()
        
        return NucleiScanResultResponse(
            success=result.success,
            scan_id=scan.id,
            targets_scanned=result.targets_scanned,
            findings_count=len(result.findings),
            critical_count=result.summary.get("critical_count", 0),
            high_count=result.summary.get("high_count", 0),
            medium_count=result.summary.get("medium_count", 0),
            low_count=result.summary.get("low_count", 0),
            info_count=result.summary.get("info_count", 0),
            cves_found=result.summary.get("cves_found", []),
            duration_seconds=result.duration_seconds,
            errors=result.errors,
        )
        
    except Exception as e:
        scan.status = ScanStatus.FAILED
        scan.error_message = str(e)
        scan.completed_at = datetime.utcnow()
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Nuclei scan failed: {str(e)}"
        )


@router.get("/scan/{scan_id}/findings", response_model=List[NucleiFindingResponse])
def get_scan_findings(
    scan_id: int,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get findings from a Nuclei scan."""
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
    
    # Get vulnerabilities for this scan
    query = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id)
    
    if severity:
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        if severity.lower() in severity_map:
            query = query.filter(Vulnerability.severity == severity_map[severity.lower()])
    
    vulnerabilities = query.all()
    
    return [
        NucleiFindingResponse(
            template_id=v.metadata_.get("template_id", "") if v.metadata_ else "",
            template_name=v.title,
            severity=v.severity.value,
            host=v.asset.value if v.asset else "",
            matched_at=v.evidence or "",
            description=v.description,
            cve_id=v.cve_id,
            cvss_score=v.cvss_score,
            tags=v.tags or [],
            reference=v.references or [],
        )
        for v in vulnerabilities
    ]


@router.get("/tags")
def get_nuclei_tags(
    current_user: User = Depends(get_current_active_user)
):
    """Get available Nuclei template tags."""
    nuclei = NucleiService()
    return {
        "tags": nuclei.get_available_tags(),
        "severity_levels": nuclei.get_severity_levels()
    }


# ==================== PROJECTDISCOVERY TOOLS ====================

@router.post("/subfinder/{domain}")
async def run_subfinder(
    domain: str,
    recursive: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Run subfinder for subdomain enumeration."""
    pd_tools = ProjectDiscoveryService()
    
    if not pd_tools.check_tools().get("subfinder", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="subfinder is not installed"
        )
    
    result = await pd_tools.run_subfinder(domain, recursive=recursive)
    
    return {
        "domain": domain,
        "subdomains": result.subdomains,
        "total": len(result.subdomains),
        "sources": result.sources
    }


@router.post("/httpx")
async def run_httpx(
    targets: List[str],
    tech_detect: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Run httpx for HTTP probing."""
    pd_tools = ProjectDiscoveryService()
    
    if not pd_tools.check_tools().get("httpx", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="httpx is not installed"
        )
    
    results = await pd_tools.run_httpx(targets, tech_detect=tech_detect)
    
    return {
        "targets_probed": len(targets),
        "live_hosts": len(results),
        "results": [
            {
                "url": r.url,
                "status_code": r.status_code,
                "title": r.title,
                "webserver": r.webserver,
                "technologies": r.technologies,
                "ip": r.ip,
                "cdn": r.cdn,
            }
            for r in results
        ]
    }


@router.post("/dnsx")
async def run_dnsx(
    targets: List[str],
    record_types: Optional[List[str]] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Run dnsx for DNS enumeration."""
    pd_tools = ProjectDiscoveryService()
    
    if not pd_tools.check_tools().get("dnsx", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="dnsx is not installed"
        )
    
    results = await pd_tools.run_dnsx(targets, record_types=record_types)
    
    return {
        "targets_resolved": len(targets),
        "results": [
            {
                "host": r.host,
                "a": r.a_records,
                "aaaa": r.aaaa_records,
                "cname": r.cname_records,
                "mx": r.mx_records,
                "ns": r.ns_records,
                "txt": r.txt_records,
            }
            for r in results
        ]
    }


@router.post("/naabu")
async def run_naabu(
    targets: List[str],
    ports: Optional[str] = None,
    top_ports: int = Query(default=100, ge=1, le=65535),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Run naabu for port scanning."""
    pd_tools = ProjectDiscoveryService()
    
    if not pd_tools.check_tools().get("naabu", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="naabu is not installed"
        )
    
    results = await pd_tools.run_naabu(targets, ports=ports, top_ports=top_ports)
    
    return {
        "targets_scanned": len(targets),
        "open_ports": len(results),
        "results": [
            {
                "host": r.host,
                "ip": r.ip,
                "port": r.port,
                "protocol": r.protocol,
            }
            for r in results
        ]
    }


@router.post("/katana")
async def run_katana(
    targets: List[str],
    depth: int = Query(default=2, ge=1, le=10),
    js_crawl: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Run katana for web crawling."""
    pd_tools = ProjectDiscoveryService()
    
    if not pd_tools.check_tools().get("katana", False):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="katana is not installed"
        )
    
    results = await pd_tools.run_katana(targets, depth=depth, js_crawl=js_crawl)
    
    return {
        "targets_crawled": len(targets),
        "urls_found": len(results),
        "results": [
            {
                "url": r.url,
                "method": r.method,
                "source": r.source,
            }
            for r in results
        ]
    }


# ==================== NUCLEI FINDINGS MANAGEMENT ====================

@router.get("/findings/summary")
def get_nuclei_findings_summary(
    organization_id: int,
    scan_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get summary of all Nuclei findings for an organization.
    
    Returns:
    - Total findings by severity
    - CVEs discovered
    - Top vulnerability templates
    - Critical findings list
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    findings_service = NucleiFindingsService(db)
    summary = findings_service.get_findings_summary(organization_id, scan_id)
    
    return summary


@router.get("/findings")
def get_all_nuclei_findings(
    organization_id: int,
    severity: Optional[str] = None,
    cve_only: bool = False,
    status_filter: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get all Nuclei findings for an organization with filtering.
    
    Filters:
    - severity: critical, high, medium, low, info
    - cve_only: Only show findings with CVE IDs
    - status_filter: open, in_progress, resolved, accepted, false_positive
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    query = db.query(Vulnerability).filter(
        Vulnerability.detected_by == "nuclei"
    ).join(Asset).filter(
        Asset.organization_id == organization_id
    )
    
    # Apply filters
    if severity:
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        if severity.lower() in severity_map:
            query = query.filter(Vulnerability.severity == severity_map[severity.lower()])
    
    if cve_only:
        query = query.filter(Vulnerability.cve_id.isnot(None))
    
    if status_filter:
        status_map = {
            "open": VulnerabilityStatus.OPEN,
            "in_progress": VulnerabilityStatus.IN_PROGRESS,
            "resolved": VulnerabilityStatus.RESOLVED,
            "accepted": VulnerabilityStatus.ACCEPTED,
            "false_positive": VulnerabilityStatus.FALSE_POSITIVE,
        }
        if status_filter.lower() in status_map:
            query = query.filter(Vulnerability.status == status_map[status_filter.lower()])
    
    # Order by severity and date
    query = query.order_by(
        Vulnerability.severity.desc(),
        Vulnerability.first_detected.desc()
    )
    
    total = query.count()
    findings = query.offset(skip).limit(limit).all()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "status": f.status.value,
                "cve_id": f.cve_id,
                "cwe_id": f.cwe_id,
                "cvss_score": f.cvss_score,
                "template_id": f.template_id,
                "asset_id": f.asset_id,
                "asset_value": f.asset.value if f.asset else None,
                "first_detected": f.first_detected.isoformat() if f.first_detected else None,
                "last_detected": f.last_detected.isoformat() if f.last_detected else None,
                "tags": f.tags or [],
                "references": f.references[:5] if f.references else [],  # Limit refs
            }
            for f in findings
        ]
    }


@router.get("/findings/{finding_id}")
def get_nuclei_finding_detail(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get detailed information about a specific Nuclei finding."""
    finding = db.query(Vulnerability).filter(
        Vulnerability.id == finding_id,
        Vulnerability.detected_by == "nuclei"
    ).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Check organization access if asset exists
    if finding.asset:
        if not check_org_access(current_user, finding.asset.organization_id):
            raise HTTPException(status_code=403, detail="Access denied")
    elif current_user.role.value != "admin":
        # Only admins can access orphan findings (no associated asset)
        raise HTTPException(status_code=403, detail="Access denied to orphan finding")
    
    return {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "cve_id": finding.cve_id,
        "cwe_id": finding.cwe_id,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "template_id": finding.template_id,
        "matcher_name": finding.matcher_name,
        "evidence": finding.evidence,
        "proof_of_concept": finding.proof_of_concept,
        "remediation": finding.remediation,
        "references": finding.references,
        "asset": {
            "id": finding.asset.id,
            "value": finding.asset.value,
            "type": finding.asset.asset_type.value,
        } if finding.asset else None,
        "scan_id": finding.scan_id,
        "first_detected": finding.first_detected.isoformat() if finding.first_detected else None,
        "last_detected": finding.last_detected.isoformat() if finding.last_detected else None,
        "resolved_at": finding.resolved_at.isoformat() if finding.resolved_at else None,
        "assigned_to": finding.assigned_to,
        "tags": finding.tags,
        "metadata": finding.metadata_,
    }


@router.put("/findings/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    new_status: str,
    assigned_to: Optional[str] = None,
    notes: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """
    Update the status of a Nuclei finding.
    
    Statuses: open, in_progress, resolved, accepted, false_positive
    """
    finding = db.query(Vulnerability).filter(
        Vulnerability.id == finding_id,
        Vulnerability.detected_by == "nuclei"
    ).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Check organization access if asset exists
    if finding.asset:
        if not check_org_access(current_user, finding.asset.organization_id):
            raise HTTPException(status_code=403, detail="Access denied")
    elif current_user.role.value != "admin":
        # Only admins can access orphan findings (no associated asset)
        raise HTTPException(status_code=403, detail="Access denied to orphan finding")
    
    status_map = {
        "open": VulnerabilityStatus.OPEN,
        "in_progress": VulnerabilityStatus.IN_PROGRESS,
        "resolved": VulnerabilityStatus.RESOLVED,
        "accepted": VulnerabilityStatus.ACCEPTED,
        "false_positive": VulnerabilityStatus.FALSE_POSITIVE,
    }
    
    if new_status.lower() not in status_map:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(status_map.keys())}"
        )
    
    finding.status = status_map[new_status.lower()]
    
    if new_status.lower() == "resolved":
        finding.resolved_at = datetime.utcnow()
    
    if assigned_to:
        finding.assigned_to = assigned_to
    
    if notes:
        if finding.metadata_ is None:
            finding.metadata_ = {}
        if "status_notes" not in finding.metadata_:
            finding.metadata_["status_notes"] = []
        finding.metadata_["status_notes"].append({
            "timestamp": datetime.utcnow().isoformat(),
            "user": current_user.username,
            "status": new_status,
            "note": notes
        })
    
    db.commit()
    
    return {
        "id": finding.id,
        "status": finding.status.value,
        "message": f"Finding status updated to {new_status}"
    }


@router.post("/findings/close-stale")
def close_stale_findings(
    organization_id: int,
    days_threshold: int = Query(default=30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin)
):
    """
    Automatically close findings that haven't been detected in recent scans.
    
    This is useful for cleanup after regular scanning to mark old issues as resolved.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    findings_service = NucleiFindingsService(db)
    closed_count = findings_service.close_stale_findings(
        organization_id=organization_id,
        scan_id=None,  # Not tied to a specific scan
        days_threshold=days_threshold
    )
    
    return {
        "message": f"Closed {closed_count} stale findings",
        "closed_count": closed_count,
        "days_threshold": days_threshold
    }


@router.get("/findings/cves")
def get_cves_found(
    organization_id: int,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get list of all CVEs found by Nuclei scans.
    
    Groups CVEs by severity and provides links to NVD/MITRE.
    """
    if not check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    query = db.query(Vulnerability).filter(
        Vulnerability.detected_by == "nuclei",
        Vulnerability.cve_id.isnot(None)
    ).join(Asset).filter(
        Asset.organization_id == organization_id
    )
    
    if severity:
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
        }
        if severity.lower() in severity_map:
            query = query.filter(Vulnerability.severity == severity_map[severity.lower()])
    
    findings = query.all()
    
    # Group by CVE
    cve_map = {}
    for f in findings:
        if f.cve_id not in cve_map:
            cve_map[f.cve_id] = {
                "cve_id": f.cve_id,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "affected_assets": [],
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{f.cve_id}",
                "mitre_url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={f.cve_id}",
            }
        
        if f.asset and f.asset.value not in cve_map[f.cve_id]["affected_assets"]:
            cve_map[f.cve_id]["affected_assets"].append(f.asset.value)
    
    # Sort by severity then CVSS
    severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    cves = sorted(
        cve_map.values(),
        key=lambda x: (severity_order.get(x["severity"], 0), x["cvss_score"] or 0),
        reverse=True
    )
    
    return {
        "total_cves": len(cves),
        "by_severity": {
            "critical": len([c for c in cves if c["severity"] == "critical"]),
            "high": len([c for c in cves if c["severity"] == "high"]),
            "medium": len([c for c in cves if c["severity"] == "medium"]),
            "low": len([c for c in cves if c["severity"] == "low"]),
            "info": len([c for c in cves if c["severity"] == "info"]),
        },
        "cves": cves
    }

