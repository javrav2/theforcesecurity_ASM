"""Vulnerability routes."""

from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.database import get_db
from app.models.vulnerability import Vulnerability, Severity, VulnerabilityStatus
from app.models.asset import Asset
from app.models.user import User
from app.schemas.vulnerability import VulnerabilityCreate, VulnerabilityUpdate, VulnerabilityResponse
from app.api.deps import get_current_active_user, require_analyst

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


def check_org_access(db: Session, user: User, asset_id: int) -> bool:
    """Check if user has access to asset's organization."""
    if user.is_superuser:
        return True
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        return False
    return user.organization_id == asset.organization_id


def build_vuln_response(vuln: Vulnerability) -> dict:
    """Build vulnerability response with computed fields."""
    response = {
        **vuln.__dict__,
        "name": vuln.title,  # Alias for frontend compatibility
        "host": vuln.asset.value if vuln.asset else None,
        "matched_at": vuln.evidence[:200] if vuln.evidence else None,
    }
    # Remove SQLAlchemy internal state
    response.pop("_sa_instance_state", None)
    return response


@router.get("/", response_model=List[VulnerabilityResponse])
def list_vulnerabilities(
    severity: Optional[Severity] = None,
    status: Optional[VulnerabilityStatus] = None,
    asset_id: Optional[int] = None,
    cve_id: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List vulnerabilities with filtering options."""
    query = db.query(Vulnerability).join(Asset)
    
    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return []
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Apply filters
    if severity:
        query = query.filter(Vulnerability.severity == severity)
    if status:
        query = query.filter(Vulnerability.status == status)
    if asset_id:
        query = query.filter(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.filter(Vulnerability.cve_id == cve_id)
    
    vulns = query.order_by(Vulnerability.severity.desc(), Vulnerability.created_at.desc()).offset(skip).limit(limit).all()
    
    # Build response with computed fields
    return [build_vuln_response(v) for v in vulns]


@router.post("/", response_model=VulnerabilityResponse, status_code=status.HTTP_201_CREATED)
def create_vulnerability(
    vuln_data: VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new vulnerability."""
    # Check asset exists and user has access
    asset = db.query(Asset).filter(Asset.id == vuln_data.asset_id).first()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found"
        )
    
    if not current_user.is_superuser and current_user.organization_id != asset.organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    new_vuln = Vulnerability(**vuln_data.model_dump())
    db.add(new_vuln)
    db.commit()
    db.refresh(new_vuln)
    
    return new_vuln


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
def get_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vulnerability by ID."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    return vuln


@router.put("/{vuln_id}", response_model=VulnerabilityResponse)
def update_vulnerability(
    vuln_id: int,
    vuln_data: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Update fields
    update_data = vuln_data.model_dump(exclude_unset=True)
    
    # Handle status change to resolved
    if update_data.get("status") == VulnerabilityStatus.RESOLVED and vuln.status != VulnerabilityStatus.RESOLVED:
        vuln.resolved_at = datetime.utcnow()
    
    for field, value in update_data.items():
        setattr(vuln, field, value)
    
    db.commit()
    db.refresh(vuln)
    
    return vuln


@router.delete("/{vuln_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vulnerability(
    vuln_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete vulnerability."""
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found"
        )
    
    if not check_org_access(db, current_user, vuln.asset_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    db.delete(vuln)
    db.commit()
    
    return None


@router.get("/stats/summary")
def get_vulnerabilities_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vulnerability statistics summary.
    
    Note: 'total' count excludes informational findings.
    Informational findings are still included in by_severity for reference.
    """
    query = db.query(Vulnerability).join(Asset)
    
    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return {"total": 0, "by_severity": {}, "by_status": {}, "info_count": 0}
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    vulns = query.all()
    
    # Calculate stats
    by_severity = {}
    by_status = {}
    actionable_count = 0  # Count of non-info findings
    info_count = 0  # Track info separately
    
    for vuln in vulns:
        sev_key = vuln.severity.value.lower() if hasattr(vuln.severity, 'value') else str(vuln.severity).lower()
        status_key = vuln.status.value if hasattr(vuln.status, 'value') else str(vuln.status)
        
        by_severity[sev_key] = by_severity.get(sev_key, 0) + 1
        by_status[status_key] = by_status.get(status_key, 0) + 1
        
        # Only count non-info findings toward the total
        if sev_key != 'info' and sev_key != 'informational':
            actionable_count += 1
        else:
            info_count += 1
    
    return {
        "total": actionable_count,  # Excludes info findings
        "total_all": len(vulns),  # Includes info findings
        "info_count": info_count,
        "by_severity": by_severity,
        "by_status": by_status
    }


@router.get("/stats/remediation-efficiency")
def get_remediation_efficiency(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get remediation efficiency statistics for the specified time period.
    
    Returns metrics showing how quickly vulnerabilities are being resolved.
    """
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    query = db.query(Vulnerability).join(Asset)
    
    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return {
                "period_days": days,
                "new_findings": 0,
                "resolved_findings": 0,
                "resolution_rate": 0,
                "avg_resolution_time_days": None,
                "mttr_days": None,  # Mean Time To Remediate
                "open_critical": 0,
                "open_high": 0,
                "overdue_count": 0
            }
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # New findings in period
    new_findings = query.filter(
        Vulnerability.first_detected >= cutoff_date
    ).count()
    
    # Resolved in period
    resolved_in_period = query.filter(
        Vulnerability.resolved_at >= cutoff_date,
        Vulnerability.status == VulnerabilityStatus.RESOLVED
    ).all()
    
    resolved_count = len(resolved_in_period)
    
    # Calculate average resolution time
    resolution_times = []
    for vuln in resolved_in_period:
        if vuln.first_detected and vuln.resolved_at:
            time_to_resolve = (vuln.resolved_at - vuln.first_detected).total_seconds() / 86400  # days
            if time_to_resolve >= 0:
                resolution_times.append(time_to_resolve)
    
    avg_resolution_time = sum(resolution_times) / len(resolution_times) if resolution_times else None
    
    # Currently open critical and high
    open_critical = query.filter(
        Vulnerability.status == VulnerabilityStatus.OPEN,
        Vulnerability.severity == Severity.CRITICAL
    ).count()
    
    open_high = query.filter(
        Vulnerability.status == VulnerabilityStatus.OPEN,
        Vulnerability.severity == Severity.HIGH
    ).count()
    
    # Overdue count (past deadline)
    overdue = query.filter(
        Vulnerability.status == VulnerabilityStatus.OPEN,
        Vulnerability.remediation_deadline < datetime.utcnow()
    ).count()
    
    # Resolution rate
    total_in_period = new_findings + query.filter(
        Vulnerability.first_detected < cutoff_date,
        Vulnerability.status == VulnerabilityStatus.OPEN
    ).count()
    resolution_rate = (resolved_count / total_in_period * 100) if total_in_period > 0 else 0
    
    return {
        "period_days": days,
        "new_findings": new_findings,
        "resolved_findings": resolved_count,
        "resolution_rate": round(resolution_rate, 1),
        "avg_resolution_time_days": round(avg_resolution_time, 1) if avg_resolution_time else None,
        "mttr_days": round(avg_resolution_time, 1) if avg_resolution_time else None,
        "open_critical": open_critical,
        "open_high": open_high,
        "overdue_count": overdue
    }


@router.get("/stats/exposure")
def get_vulnerability_exposure(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get vulnerability exposure statistics.
    
    Shows overall exposure level and risk distribution across assets.
    """
    query = db.query(Vulnerability).join(Asset)
    
    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return {
                "total_exposure_score": 0,
                "assets_with_vulnerabilities": 0,
                "total_assets": 0,
                "exposure_percentage": 0,
                "severity_distribution": {},
                "top_vulnerable_assets": [],
                "exposure_trend": "stable"
            }
        query = query.filter(Asset.organization_id == current_user.organization_id)
    
    # Get all open vulnerabilities (excluding info)
    open_vulns = query.filter(
        Vulnerability.status == VulnerabilityStatus.OPEN,
        Vulnerability.severity != Severity.INFO
    ).all()
    
    # Calculate exposure score (weighted by severity)
    severity_weights = {
        Severity.CRITICAL: 10,
        Severity.HIGH: 5,
        Severity.MEDIUM: 2,
        Severity.LOW: 1,
        Severity.INFO: 0
    }
    
    total_exposure_score = sum(severity_weights.get(v.severity, 0) for v in open_vulns)
    
    # Get assets with vulnerabilities
    asset_vuln_counts: dict = {}
    for vuln in open_vulns:
        asset_vuln_counts[vuln.asset_id] = asset_vuln_counts.get(vuln.asset_id, 0) + 1
    
    assets_with_vulns = len(asset_vuln_counts)
    
    # Get total assets count
    assets_query = db.query(Asset)
    if not current_user.is_superuser and current_user.organization_id:
        assets_query = assets_query.filter(Asset.organization_id == current_user.organization_id)
    total_assets = assets_query.count()
    
    exposure_percentage = (assets_with_vulns / total_assets * 100) if total_assets > 0 else 0
    
    # Severity distribution
    severity_distribution = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    for vuln in open_vulns:
        sev_key = vuln.severity.value.lower() if hasattr(vuln.severity, 'value') else str(vuln.severity).lower()
        if sev_key in severity_distribution:
            severity_distribution[sev_key] += 1
    
    # Top vulnerable assets
    top_assets = []
    for asset_id, count in sorted(asset_vuln_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        asset = db.query(Asset).filter(Asset.id == asset_id).first()
        if asset:
            top_assets.append({
                "asset_id": asset_id,
                "asset_name": asset.name or asset.value,
                "asset_value": asset.value,
                "vulnerability_count": count,
                "asset_type": asset.asset_type.value if hasattr(asset.asset_type, 'value') else str(asset.asset_type)
            })
    
    # Trend calculation (compare last 7 days to previous 7 days)
    now = datetime.utcnow()
    week_ago = now - timedelta(days=7)
    two_weeks_ago = now - timedelta(days=14)
    
    recent_new = query.filter(
        Vulnerability.first_detected >= week_ago,
        Vulnerability.severity != Severity.INFO
    ).count()
    
    previous_new = query.filter(
        Vulnerability.first_detected >= two_weeks_ago,
        Vulnerability.first_detected < week_ago,
        Vulnerability.severity != Severity.INFO
    ).count()
    
    if recent_new > previous_new * 1.2:
        trend = "increasing"
    elif recent_new < previous_new * 0.8:
        trend = "decreasing"
    else:
        trend = "stable"
    
    return {
        "total_exposure_score": total_exposure_score,
        "assets_with_vulnerabilities": assets_with_vulns,
        "total_assets": total_assets,
        "exposure_percentage": round(exposure_percentage, 1),
        "severity_distribution": severity_distribution,
        "top_vulnerable_assets": top_assets,
        "exposure_trend": trend
    }

















