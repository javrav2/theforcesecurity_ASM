"""Remediation playbook API routes."""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.vulnerability import Vulnerability
from app.models.user import User
from app.api.deps import get_current_active_user
from app.services.remediation_playbook_service import (
    RemediationPlaybookService,
    RemediationPlaybook,
    REMEDIATION_PLAYBOOKS,
)

router = APIRouter(prefix="/remediation", tags=["Remediation"])


@router.get("/playbooks")
def list_playbooks(
    current_user: User = Depends(get_current_active_user)
):
    """
    List all available remediation playbooks.
    
    Returns a summary of each playbook including ID, title, priority, and effort.
    """
    playbooks = RemediationPlaybookService.get_all_playbooks()
    
    return {
        "playbooks": [
            {
                "id": p.id,
                "title": p.title,
                "summary": p.summary,
                "priority": p.priority.value,
                "effort": p.effort.value,
                "estimated_time": p.estimated_time,
                "tags": p.tags,
            }
            for p in playbooks
        ],
        "total": len(playbooks),
    }


@router.get("/playbooks/{playbook_id}")
def get_playbook(
    playbook_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a specific remediation playbook by ID.
    
    Returns the full playbook with all steps, verification, and references.
    """
    playbook = RemediationPlaybookService.get_playbook(playbook_id)
    
    if not playbook:
        raise HTTPException(
            status_code=404,
            detail=f"Playbook '{playbook_id}' not found"
        )
    
    return playbook.to_dict()


@router.get("/playbooks/search")
def search_playbooks(
    query: str = Query(..., min_length=2),
    current_user: User = Depends(get_current_active_user)
):
    """
    Search for remediation playbooks.
    
    Searches by title, summary, and tags.
    """
    results = RemediationPlaybookService.search_playbooks(query)
    
    return {
        "query": query,
        "results": [
            {
                "id": p.id,
                "title": p.title,
                "summary": p.summary,
                "priority": p.priority.value,
                "effort": p.effort.value,
                "tags": p.tags,
            }
            for p in results
        ],
        "total": len(results),
    }


@router.get("/for-finding/{finding_id}")
def get_remediation_for_finding(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get remediation guidance for a specific finding/vulnerability.
    
    Automatically matches the finding to the most relevant playbook based on
    title, template ID, port, or tags.
    """
    # Get the finding
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    # Extract matching criteria from finding
    title = finding.title
    template_id = finding.template_id
    tags = finding.tags or []
    cwe_id = finding.cwe_id
    cve_id = finding.cve_id
    
    # Try to extract port from metadata or evidence
    port = None
    if finding.metadata_:
        port = finding.metadata_.get("port")
    
    # Find matching playbook - includes CWE/CVE matching for Nuclei findings
    playbook = RemediationPlaybookService.get_playbook_for_finding(
        title=title,
        template_id=template_id,
        port=port,
        tags=tags,
        cwe_id=cwe_id,
        cve_id=cve_id,
    )
    
    if not playbook:
        # Return the finding's built-in remediation if no playbook matches
        return {
            "finding_id": finding_id,
            "finding_title": finding.title,
            "has_playbook": False,
            "remediation": finding.remediation,
            "references": finding.references or [],
            "message": "No specific playbook found. Showing finding's built-in remediation."
        }
    
    return {
        "finding_id": finding_id,
        "finding_title": finding.title,
        "has_playbook": True,
        "playbook": playbook.to_dict(),
    }


@router.post("/for-finding/{finding_id}/assign")
def assign_playbook_to_finding(
    finding_id: int,
    playbook_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Assign a specific playbook to a finding.
    
    This copies the playbook's remediation guidance to the finding's remediation field.
    """
    finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    playbook = RemediationPlaybookService.get_playbook(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    # Build remediation text from playbook
    remediation_text = f"## {playbook.title}\n\n"
    remediation_text += f"**Priority:** {playbook.priority.value.upper()}\n"
    remediation_text += f"**Estimated Effort:** {playbook.estimated_time}\n\n"
    remediation_text += "### Steps\n\n"
    
    for step in playbook.steps:
        remediation_text += f"**{step.order}. {step.title}**\n"
        remediation_text += f"{step.description}\n"
        if step.command:
            remediation_text += f"\n```\n{step.command}\n```\n"
        if step.notes:
            remediation_text += f"\n> Note: {step.notes}\n"
        remediation_text += "\n"
    
    remediation_text += "### Verification\n\n"
    for v in playbook.verification:
        remediation_text += f"- {v.description}: {v.expected_result}\n"
    
    # Update the finding
    finding.remediation = remediation_text
    
    # Store playbook reference in metadata
    metadata = finding.metadata_ or {}
    metadata["assigned_playbook"] = playbook_id
    finding.metadata_ = metadata
    
    db.commit()
    
    return {
        "success": True,
        "finding_id": finding_id,
        "playbook_id": playbook_id,
        "message": f"Playbook '{playbook.title}' assigned to finding",
    }


@router.get("/stats")
def get_remediation_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get remediation statistics.
    
    Returns counts by priority, effort, and status.
    """
    from sqlalchemy import func
    from app.models.vulnerability import VulnerabilityStatus
    
    # Count findings by status
    status_counts = db.query(
        Vulnerability.status,
        func.count(Vulnerability.id)
    ).group_by(Vulnerability.status).all()
    
    status_dict = {str(s.value): c for s, c in status_counts}
    
    # Count findings with remediation
    with_remediation = db.query(func.count(Vulnerability.id)).filter(
        Vulnerability.remediation.isnot(None),
        Vulnerability.remediation != ""
    ).scalar()
    
    total_findings = db.query(func.count(Vulnerability.id)).scalar()
    
    return {
        "total_findings": total_findings,
        "with_remediation_guidance": with_remediation,
        "without_remediation_guidance": total_findings - with_remediation,
        "by_status": status_dict,
        "available_playbooks": len(REMEDIATION_PLAYBOOKS),
    }


@router.get("/workload")
def get_remediation_workload(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Calculate total remediation workload vs 40-hour work week.
    
    Returns:
    - Total estimated hours for all open findings
    - Comparison to 40-hour work weeks
    - Breakdown by severity, effort level, and playbook
    - Prioritized action list (quick wins, highest impact)
    """
    from sqlalchemy import func
    from app.models.vulnerability import VulnerabilityStatus, Severity
    from app.models.asset import Asset
    
    # Effort level to hours mapping
    EFFORT_HOURS = {
        "minimal": 0.5,    # 30 minutes
        "low": 1.5,        # 1-2 hours
        "medium": 4,       # Half day
        "high": 12,        # 1.5 days
        "significant": 40, # 1 week
    }
    
    # Default hours if no playbook match
    SEVERITY_DEFAULT_HOURS = {
        "critical": 4,
        "high": 2,
        "medium": 1,
        "low": 0.5,
        "info": 0.25,
    }
    
    # Build base query for open findings
    query = db.query(Vulnerability).filter(
        Vulnerability.status.in_([
            VulnerabilityStatus.OPEN,
            VulnerabilityStatus.IN_PROGRESS,
            VulnerabilityStatus.REOPENED
        ])
    )
    
    if organization_id:
        query = query.join(Asset).filter(Asset.organization_id == organization_id)
    
    findings = query.all()
    
    # Calculate workload
    total_hours = 0
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_effort = {"minimal": 0, "low": 0, "medium": 0, "high": 0, "significant": 0}
    by_playbook = {}
    quick_wins = []  # Low effort, high impact
    high_priority = []  # Critical/high severity
    
    for finding in findings:
        severity = (finding.severity.value if finding.severity else "medium").lower()
        
        # Try to get playbook for this finding
        playbook = RemediationPlaybookService.get_playbook_for_finding(
            title=finding.title,
            template_id=finding.template_id,
            tags=finding.tags or [],
            cwe_id=finding.cwe_id,
            cve_id=finding.cve_id,
        )
        
        if playbook:
            effort = playbook.effort.value
            hours = EFFORT_HOURS.get(effort, 2)
            playbook_id = playbook.id
            playbook_title = playbook.title
        else:
            effort = "medium" if severity in ["critical", "high"] else "low"
            hours = SEVERITY_DEFAULT_HOURS.get(severity, 1)
            playbook_id = None
            playbook_title = "No playbook matched"
        
        total_hours += hours
        
        # Track by severity
        if severity in by_severity:
            by_severity[severity] += hours
            by_severity_count[severity] += 1
        
        # Track by effort
        if effort in by_effort:
            by_effort[effort] += 1
        
        # Track by playbook
        if playbook_id:
            if playbook_id not in by_playbook:
                by_playbook[playbook_id] = {
                    "id": playbook_id,
                    "title": playbook_title,
                    "count": 0,
                    "total_hours": 0,
                    "effort": effort,
                    "priority": playbook.priority.value if playbook else "medium",
                }
            by_playbook[playbook_id]["count"] += 1
            by_playbook[playbook_id]["total_hours"] += hours
        
        # Identify quick wins (low effort, any severity)
        if effort in ["minimal", "low"] and severity in ["critical", "high", "medium"]:
            quick_wins.append({
                "id": finding.id,
                "title": finding.title,
                "severity": severity,
                "effort": effort,
                "hours": hours,
                "playbook_id": playbook_id,
                "playbook_title": playbook_title,
                "asset_value": finding.asset.value if finding.asset else None,
            })
        
        # Identify high priority (critical/high severity)
        if severity in ["critical", "high"]:
            high_priority.append({
                "id": finding.id,
                "title": finding.title,
                "severity": severity,
                "effort": effort,
                "hours": hours,
                "playbook_id": playbook_id,
                "playbook_title": playbook_title,
                "asset_value": finding.asset.value if finding.asset else None,
            })
    
    # Calculate work weeks
    work_week_hours = 40
    total_weeks = total_hours / work_week_hours
    
    # Sort and limit lists
    quick_wins.sort(key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x["severity"], 5), x["hours"]))
    high_priority.sort(key=lambda x: ({"critical": 0, "high": 1}.get(x["severity"], 2), x["hours"]))
    
    # Convert playbook dict to sorted list
    playbook_list = sorted(by_playbook.values(), key=lambda x: -x["count"])
    
    return {
        "summary": {
            "total_findings": len(findings),
            "total_hours": round(total_hours, 1),
            "total_work_weeks": round(total_weeks, 2),
            "work_week_hours": work_week_hours,
            "hours_display": f"{int(total_hours)}h {int((total_hours % 1) * 60)}m",
            "weeks_display": f"{total_weeks:.1f} weeks" if total_weeks >= 1 else f"{int(total_hours)} hours",
        },
        "by_severity": {
            "hours": by_severity,
            "counts": by_severity_count,
        },
        "by_effort": by_effort,
        "by_playbook": playbook_list[:20],  # Top 20 playbooks
        "quick_wins": quick_wins[:15],  # Top 15 quick wins
        "high_priority": high_priority[:15],  # Top 15 high priority
        "work_week_breakdown": {
            "critical_hours": by_severity.get("critical", 0),
            "high_hours": by_severity.get("high", 0),
            "medium_hours": by_severity.get("medium", 0),
            "low_hours": by_severity.get("low", 0),
            "info_hours": by_severity.get("info", 0),
        },
    }


@router.get("/prioritized-list")
def get_prioritized_remediation_list(
    organization_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get a prioritized list of findings to remediate.
    
    Sorted by severity and then by effort (easier fixes first).
    Groups findings by playbook for batch remediation.
    """
    from app.models.vulnerability import VulnerabilityStatus, Severity
    from app.models.asset import Asset
    
    query = db.query(Vulnerability).filter(
        Vulnerability.status.in_([
            VulnerabilityStatus.OPEN,
            VulnerabilityStatus.IN_PROGRESS,
            VulnerabilityStatus.REOPENED
        ])
    )
    
    if organization_id:
        query = query.join(Asset).filter(Asset.organization_id == organization_id)
    
    # Order by severity first
    findings = query.order_by(
        Vulnerability.severity.desc(),
        Vulnerability.created_at.asc()
    ).limit(limit).all()
    
    result = []
    for finding in findings:
        playbook = RemediationPlaybookService.get_playbook_for_finding(
            title=finding.title,
            template_id=finding.template_id,
            tags=finding.tags or [],
            cwe_id=finding.cwe_id,
            cve_id=finding.cve_id,
        )
        
        result.append({
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value if finding.severity else "medium",
            "status": finding.status.value if finding.status else "open",
            "asset_id": finding.asset_id,
            "asset_value": finding.asset.value if finding.asset else None,
            "template_id": finding.template_id,
            "has_playbook": playbook is not None,
            "playbook": {
                "id": playbook.id,
                "title": playbook.title,
                "effort": playbook.effort.value,
                "estimated_time": playbook.estimated_time,
                "priority": playbook.priority.value,
            } if playbook else None,
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
        })
    
    return {
        "findings": result,
        "total": len(result),
    }
