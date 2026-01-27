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
