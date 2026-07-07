"""
Scoring pipeline API routes.

Provides visibility into and control over the universal vulnerability scoring
pipeline (ScoringPipeline). Useful for:
  - Monitoring queue depth and worker health from a dashboard
  - Manually triggering re-scoring of specific findings
  - Batch-scoring all unscored findings for an organization
  - Inspecting dead-letter items that failed after max retries
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.core.security import get_current_active_user
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.asset import Asset
from app.services.scoring_pipeline import get_scoring_pipeline

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scoring", tags=["Scoring Pipeline"])


# ── Response models ───────────────────────────────────────────────────────────

class PipelineStatus(BaseModel):
    running: bool
    workers: int
    queue_depth: int
    currently_pending: int
    processed_total: int
    skipped_dedup: int
    retried: int
    errors: int
    dead_letter_count: int
    dead_letter_recent: List[Dict[str, Any]]


class SubmitResponse(BaseModel):
    submitted: bool
    message: str


class BatchSubmitRequest(BaseModel):
    organization_id: int
    force: bool = False
    severity_filter: Optional[List[str]] = None
    limit: Optional[int] = None


class BatchSubmitResponse(BaseModel):
    submitted: int
    skipped: int
    total_eligible: int


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/status", response_model=PipelineStatus)
async def pipeline_status(
    current_user: User = Depends(get_current_active_user),
) -> PipelineStatus:
    """
    Return live pipeline health metrics: queue depth, worker count,
    processed/error counters, and recent dead-letter entries.
    """
    stats = get_scoring_pipeline().stats()
    return PipelineStatus(**stats)


@router.post("/submit/{vuln_id}", response_model=SubmitResponse)
async def submit_vulnerability(
    vuln_id: int,
    force: bool = Query(default=False, description="Re-score even if enriched recently"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> SubmitResponse:
    """
    Manually submit a single vulnerability for OPES scoring.

    Useful when a finding was created before the pipeline was enabled,
    or when you want to force a re-score after changing asset signals.
    """
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if vuln is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id} not found")

    severity = (
        vuln.severity.value
        if hasattr(vuln.severity, "value")
        else str(vuln.severity or "medium")
    )
    pipeline = get_scoring_pipeline()
    submitted = pipeline.submit(vuln_id, severity=severity, force=force)

    if submitted:
        return SubmitResponse(submitted=True, message=f"Vulnerability {vuln_id} queued for scoring")
    return SubmitResponse(
        submitted=False,
        message=f"Vulnerability {vuln_id} is already in the queue or was recently scored",
    )


@router.post("/batch", response_model=BatchSubmitResponse)
async def batch_submit(
    request: BatchSubmitRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> BatchSubmitResponse:
    """
    Submit all unscored (or stale) vulnerabilities for an organization.

    Use this to bootstrap scoring for existing findings after enabling
    the pipeline, or to force a full re-score after a scoring logic update.
    """
    q = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(Asset.organization_id == request.organization_id)
    )

    if request.severity_filter:
        from app.models.vulnerability import Severity  # avoid circular at top
        sev_enums = []
        for s in request.severity_filter:
            try:
                sev_enums.append(Severity(s.lower()))
            except ValueError:
                pass
        if sev_enums:
            q = q.filter(Vulnerability.severity.in_(sev_enums))

    if not request.force:
        # Only include vulnerabilities that have never been Oracle-scored
        # or whose oracle_enriched_at is null (not scored yet).
        q = q.filter(Vulnerability.oracle_enriched_at.is_(None))

    if request.limit:
        q = q.limit(request.limit)

    vulns = q.all()
    total = len(vulns)

    pipeline = get_scoring_pipeline()
    submitted = skipped = 0
    for v in vulns:
        severity = (
            v.severity.value if hasattr(v.severity, "value") else str(v.severity or "medium")
        )
        if pipeline.submit(v.id, severity=severity, force=request.force):
            submitted += 1
        else:
            skipped += 1

    logger.info(
        "Scoring batch: org=%s submitted=%d skipped=%d total=%d force=%s",
        request.organization_id, submitted, skipped, total, request.force,
    )
    return BatchSubmitResponse(submitted=submitted, skipped=skipped, total_eligible=total)


@router.post("/rescore-all/{organization_id}", response_model=BatchSubmitResponse)
async def rescore_all(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> BatchSubmitResponse:
    """
    Force re-score of ALL open findings for an organization.

    Useful after a scoring logic upgrade (e.g. new CWE ceilings, updated
    detection confidence classification, new FIRE CVE list).
    """
    from app.models.vulnerability import VulnerabilityStatus

    vulns = (
        db.query(Vulnerability)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .filter(
            Asset.organization_id == organization_id,
            Vulnerability.status == VulnerabilityStatus.OPEN,
        )
        .all()
    )

    pipeline = get_scoring_pipeline()
    submitted = skipped = 0
    for v in vulns:
        severity = (
            v.severity.value if hasattr(v.severity, "value") else str(v.severity or "medium")
        )
        if pipeline.submit(v.id, severity=severity, force=True):
            submitted += 1
        else:
            skipped += 1

    return BatchSubmitResponse(submitted=submitted, skipped=skipped, total_eligible=len(vulns))
