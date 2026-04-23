"""
Rules of Engagement routes.

All routes are scoped to an organization and require ``analyst`` role (GET)
or ``admin`` role (POST/PUT) to modify.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import require_admin, require_analyst
from app.db.database import get_db
from app.models.user import User
from app.services import roe_service

router = APIRouter(prefix="/roe", tags=["rules-of-engagement"])


class RoEPayload(BaseModel):
    """Full or partial RoE update."""

    enabled: bool = True
    document_name: Optional[str] = Field(default=None)
    document_text: Optional[str] = Field(default=None)
    scope_in: Optional[list[str]] = None
    scope_out: Optional[list[str]] = None
    allowed_scan_types: Optional[list[str]] = None
    restricted_scan_types: Optional[list[str]] = None
    max_rps_global: Optional[int] = None
    max_concurrency: Optional[int] = None
    requires_agent_confirmation: Optional[bool] = None
    contacts: Optional[list[str]] = None
    notes: Optional[str] = None


class RoECheckRequest(BaseModel):
    organization_id: int
    targets: list[str]
    scan_type: Optional[str] = None


def _check_org_access(user: User, org_id: int) -> bool:
    if user.is_superuser:
        return True
    return user.organization_id == org_id


@router.get("/{organization_id}")
def get_roe(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    if not _check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    return roe_service.load_roe(db, organization_id)


@router.put("/{organization_id}", status_code=status.HTTP_200_OK)
def update_roe(
    organization_id: int,
    payload: RoEPayload,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    if not _check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")

    updated = roe_service.accept_roe(
        db,
        organization_id=organization_id,
        actor_email=current_user.email or current_user.username or "",
        document_text=payload.document_text or "",
        document_name=payload.document_name or "",
        scope_in=payload.scope_in,
        scope_out=payload.scope_out,
        allowed_scan_types=payload.allowed_scan_types,
        restricted_scan_types=payload.restricted_scan_types,
        max_rps_global=payload.max_rps_global,
        max_concurrency=payload.max_concurrency,
        requires_agent_confirmation=payload.requires_agent_confirmation,
        contacts=payload.contacts,
        notes=payload.notes,
        enabled=payload.enabled,
    )
    return updated


@router.post("/{organization_id}/upload", status_code=status.HTTP_200_OK)
async def upload_roe(
    organization_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Upload a markdown RoE document. The server will best-effort parse scope
    sections and pre-populate ``scope_in`` / ``scope_out`` / ``contacts``.
    The user can then review and call ``PUT /roe/{org}`` to finalize.
    """
    if not _check_org_access(current_user, organization_id):
        raise HTTPException(status_code=403, detail="Access denied")

    raw = await file.read()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not UTF-8 text")

    parsed = roe_service.ingest_markdown(text)

    updated = roe_service.accept_roe(
        db,
        organization_id=organization_id,
        actor_email=current_user.email or current_user.username or "",
        document_text=text,
        document_name=file.filename or "roe.md",
        scope_in=parsed.get("scope_in"),
        scope_out=parsed.get("scope_out"),
        contacts=parsed.get("contacts"),
        notes=parsed.get("notes"),
        enabled=True,
    )
    return {
        "parsed": parsed,
        "config": updated,
    }


@router.post("/check")
def check_roe(
    payload: RoECheckRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Dry-run RoE guardrail for a list of targets."""
    if not _check_org_access(current_user, payload.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")

    ok, reason, rejected = roe_service.check_targets(
        db, payload.organization_id, payload.targets, scan_type=payload.scan_type
    )
    return {
        "allowed": ok,
        "reason": reason,
        "rejected_targets": rejected,
    }
