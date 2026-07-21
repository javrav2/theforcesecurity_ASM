"""Integrations router — Jira (Atlassian) bidirectional integration."""

from datetime import datetime
from typing import List

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_current_active_user, require_analyst
from app.db.database import get_db
from app.models.jira_integration import JiraIntegration, JiraTicket
from app.models.censys_integration import CensysAsmIntegration
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.asset import Asset
from app.schemas.jira_schemas import (
    AssociateJiraTicketRequest,
    CreateJiraTicketRequest,
    JiraIntegrationCreate,
    JiraIntegrationResponse,
    JiraIntegrationUpdate,
    JiraIssueTypesResponse,
    JiraProjectsResponse,
    JiraTestConnectionResponse,
    JiraTicketResponse,
    JiraTransitionsResponse,
    JiraSyncResult,
)
from app.schemas.censys_schemas import (
    CensysIntegrationCreate,
    CensysIntegrationResponse,
    CensysIntegrationUpdate,
    CensysSyncResult,
    CensysTestConnectionResponse,
)
from app.services import jira_service, censys_asm_service

router = APIRouter(prefix="/integrations", tags=["Integrations"])


def _get_org_id(user: User) -> int:
    if not user.organization_id:
        raise HTTPException(status_code=400, detail="User has no associated organization.")
    return user.organization_id


def _resolve_org_id(user: User, org_id_override: Optional[int] = None) -> int:
    """
    Return the effective org_id for an integration request.

    Admins (is_superuser) may pass an explicit org_id to manage any
    organization's integration.  Regular users always use their own org.
    """
    if org_id_override is not None:
        if not user.is_superuser:
            raise HTTPException(
                status_code=403,
                detail="Admin access required to manage another organization's integrations.",
            )
        return org_id_override
    if not user.organization_id:
        raise HTTPException(status_code=400, detail="User has no associated organization.")
    return user.organization_id


def _get_integration(db: Session, org_id: int) -> JiraIntegration:
    integration = (
        db.query(JiraIntegration)
        .filter(JiraIntegration.organization_id == org_id)
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Jira integration not configured for this organization.")
    return integration


def _active_tickets_for_vuln(db: Session, integration_id: int, vulnerability_id: int) -> List[JiraTicket]:
    return (
        db.query(JiraTicket)
        .filter(
            JiraTicket.vulnerability_id == vulnerability_id,
            JiraTicket.integration_id == integration_id,
            JiraTicket.disconnected_at.is_(None),
        )
        .order_by(JiraTicket.created_at.desc())
        .all()
    )


# ── Jira configuration ───────────────────────────────────────────────────────

@router.get("/jira", response_model=JiraIntegrationResponse)
def get_jira_integration(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    return _get_integration(db, resolved)


@router.post("/jira", response_model=JiraIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_jira_integration(
    payload: JiraIntegrationCreate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    if db.query(JiraIntegration).filter(JiraIntegration.organization_id == resolved).first():
        raise HTTPException(status_code=409, detail="Jira integration already exists. Use PUT to update.")

    result = await jira_service.test_connection(payload.hostname, payload.email, payload.api_token)
    integration = JiraIntegration(
        organization_id=resolved,
        **payload.model_dump(exclude={"api_token"}),
        api_token=payload.api_token,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=result["ok"],
    )
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/jira", response_model=JiraIntegrationResponse)
async def update_jira_integration(
    payload: JiraIntegrationUpdate,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(integration, field, value)

    result = await jira_service.test_connection(integration.hostname, integration.email, integration.api_token)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/jira", status_code=status.HTTP_204_NO_CONTENT)
def delete_jira_integration(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    db.delete(integration)
    db.commit()


# ── Test connection ──────────────────────────────────────────────────────────

@router.post("/jira/test", response_model=JiraTestConnectionResponse)
async def test_jira_connection(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    result = await jira_service.test_connection(integration.hostname, integration.email, integration.api_token)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()
    return JiraTestConnectionResponse(**result)


# ── Projects / issue types / transitions ─────────────────────────────────────

@router.get("/jira/projects", response_model=JiraProjectsResponse)
async def list_jira_projects(
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    try:
        projects = await jira_service.get_projects(integration.hostname, integration.email, integration.api_token)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")
    return JiraProjectsResponse(projects=projects)


@router.get("/jira/projects/{project_key}/issue-types", response_model=JiraIssueTypesResponse)
async def list_jira_issue_types(
    project_key: str,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    try:
        issue_types = await jira_service.get_issue_types(
            integration.hostname, integration.email, integration.api_token, project_key
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")
    return JiraIssueTypesResponse(issue_types=issue_types)


@router.get("/jira/issues/{issue_key}/transitions", response_model=JiraTransitionsResponse)
async def list_jira_transitions(
    issue_key: str,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Return available transitions from the current state of a Jira issue."""
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    try:
        transitions = await jira_service.get_issue_transitions(
            integration.hostname, integration.email, integration.api_token, issue_key
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")
    return JiraTransitionsResponse(transitions=transitions)


# ── Ticket creation ──────────────────────────────────────────────────────────

@router.post(
    "/jira/vulnerabilities/{vulnerability_id}/ticket",
    response_model=JiraTicketResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_jira_ticket_for_vulnerability(
    vulnerability_id: int,
    payload: CreateJiraTicketRequest,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)

    vuln = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .filter(Vulnerability.id == vulnerability_id)
        .first()
    )
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")
    if vuln.asset and vuln.asset.organization_id != resolved and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Access denied.")

    existing = (
        db.query(JiraTicket)
        .filter(
            JiraTicket.vulnerability_id == vulnerability_id,
            JiraTicket.integration_id == integration.id,
            JiraTicket.jira_project_key == payload.project_key,
            JiraTicket.disconnected_at.is_(None),
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A Jira ticket already exists for this vulnerability: {existing.jira_issue_key}",
        )

    try:
        result = await jira_service.create_jira_ticket(
            integration=integration,
            vuln=vuln,
            project_key=payload.project_key,
            issue_type=payload.issue_type,
            include_description=payload.include_description,
            include_evidence=payload.include_evidence,
            include_remediation=payload.include_remediation,
            include_references=payload.include_references,
            include_enrichment=payload.include_enrichment,
            assignee_account_id=payload.assignee_account_id,
            extra_labels=payload.extra_labels,
        )
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    ticket = JiraTicket(
        integration_id=integration.id,
        vulnerability_id=vulnerability_id,
        jira_issue_key=result["key"],
        jira_issue_url=result["url"],
        jira_project_key=payload.project_key,
        jira_issue_type=payload.issue_type,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


# ── Associate existing ticket ────────────────────────────────────────────────

@router.post(
    "/jira/vulnerabilities/{vulnerability_id}/associate",
    response_model=JiraTicketResponse,
    status_code=status.HTTP_201_CREATED,
)
async def associate_existing_jira_ticket(
    vulnerability_id: int,
    payload: AssociateJiraTicketRequest,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Link an existing Jira ticket to a vulnerability without creating a new one."""
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)

    vuln = db.query(Vulnerability).options(joinedload(Vulnerability.asset)).filter(Vulnerability.id == vulnerability_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")
    if vuln.asset and vuln.asset.organization_id != resolved and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Access denied.")

    # Verify the issue exists in Jira and fetch its current status
    try:
        detail = await jira_service.get_issue_detail(
            integration.hostname, integration.email, integration.api_token, payload.issue_key
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not verify Jira issue {payload.issue_key}: {exc}")

    # Derive project key from the issue key (e.g. "SEC-123" → "SEC")
    project_key = payload.project_key or payload.issue_key.rsplit("-", 1)[0]

    ticket = JiraTicket(
        integration_id=integration.id,
        vulnerability_id=vulnerability_id,
        jira_issue_key=payload.issue_key,
        jira_issue_url=jira_service._issue_url(integration.hostname, payload.issue_key),
        jira_project_key=project_key,
        jira_status=detail.get("status"),
        jira_assignee=detail.get("assignee"),
        is_associated=True,
    )
    db.add(ticket)
    db.commit()
    db.refresh(ticket)
    return ticket


# ── List tickets ─────────────────────────────────────────────────────────────

@router.get(
    "/jira/vulnerabilities/{vulnerability_id}/tickets",
    response_model=List[JiraTicketResponse],
)
def list_jira_tickets_for_vulnerability(
    vulnerability_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)
    return _active_tickets_for_vuln(db, integration.id, vulnerability_id)


# ── Disconnect a ticket ──────────────────────────────────────────────────────

@router.delete("/jira/tickets/{ticket_id}", status_code=status.HTTP_200_OK)
def disconnect_jira_ticket(
    ticket_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Unlink a Jira ticket from the vulnerability.
    The ticket is soft-deleted (disconnected_at set); the Jira issue is untouched.
    """
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)

    ticket = (
        db.query(JiraTicket)
        .filter(JiraTicket.id == ticket_id, JiraTicket.integration_id == integration.id)
        .first()
    )
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found.")

    ticket.disconnected_at = datetime.utcnow()
    db.commit()
    return {"ok": True, "message": f"Ticket {ticket.jira_issue_key} disconnected."}


# ── Refresh ticket status from Jira ─────────────────────────────────────────

@router.post("/jira/tickets/{ticket_id}/refresh", response_model=JiraTicketResponse)
async def refresh_jira_ticket_status(
    ticket_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Pull the latest status and assignee from Jira and update our record."""
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)

    ticket = (
        db.query(JiraTicket)
        .filter(JiraTicket.id == ticket_id, JiraTicket.integration_id == integration.id)
        .first()
    )
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found.")

    try:
        detail = await jira_service.get_issue_detail(
            integration.hostname, integration.email, integration.api_token, ticket.jira_issue_key
        )
        ticket.jira_status = detail.get("status")
        ticket.jira_assignee = detail.get("assignee")
        db.commit()
        db.refresh(ticket)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")

    return ticket


# ── Manual status sync ───────────────────────────────────────────────────────

@router.post(
    "/jira/vulnerabilities/{vulnerability_id}/sync",
    response_model=JiraSyncResult,
)
async def manually_sync_vulnerability_status(
    vulnerability_id: int,
    org_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Manually trigger a Jira ticket status sync for the current vulnerability status."""
    resolved = _resolve_org_id(current_user, org_id)
    integration = _get_integration(db, resolved)

    vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")

    tickets = _active_tickets_for_vuln(db, integration.id, vulnerability_id)
    if not tickets:
        raise HTTPException(status_code=404, detail="No active Jira tickets linked to this vulnerability.")

    ticket = tickets[0]
    new_status = vuln.status.value if vuln.status else "open"
    result = await jira_service.sync_ticket_for_status_change(
        integration=integration,
        ticket=ticket,
        old_status="open",  # treat as transition from open when manually triggered
        new_status=new_status,
        changed_by=current_user.email or current_user.username or "unknown",
    )

    if result.get("transitions_executed") or result.get("comment_added"):
        ticket.jira_status = new_status
        db.commit()

    return JiraSyncResult(**result)


# ══════════════════════════════════════════════════════════════════════════════
# Censys ASM integration — read-only import of risks & assets from a workspace
# ══════════════════════════════════════════════════════════════════════════════


def _get_censys_integration(db: Session, org_id: int, integration_id: int) -> CensysAsmIntegration:
    integration = (
        db.query(CensysAsmIntegration)
        .filter(
            CensysAsmIntegration.id == integration_id,
            CensysAsmIntegration.organization_id == org_id,
        )
        .first()
    )
    if not integration:
        raise HTTPException(status_code=404, detail="Censys ASM connection not found.")
    return integration


@router.get("/censys", response_model=List[CensysIntegrationResponse])
def list_censys_integrations(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    return (
        db.query(CensysAsmIntegration)
        .filter(CensysAsmIntegration.organization_id == org_id)
        .order_by(CensysAsmIntegration.created_at.desc())
        .all()
    )


@router.post("/censys", response_model=CensysIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_censys_integration(
    payload: CensysIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)

    existing = (
        db.query(CensysAsmIntegration)
        .filter(
            CensysAsmIntegration.organization_id == org_id,
            CensysAsmIntegration.workspace_name == payload.workspace_name,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A Censys ASM connection named '{payload.workspace_name}' already exists.",
        )

    result = await censys_asm_service.test_connection(payload.api_key)

    integration = CensysAsmIntegration(
        organization_id=org_id,
        workspace_name=payload.workspace_name,
        import_vulnerabilities=payload.import_vulnerabilities,
        import_assets=payload.import_assets,
        continuous_sync_enabled=payload.continuous_sync_enabled,
        sync_interval_minutes=payload.sync_interval_minutes,
        is_active=True,
        last_tested_at=datetime.utcnow(),
        last_test_ok=result["ok"],
    )
    integration.set_api_key(payload.api_key)
    db.add(integration)
    db.commit()
    db.refresh(integration)
    return integration


@router.put("/censys/{integration_id}", response_model=CensysIntegrationResponse)
async def update_censys_integration(
    integration_id: int,
    payload: CensysIntegrationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_censys_integration(db, org_id, integration_id)

    data = payload.model_dump(exclude_unset=True)
    new_key = data.pop("api_key", None)
    for field, value in data.items():
        setattr(integration, field, value)
    if new_key:
        integration.set_api_key(new_key)

    # Re-validate whenever the key changes (or on any edit for freshness).
    result = await censys_asm_service.test_connection(integration.get_api_key())
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/censys/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_censys_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    org_id = _get_org_id(current_user)
    integration = _get_censys_integration(db, org_id, integration_id)
    db.delete(integration)
    db.commit()


@router.post("/censys/{integration_id}/test", response_model=CensysTestConnectionResponse)
async def test_censys_connection(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    org_id = _get_org_id(current_user)
    integration = _get_censys_integration(db, org_id, integration_id)
    result = await censys_asm_service.test_connection(integration.get_api_key())
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()
    return CensysTestConnectionResponse(**result)


@router.post("/censys/{integration_id}/sync", response_model=CensysSyncResult)
async def sync_censys_integration(
    integration_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Pull the latest risks and/or assets from Censys ASM and import them."""
    org_id = _get_org_id(current_user)
    integration = _get_censys_integration(db, org_id, integration_id)
    if not integration.is_active:
        raise HTTPException(status_code=400, detail="This Censys ASM connection is disabled.")

    result = await censys_asm_service.sync_integration(db, integration)
    return CensysSyncResult(**result)
