"""Integrations router — currently covers Jira (Atlassian) only."""

from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload

from app.api.deps import get_current_active_user, require_analyst
from app.db.database import get_db
from app.models.jira_integration import JiraIntegration, JiraTicket
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.models.asset import Asset
from app.schemas.jira_schemas import (
    CreateJiraTicketRequest,
    JiraIntegrationCreate,
    JiraIntegrationResponse,
    JiraIntegrationUpdate,
    JiraIssueTypesResponse,
    JiraProjectsResponse,
    JiraTestConnectionResponse,
    JiraTicketResponse,
)
from app.services import jira_service

router = APIRouter(prefix="/integrations", tags=["Integrations"])


def _get_org_id(user: User) -> int:
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


# ── Jira configuration ───────────────────────────────────────────────────────

@router.get("/jira", response_model=JiraIntegrationResponse)
def get_jira_integration(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get the current Jira integration settings for the user's organization."""
    org_id = _get_org_id(current_user)
    return _get_integration(db, org_id)


@router.post("/jira", response_model=JiraIntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_jira_integration(
    payload: JiraIntegrationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Configure Jira integration for this organization."""
    org_id = _get_org_id(current_user)

    existing = db.query(JiraIntegration).filter(JiraIntegration.organization_id == org_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Jira integration already exists. Use PUT to update.")

    # Test the connection before saving
    result = await jira_service.test_connection(payload.hostname, payload.email, payload.api_token)

    integration = JiraIntegration(
        organization_id=org_id,
        hostname=payload.hostname,
        email=payload.email,
        api_token=payload.api_token,
        default_project_key=payload.default_project_key,
        default_issue_type=payload.default_issue_type,
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
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update Jira integration settings."""
    org_id = _get_org_id(current_user)
    integration = _get_integration(db, org_id)

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(integration, field, value)

    # Re-test connection when credentials change
    hostname = integration.hostname
    email = integration.email
    api_token = integration.api_token
    result = await jira_service.test_connection(hostname, email, api_token)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]

    db.commit()
    db.refresh(integration)
    return integration


@router.delete("/jira", status_code=status.HTTP_204_NO_CONTENT)
def delete_jira_integration(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Remove Jira integration configuration."""
    org_id = _get_org_id(current_user)
    integration = _get_integration(db, org_id)
    db.delete(integration)
    db.commit()


# ── Test connection ──────────────────────────────────────────────────────────

@router.post("/jira/test", response_model=JiraTestConnectionResponse)
async def test_jira_connection(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Test the saved Jira connection for this organization."""
    org_id = _get_org_id(current_user)
    integration = _get_integration(db, org_id)

    result = await jira_service.test_connection(integration.hostname, integration.email, integration.api_token)
    integration.last_tested_at = datetime.utcnow()
    integration.last_test_ok = result["ok"]
    db.commit()

    return JiraTestConnectionResponse(**result)


# ── Projects / issue types ───────────────────────────────────────────────────

@router.get("/jira/projects", response_model=JiraProjectsResponse)
async def list_jira_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List accessible Jira projects for the configured integration."""
    org_id = _get_org_id(current_user)
    integration = _get_integration(db, org_id)

    try:
        projects = await jira_service.get_projects(integration.hostname, integration.email, integration.api_token)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")

    return JiraProjectsResponse(projects=projects)


@router.get("/jira/projects/{project_key}/issue-types", response_model=JiraIssueTypesResponse)
async def list_jira_issue_types(
    project_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List issue types available for a given Jira project."""
    org_id = _get_org_id(current_user)
    integration = _get_integration(db, org_id)

    try:
        issue_types = await jira_service.get_issue_types(
            integration.hostname, integration.email, integration.api_token, project_key
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Jira API error: {exc}")

    return JiraIssueTypesResponse(issue_types=issue_types)


# ── Ticket creation ──────────────────────────────────────────────────────────

@router.post(
    "/jira/vulnerabilities/{vulnerability_id}/ticket",
    response_model=JiraTicketResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_jira_ticket_for_vulnerability(
    vulnerability_id: int,
    payload: CreateJiraTicketRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create a Jira ticket for the specified vulnerability."""
    org_id = _get_org_id(current_user)
    integration = _get_integration(db, org_id)

    # Load vulnerability with asset relationship
    vuln = (
        db.query(Vulnerability)
        .options(joinedload(Vulnerability.asset))
        .filter(Vulnerability.id == vulnerability_id)
        .first()
    )
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found.")

    # Verify org access
    if vuln.asset and vuln.asset.organization_id != org_id and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Access denied.")

    # Check for duplicate ticket
    existing_ticket = (
        db.query(JiraTicket)
        .filter(
            JiraTicket.vulnerability_id == vulnerability_id,
            JiraTicket.integration_id == integration.id,
            JiraTicket.jira_project_key == payload.project_key,
        )
        .first()
    )
    if existing_ticket:
        raise HTTPException(
            status_code=409,
            detail=f"A Jira ticket already exists for this vulnerability: {existing_ticket.jira_issue_key}",
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
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to create Jira ticket: {exc}")

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


@router.get(
    "/jira/vulnerabilities/{vulnerability_id}/tickets",
    response_model=List[JiraTicketResponse],
)
def list_jira_tickets_for_vulnerability(
    vulnerability_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all Jira tickets created for a vulnerability."""
    org_id = _get_org_id(current_user)
    integration = _get_integration(db, org_id)

    tickets = (
        db.query(JiraTicket)
        .filter(
            JiraTicket.vulnerability_id == vulnerability_id,
            JiraTicket.integration_id == integration.id,
        )
        .order_by(JiraTicket.created_at.desc())
        .all()
    )
    return tickets
