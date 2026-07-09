"""Pydantic schemas for Jira integration."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ── Config ──────────────────────────────────────────────────────────────────

class JiraIntegrationCreate(BaseModel):
    hostname: str = Field(..., description="Jira cloud hostname, e.g. myorg.atlassian.net")
    email: str
    api_token: str
    default_project_key: Optional[str] = None
    default_issue_type: Optional[str] = "Bug"
    auto_create_enabled: bool = False
    auto_create_min_severity: Optional[str] = "high"
    open_to_close_transitions: List[str] = []
    close_to_open_transitions: List[str] = []
    close_custom_fields: Dict[str, Any] = {}
    reopen_custom_fields: Dict[str, Any] = {}


class JiraIntegrationUpdate(BaseModel):
    hostname: Optional[str] = None
    email: Optional[str] = None
    api_token: Optional[str] = None
    default_project_key: Optional[str] = None
    default_issue_type: Optional[str] = None
    is_active: Optional[bool] = None
    auto_create_enabled: Optional[bool] = None
    auto_create_min_severity: Optional[str] = None
    open_to_close_transitions: Optional[List[str]] = None
    close_to_open_transitions: Optional[List[str]] = None
    close_custom_fields: Optional[Dict[str, Any]] = None
    reopen_custom_fields: Optional[Dict[str, Any]] = None


class JiraIntegrationResponse(BaseModel):
    id: int
    organization_id: int
    hostname: str
    email: str
    default_project_key: Optional[str]
    default_issue_type: Optional[str]
    auto_create_enabled: bool
    auto_create_min_severity: Optional[str]
    open_to_close_transitions: List[str]
    close_to_open_transitions: List[str]
    close_custom_fields: Dict[str, Any]
    reopen_custom_fields: Dict[str, Any]
    is_active: bool
    last_tested_at: Optional[datetime]
    last_test_ok: Optional[bool]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ── Test connection ──────────────────────────────────────────────────────────

class JiraTestConnectionResponse(BaseModel):
    ok: bool
    message: str
    display_name: Optional[str] = None


# ── Projects / issue types ───────────────────────────────────────────────────

class JiraProject(BaseModel):
    key: str
    name: str
    project_type: Optional[str] = None


class JiraIssueType(BaseModel):
    id: str
    name: str
    description: Optional[str] = None


class JiraTransition(BaseModel):
    id: str
    name: str
    to_status: Optional[str] = None


class JiraProjectsResponse(BaseModel):
    projects: List[JiraProject]


class JiraIssueTypesResponse(BaseModel):
    issue_types: List[JiraIssueType]


class JiraTransitionsResponse(BaseModel):
    transitions: List[JiraTransition]


# ── Ticket creation ──────────────────────────────────────────────────────────

class CreateJiraTicketRequest(BaseModel):
    project_key: str
    issue_type: str = "Bug"
    include_description: bool = True
    include_evidence: bool = True
    include_remediation: bool = True
    include_references: bool = True
    include_enrichment: bool = True
    assignee_account_id: Optional[str] = None
    extra_labels: Optional[List[str]] = None


class AssociateJiraTicketRequest(BaseModel):
    issue_key: str = Field(..., description="Existing Jira issue key, e.g. SEC-123")
    project_key: Optional[str] = None


class JiraTicketResponse(BaseModel):
    id: int
    vulnerability_id: int
    jira_issue_key: str
    jira_issue_url: str
    jira_project_key: str
    jira_issue_type: Optional[str]
    jira_status: Optional[str]
    jira_assignee: Optional[str]
    is_associated: bool
    disconnected_at: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Status sync ──────────────────────────────────────────────────────────────

class JiraSyncResult(BaseModel):
    ok: bool
    message: str
    transitions_executed: List[str] = []
    comment_added: bool = False
