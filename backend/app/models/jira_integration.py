"""Jira integration models."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class JiraIntegration(Base):
    """Stores Jira connection configuration per organization."""

    __tablename__ = "jira_integrations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, unique=True, index=True)
    organization = relationship("Organization")

    hostname = Column(String(500), nullable=False)  # e.g. myorg.atlassian.net
    email = Column(String(255), nullable=False)
    api_token = Column(Text, nullable=False)

    default_project_key = Column(String(50), nullable=True)
    default_issue_type = Column(String(100), nullable=True, default="Bug")

    # Auto-create: automatically open a ticket when a new vuln meets the threshold
    auto_create_enabled = Column(Boolean, default=False, nullable=False)
    auto_create_min_severity = Column(String(20), nullable=True, default="high")  # critical/high/medium/low/info

    # Bidirectional status sync — ordered list of Jira transition names to execute
    # e.g. ["In Progress", "Done"] for open→close
    open_to_close_transitions = Column(JSON, default=list)
    close_to_open_transitions = Column(JSON, default=list)

    # Optional field values to set before executing each transition direction
    close_custom_fields = Column(JSON, default=dict)   # e.g. {"resolution": "Done"}
    reopen_custom_fields = Column(JSON, default=dict)

    is_active = Column(Boolean, default=True, nullable=False)
    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tickets = relationship("JiraTicket", back_populates="integration", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<JiraIntegration org={self.organization_id} host={self.hostname}>"


# Severity rank for auto-create threshold comparison
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def severity_meets_threshold(vuln_severity: str, min_severity: str) -> bool:
    """Return True if vuln_severity is at or above min_severity."""
    return SEVERITY_RANK.get(vuln_severity.lower(), 99) <= SEVERITY_RANK.get(min_severity.lower(), 99)


class JiraTicket(Base):
    """Tracks Jira issues linked to ASM vulnerabilities."""

    __tablename__ = "jira_tickets"

    id = Column(Integer, primary_key=True, index=True)
    integration_id = Column(Integer, ForeignKey("jira_integrations.id"), nullable=False, index=True)
    integration = relationship("JiraIntegration", back_populates="tickets")

    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    vulnerability = relationship("Vulnerability")

    jira_issue_key = Column(String(50), nullable=False)   # e.g. SEC-123
    jira_issue_url = Column(String(1000), nullable=False)
    jira_project_key = Column(String(50), nullable=False)
    jira_issue_type = Column(String(100), nullable=True)

    # Live status tracking
    jira_status = Column(String(100), nullable=True)        # Last known Jira status name
    jira_assignee = Column(String(255), nullable=True)      # Last known Jira assignee display name

    # Whether this ticket was manually associated (vs created by ASM)
    is_associated = Column(Boolean, default=False, nullable=False)

    # Set when the ticket is disconnected (soft-delete; ticket still exists in Jira)
    disconnected_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<JiraTicket {self.jira_issue_key} vuln={self.vulnerability_id}>"
