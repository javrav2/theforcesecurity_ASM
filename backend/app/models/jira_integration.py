"""Jira integration models."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
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
    # Stored as-is; treat as a secret in production (consider encrypting at rest).
    api_token = Column(Text, nullable=False)

    default_project_key = Column(String(50), nullable=True)
    default_issue_type = Column(String(100), nullable=True, default="Bug")

    is_active = Column(Boolean, default=True, nullable=False)
    last_tested_at = Column(DateTime, nullable=True)
    last_test_ok = Column(Boolean, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tickets = relationship("JiraTicket", back_populates="integration", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<JiraIntegration org={self.organization_id} host={self.hostname}>"


class JiraTicket(Base):
    """Tracks Jira issues created from ASM vulnerabilities."""

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

    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<JiraTicket {self.jira_issue_key} vuln={self.vulnerability_id}>"
