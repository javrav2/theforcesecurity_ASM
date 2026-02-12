"""Agent note model for session-scoped findings (credentials, vulnerabilities, artifacts)."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship

from app.db.database import Base


class AgentNote(Base):
    """Session-scoped notes the agent can save and that are re-injected into context."""

    __tablename__ = "agent_notes"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(255), nullable=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    category = Column(String(50), nullable=False)  # credential, vulnerability, finding, artifact
    content = Column(Text, nullable=False)
    target = Column(String(512), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    organization = relationship("Organization", backref="agent_notes")
