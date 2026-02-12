"""Agent knowledge model for org-scoped and global RAG documents."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class AgentKnowledge(Base):
    """Per-organization or global knowledge documents for agent RAG (scope, ROE, methodology)."""

    __tablename__ = "agent_knowledge"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(
        Integer,
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )  # NULL = global
    title = Column(String(512), nullable=False)
    content = Column(Text, nullable=False)
    tags = Column(JSON, default=list)  # e.g. ["scope", "roe", "methodology"]
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", backref="agent_knowledge")
