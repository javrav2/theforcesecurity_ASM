"""Label model for organizing and grouping assets."""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Table, Text
from sqlalchemy.orm import relationship

from app.db.database import Base


# Association table for many-to-many relationship between assets and labels
asset_labels = Table(
    'asset_labels',
    Base.metadata,
    Column('asset_id', Integer, ForeignKey('assets.id', ondelete='CASCADE'), primary_key=True),
    Column('label_id', Integer, ForeignKey('labels.id', ondelete='CASCADE'), primary_key=True),
    Column('created_at', DateTime, default=lambda: datetime.now(timezone.utc))
)


class Label(Base):
    """Label model for categorizing and grouping assets."""
    
    __tablename__ = "labels"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, index=True)
    color = Column(String(20), default="#6366f1")  # Default indigo color
    description = Column(Text, nullable=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Relationships
    organization = relationship("Organization", backref="labels")
    assets = relationship("Asset", secondary=asset_labels, back_populates="labels")
    
    def __repr__(self):
        return f"<Label(id={self.id}, name='{self.name}', org={self.organization_id})>"

