"""M&A / Acquisition model for tracking mergers and acquisitions."""

from datetime import datetime
from enum import Enum as PyEnum
from typing import List, Optional
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Enum, JSON, Float
from sqlalchemy.orm import relationship

from app.db.database import Base


class AcquisitionStatus(str, PyEnum):
    """Status of an acquisition."""
    ANNOUNCED = "announced"
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    UNKNOWN = "unknown"


class AcquisitionType(str, PyEnum):
    """Type of acquisition."""
    ACQUISITION = "acquisition"
    MERGER = "merger"
    ASSET_PURCHASE = "asset_purchase"
    DIVESTITURE = "divestiture"
    SPINOFF = "spinoff"
    UNKNOWN = "unknown"


class Acquisition(Base):
    """Model for tracking M&A events."""
    
    __tablename__ = "acquisitions"
    
    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    
    # Target company info
    target_name = Column(String(255), nullable=False, index=True)
    target_domain = Column(String(255), nullable=True)  # Primary domain of acquired company
    target_domains = Column(JSON, default=list)  # List of all known domains
    target_description = Column(Text, nullable=True)
    target_industry = Column(String(255), nullable=True)
    target_country = Column(String(100), nullable=True)
    target_city = Column(String(100), nullable=True)
    target_founded_year = Column(Integer, nullable=True)
    target_employees = Column(Integer, nullable=True)
    
    # Acquisition details
    acquisition_type = Column(Enum(AcquisitionType), default=AcquisitionType.ACQUISITION)
    status = Column(Enum(AcquisitionStatus), default=AcquisitionStatus.COMPLETED)
    announced_date = Column(DateTime, nullable=True)
    closed_date = Column(DateTime, nullable=True)
    deal_value = Column(Float, nullable=True)  # In millions USD
    deal_currency = Column(String(10), default="USD")
    
    # Integration status
    is_integrated = Column(Boolean, default=False)  # Has the acquisition been fully integrated
    integration_notes = Column(Text, nullable=True)
    
    # Domain tracking
    domains_discovered = Column(Integer, default=0)
    domains_in_scope = Column(Integer, default=0)
    
    # External IDs
    tracxn_id = Column(String(100), nullable=True, unique=True)
    crunchbase_id = Column(String(100), nullable=True)
    linkedin_url = Column(String(500), nullable=True)
    website_url = Column(String(500), nullable=True)
    
    # Source tracking
    source = Column(String(50), default="manual")  # manual, tracxn, crunchbase, etc.
    metadata_ = Column(JSON, default=dict)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    organization = relationship("Organization", back_populates="acquisitions")
    
    def __repr__(self):
        return f"<Acquisition {self.target_name} by org {self.organization_id}>"
    
    def add_domain(self, domain: str):
        """Add a domain to the target_domains list."""
        domains = self.target_domains or []
        if domain not in domains:
            domains.append(domain)
            self.target_domains = domains
            self.domains_discovered = len(domains)
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            "id": self.id,
            "organization_id": self.organization_id,
            "target_name": self.target_name,
            "target_domain": self.target_domain,
            "target_domains": self.target_domains or [],
            "target_description": self.target_description,
            "target_industry": self.target_industry,
            "target_country": self.target_country,
            "target_city": self.target_city,
            "target_founded_year": self.target_founded_year,
            "target_employees": self.target_employees,
            "acquisition_type": self.acquisition_type.value if self.acquisition_type else None,
            "status": self.status.value if self.status else None,
            "announced_date": self.announced_date.isoformat() if self.announced_date else None,
            "closed_date": self.closed_date.isoformat() if self.closed_date else None,
            "deal_value": self.deal_value,
            "deal_currency": self.deal_currency,
            "is_integrated": self.is_integrated,
            "integration_notes": self.integration_notes,
            "domains_discovered": self.domains_discovered,
            "domains_in_scope": self.domains_in_scope,
            "tracxn_id": self.tracxn_id,
            "crunchbase_id": self.crunchbase_id,
            "linkedin_url": self.linkedin_url,
            "website_url": self.website_url,
            "source": self.source,
            "metadata_": self.metadata_ or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
