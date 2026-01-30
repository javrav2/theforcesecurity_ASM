"""Finding Exception model for tracking risk accepted and mitigated findings."""

import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Text, JSON, Boolean
from sqlalchemy.orm import relationship

from app.db.database import Base


class ExceptionType(str, enum.Enum):
    """Type of exception."""
    RISK_ACCEPTED = "risk_accepted"  # Risk acknowledged and accepted
    MITIGATED = "mitigated"  # Compensating controls in place
    FALSE_POSITIVE = "false_positive"  # Confirmed not a real vulnerability
    DEFERRED = "deferred"  # Remediation postponed to a future date


class ExceptionStatus(str, enum.Enum):
    """Status of the exception."""
    PENDING_APPROVAL = "pending_approval"  # Awaiting approval
    APPROVED = "approved"  # Exception approved
    REJECTED = "rejected"  # Exception rejected
    EXPIRED = "expired"  # Exception has expired


class FindingException(Base):
    """
    Exception record for tracking risk accepted, mitigated, or false positive findings.
    
    This provides an audit trail and documentation for findings that are not being
    remediated in the traditional sense.
    """
    
    __tablename__ = "finding_exceptions"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Exception details
    title = Column(String(255), nullable=False)
    exception_type = Column(Enum(ExceptionType), nullable=False, index=True)
    status = Column(Enum(ExceptionStatus), default=ExceptionStatus.APPROVED, index=True)
    
    # Justification and documentation
    justification = Column(Text, nullable=False)  # Why is this exception being requested?
    business_impact = Column(Text, nullable=True)  # What is the business impact of not remediating?
    compensating_controls = Column(Text, nullable=True)  # What controls mitigate the risk?
    
    # Risk assessment
    residual_risk = Column(String(50), nullable=True)  # low, medium, high, critical
    risk_score = Column(Integer, nullable=True)  # Optional numeric risk score
    
    # Ownership
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization")
    requested_by = Column(String(255), nullable=False)  # User who requested the exception
    approved_by = Column(String(255), nullable=True)  # User who approved (if approved)
    
    # Validity period
    effective_date = Column(DateTime, default=datetime.utcnow)
    expiration_date = Column(DateTime, nullable=True)  # When the exception expires (requires re-review)
    review_date = Column(DateTime, nullable=True)  # Next review date
    
    # Linked findings
    findings = relationship("Vulnerability", back_populates="exception")
    
    # Audit trail
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    approved_at = Column(DateTime, nullable=True)
    
    # Additional metadata
    tags = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    
    # Attachments/evidence (stored as list of file paths or URLs)
    attachments = Column(JSON, default=list)
    
    def __repr__(self):
        return f"<FindingException {self.id}: {self.exception_type.value} - {self.title[:30]}>"
    
    @property
    def is_expired(self) -> bool:
        """Check if the exception has expired."""
        if self.expiration_date:
            return datetime.utcnow() > self.expiration_date
        return False
    
    @property
    def is_active(self) -> bool:
        """Check if the exception is currently active."""
        return self.status == ExceptionStatus.APPROVED and not self.is_expired
    
    @property
    def findings_count(self) -> int:
        """Get count of linked findings."""
        return len(self.findings) if self.findings else 0
