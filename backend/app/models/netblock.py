"""
Netblock/CIDR model for tracking IP ranges owned by organizations.

Stores CIDR blocks, ASN information, and ownership data discovered via
WhoisXML API and other sources.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON, BigInteger
from sqlalchemy.orm import relationship

from app.db.database import Base


class Netblock(Base):
    """
    Model for storing IP netblocks/CIDR ranges.
    
    Tracks ownership, scope status, and associated metadata from WHOIS data.
    """
    __tablename__ = "netblocks"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Organization this netblock belongs to
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    organization = relationship("Organization")
    
    # IP Range information
    inetnum = Column(String(100), nullable=False, index=True)  # Original range notation (e.g., "192.0.2.0 - 192.0.2.255")
    start_ip = Column(String(45), nullable=False, index=True)  # Start IP (normalized)
    end_ip = Column(String(45), nullable=False)  # End IP (normalized)
    cidr_notation = Column(String(500), nullable=True)  # CIDR notation (e.g., "192.0.2.0/24")
    ip_count = Column(BigInteger, default=0)  # Number of IPs in this range
    ip_version = Column(String(10), default="ipv4")  # "ipv4" or "ipv6"
    
    # Ownership and Scope flags
    is_owned = Column(Boolean, default=False, index=True)  # Owned by the target organization
    in_scope = Column(Boolean, default=True, index=True)  # In scope for scanning
    ownership_confidence = Column(Integer, default=0)  # 0-100 confidence score
    
    # ASN Information
    asn = Column(String(20), nullable=True, index=True)  # AS Number (e.g., "AS12345")
    as_name = Column(String(255), nullable=True)  # AS Name
    as_type = Column(String(50), nullable=True)  # AS Type (e.g., "ISP", "Enterprise")
    route = Column(String(100), nullable=True)  # BGP route
    as_domain = Column(String(255), nullable=True)  # AS Domain
    
    # Network details
    netname = Column(String(255), nullable=True)  # Network name
    nethandle = Column(String(100), nullable=True)  # Network handle
    description = Column(Text, nullable=True)  # Description from WHOIS
    
    # Geographic information
    region = Column(String(50), nullable=True, index=True)  # Geographic region (e.g., "North America", "EMEA", "APAC")
    country = Column(String(10), nullable=True, index=True)
    city = Column(String(100), nullable=True)
    address = Column(Text, nullable=True)
    
    # Organization details from WHOIS
    org_name = Column(String(500), nullable=True)  # Organization name from WHOIS
    org_email = Column(Text, nullable=True)  # Can have multiple emails
    org_phone = Column(Text, nullable=True)  # Can have multiple phone numbers
    org_country = Column(String(10), nullable=True)
    org_city = Column(String(100), nullable=True)
    org_postal_code = Column(String(50), nullable=True)
    
    # Discovery tracking
    discovery_source = Column(String(100), default="whoisxml")  # Source of discovery
    discovered_at = Column(DateTime, default=datetime.utcnow)
    last_verified = Column(DateTime, nullable=True)
    whois_modified = Column(DateTime, nullable=True)  # When WHOIS record was last modified
    
    # Scan tracking
    last_scanned = Column(DateTime, nullable=True)
    scan_count = Column(Integer, default=0)
    
    # Additional metadata
    tags = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<Netblock {self.cidr_notation or self.inetnum} owned={self.is_owned} scope={self.in_scope}>"




