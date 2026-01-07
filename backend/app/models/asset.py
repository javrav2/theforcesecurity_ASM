"""Asset model for attack surface management."""

import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class AssetType(str, enum.Enum):
    """Types of assets in the attack surface."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    IP_RANGE = "ip_range"
    URL = "url"
    CERTIFICATE = "certificate"
    PORT = "port"
    SERVICE = "service"
    CLOUD_RESOURCE = "cloud_resource"
    API_ENDPOINT = "api_endpoint"
    EMAIL = "email"
    OTHER = "other"


class AssetStatus(str, enum.Enum):
    """Asset discovery and verification status."""
    DISCOVERED = "discovered"
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


class Asset(Base):
    """Asset model representing elements of the attack surface."""
    
    __tablename__ = "assets"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Asset identification
    name = Column(String(255), index=True, nullable=False)
    asset_type = Column(Enum(AssetType), nullable=False, index=True)
    value = Column(String(500), nullable=False)  # The actual domain/IP/URL etc.
    
    # Organization
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization", back_populates="assets")
    
    # Parent asset (for hierarchical relationships)
    parent_id = Column(Integer, ForeignKey("assets.id"), nullable=True)
    parent = relationship("Asset", remote_side=[id], backref="children")
    
    # Asset details
    status = Column(Enum(AssetStatus), default=AssetStatus.DISCOVERED)
    description = Column(Text, nullable=True)
    tags = Column(JSON, default=list)  # List of tags
    metadata_ = Column("metadata", JSON, default=dict)  # Additional metadata
    
    # Discovery info
    discovery_source = Column(String(100), nullable=True)  # How was it discovered
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    
    # Risk scoring
    risk_score = Column(Integer, default=0)  # 0-100
    criticality = Column(String(20), default="medium")  # low, medium, high, critical
    
    # State
    is_monitored = Column(Boolean, default=True)
    is_live = Column(Boolean, default=False, index=True)  # Has the asset responded to probes (port scan, HTTP, etc.)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")
    technologies = relationship(
        "Technology",
        secondary="asset_technologies",
        back_populates="assets"
    )
    port_services = relationship("PortService", back_populates="asset", cascade="all, delete-orphan")
    screenshots = relationship("Screenshot", back_populates="asset", cascade="all, delete-orphan", order_by="desc(Screenshot.captured_at)")
    
    # Labels (many-to-many relationship)
    labels = relationship("Label", secondary="asset_labels", back_populates="assets")
    
    # HTTP info (for web assets)
    http_status = Column(Integer, nullable=True)
    http_title = Column(String(500), nullable=True)
    http_headers = Column(JSON, default=dict)
    live_url = Column(String(500), nullable=True)  # The actual URL that responded (e.g., https://example.com)
    
    # DNS info
    dns_records = Column(JSON, default=dict)  # A, AAAA, MX, TXT, NS, etc.
    
    # SSL/TLS info
    ssl_info = Column(JSON, default=dict)  # Certificate details
    
    # Discovered endpoints and parameters (from ffuf, ParamSpider, Katana, etc.)
    endpoints = Column(JSON, default=list)  # List of discovered URL paths/endpoints
    parameters = Column(JSON, default=list)  # List of discovered URL parameters
    js_files = Column(JSON, default=list)  # JavaScript files found (often contain secrets/endpoints)
    
    # Geo-location info (for IP addresses and resolved domains)
    ip_address = Column(String(45), nullable=True)  # Resolved IP address
    latitude = Column(String(20), nullable=True)
    longitude = Column(String(20), nullable=True)
    region = Column(String(50), nullable=True, index=True)  # Geographic region (e.g., "North America", "EMEA", "APAC")
    city = Column(String(100), nullable=True)
    country = Column(String(100), nullable=True)
    country_code = Column(String(10), nullable=True, index=True)
    isp = Column(String(200), nullable=True)
    asn = Column(String(50), nullable=True)
    
    # Scope and ownership tracking
    in_scope = Column(Boolean, default=True, index=True)  # Is this asset in scope for scanning
    is_owned = Column(Boolean, default=False, index=True)  # Is this asset confirmed owned by the org
    netblock_id = Column(Integer, ForeignKey("netblocks.id"), nullable=True)  # Associated netblock if any
    
    @property
    def open_ports_count(self) -> int:
        """Get count of open ports."""
        from app.models.port_service import PortState
        return len([p for p in self.port_services if p.state == PortState.OPEN])
    
    @property
    def risky_ports_count(self) -> int:
        """Get count of risky ports."""
        return len([p for p in self.port_services if p.is_risky])
    
    def __repr__(self):
        return f"<Asset {self.asset_type.value}: {self.value}>"
