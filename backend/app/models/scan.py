"""Scan model for tracking ASM scan jobs."""

import enum
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class ScanType(str, enum.Enum):
    """Types of scans."""
    DISCOVERY = "discovery"           # Full asset discovery from seed domain
    SUBDOMAIN_ENUM = "subdomain_enum" # Subdomain enumeration
    DNS_ENUM = "dns_enum"             # DNS record enumeration
    DNS_RESOLUTION = "dns_resolution" # Resolve domains to IPs + geo enrichment
    PORT_SCAN = "port_scan"           # Port/service scanning
    PORT_VERIFY = "port_verify"       # Nmap verification of masscan-discovered ports
    SERVICE_DETECT = "service_detect" # Deep nmap scan for unknown services
    WEB_SCAN = "web_scan"             # Web application scanning
    HTTP_PROBE = "http_probe"         # HTTP probing for live web assets
    TECHNOLOGY = "technology"          # Wappalyzer technology fingerprinting
    CERTIFICATE = "certificate"        # SSL/TLS certificate analysis
    VULNERABILITY = "vulnerability"    # Vulnerability scanning
    LOGIN_PORTAL = "login_portal"      # Login portal & admin panel detection
    SCREENSHOT = "screenshot"          # Web screenshot capture
    PARAMSPIDER = "paramspider"        # URL parameter discovery
    WAYBACKURLS = "waybackurls"        # Historical URL discovery
    KATANA = "katana"                  # Deep web crawling with JS parsing
    CLEANUP = "cleanup"                # System maintenance and file cleanup
    FULL = "full"                      # Complete discovery + all scans
    GEO_ENRICH = "geo_enrich"          # Geo-location enrichment for all assets
    TLDFINDER = "tldfinder"            # TLD/domain discovery via ProjectDiscovery tldfinder


class ScanStatus(str, enum.Enum):
    """Scan execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Scan(Base):
    """Scan model for tracking scan jobs."""
    
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Scan identification
    name = Column(String(255), nullable=False)
    scan_type = Column(Enum(ScanType), nullable=False, index=True)
    
    # Organization
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    organization = relationship("Organization", back_populates="scans")
    
    # Target configuration
    targets = Column(JSON, default=list)  # List of target assets/values
    config = Column(JSON, default=dict)  # Scan configuration options
    
    # Status tracking
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    progress = Column(Integer, default=0)  # 0-100 percentage
    current_step = Column(String(255), nullable=True)  # Current operation description
    
    # Results summary
    assets_discovered = Column(Integer, default=0)
    technologies_found = Column(Integer, default=0)
    vulnerabilities_found = Column(Integer, default=0)
    
    # Execution info
    started_by = Column(String(255), nullable=True)  # User who initiated
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Results
    results = Column(JSON, default=dict)  # Raw scan results
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    vulnerabilities = relationship("Vulnerability", back_populates="scan")
    
    def __repr__(self):
        return f"<Scan {self.scan_type.value}: {self.name}>"
