"""Pydantic schemas for external discovery and API configuration."""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# =============================================================================
# API Configuration Schemas
# =============================================================================

class APIConfigCreate(BaseModel):
    """Schema for creating an API configuration."""
    service_name: str = Field(..., description="Service name (e.g., virustotal, otx, whoisxml)")
    api_key: str = Field(..., description="API key for the service")
    api_user: Optional[str] = Field(default=None, description="Username if required")
    api_secret: Optional[str] = Field(default=None, description="API secret if separate from key")
    config: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Service-specific configuration",
        examples=[{
            "organization_names": ["Company Inc"],
            "registration_emails": ["admin@company.com"]
        }]
    )


class APIConfigUpdate(BaseModel):
    """Schema for updating an API configuration."""
    api_key: Optional[str] = None
    api_user: Optional[str] = None
    api_secret: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class APIConfigResponse(BaseModel):
    """Response schema for API configuration (key masked)."""
    id: int
    organization_id: int
    service_name: str
    api_user: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_active: bool
    is_valid: bool
    last_used: Optional[datetime] = None
    usage_count: int
    daily_usage: int
    last_error: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    # Key is masked for security
    api_key_masked: Optional[str] = None
    
    class Config:
        from_attributes = True


class APIConfigListResponse(BaseModel):
    """List of API configurations."""
    configs: List[APIConfigResponse]
    available_services: List[str]


# =============================================================================
# External Discovery Request Schemas
# =============================================================================

class ExternalDiscoveryRequest(BaseModel):
    """Request schema for running external discovery."""
    domain: str = Field(..., description="Primary domain to discover (e.g., rockwellautomation.com)")
    organization_id: int = Field(..., description="Organization ID")
    
    # Options for what sources to use
    include_free_sources: bool = Field(default=True, description="Include free sources (crt.sh, wayback, rapiddns, m365)")
    include_paid_sources: bool = Field(default=True, description="Include paid API sources")
    
    # Specific sources to enable/disable
    sources: Optional[List[str]] = Field(
        default=None,
        description="Specific sources to use (if None, uses all available)",
        examples=[["crtsh", "virustotal", "otx", "wayback", "rapiddns", "m365"]]
    )
    
    # Additional configuration
    organization_names: Optional[List[str]] = Field(
        default=None,
        description="Organization names for WHOIS lookups"
    )
    registration_emails: Optional[List[str]] = Field(
        default=None,
        description="Registration emails for reverse WHOIS"
    )
    
    # Options
    create_assets: bool = Field(default=True, description="Automatically create discovered assets")
    skip_existing: bool = Field(default=True, description="Skip assets that already exist")


class SourceResult(BaseModel):
    """Result from a single discovery source."""
    source: str
    success: bool
    domains_found: int = 0
    subdomains_found: int = 0
    ips_found: int = 0
    cidrs_found: int = 0
    elapsed_time: float = 0.0
    error: Optional[str] = None


class ExternalDiscoveryResponse(BaseModel):
    """Response schema for external discovery."""
    domain: str
    organization_id: int
    
    # Summary
    total_domains: int
    total_subdomains: int
    total_ips: int
    total_cidrs: int
    
    # Results by source
    source_results: List[SourceResult]
    
    # Aggregated unique findings
    domains: List[str]
    subdomains: List[str]
    ip_addresses: List[str]
    ip_ranges: List[str]
    
    # Asset creation stats
    assets_created: int = 0
    assets_skipped: int = 0
    
    # Timing
    total_elapsed_time: float


class SingleSourceRequest(BaseModel):
    """Request to run a single discovery source."""
    domain: str
    organization_id: int
    source: str = Field(..., description="Source to use (e.g., virustotal, wayback, crtsh)")
    create_assets: bool = Field(default=False, description="Create assets from results")


class SingleSourceResponse(BaseModel):
    """Response from a single discovery source."""
    source: str
    domain: str
    success: bool
    domains: List[str] = []
    subdomains: List[str] = []
    ip_addresses: List[str] = []
    ip_ranges: List[str] = []
    error: Optional[str] = None
    elapsed_time: float = 0.0
    assets_created: int = 0


# =============================================================================
# Available Services
# =============================================================================

class AvailableServicesResponse(BaseModel):
    """List of available external discovery services."""
    paid_services: List[Dict[str, Any]]
    free_services: List[Dict[str, Any]]
    configured_services: List[str]


# Service information
PAID_SERVICES_INFO = [
    {
        "name": "virustotal",
        "display_name": "VirusTotal",
        "description": "Subdomain enumeration from VT database",
        "requires_key": True,
        "rate_limit": "4/second, varies by plan",
        "website": "https://www.virustotal.com/",
    },
    {
        "name": "otx",
        "display_name": "AlienVault OTX",
        "description": "Passive DNS and URL data from OTX",
        "requires_key": True,
        "rate_limit": "10,000/hour",
        "website": "https://otx.alienvault.com/",
    },
    {
        "name": "whoisxml",
        "display_name": "WhoisXML API",
        "description": "IP ranges and CIDRs by organization name",
        "requires_key": True,
        "rate_limit": "Varies by plan",
        "website": "https://whoisxmlapi.com/",
        "config_options": ["organization_names"],
    },
    {
        "name": "whoxy",
        "display_name": "Whoxy",
        "description": "Reverse WHOIS by registration email",
        "requires_key": True,
        "rate_limit": "Varies by plan",
        "website": "https://www.whoxy.com/",
        "config_options": ["registration_emails"],
    },
    {
        "name": "shodan",
        "display_name": "Shodan",
        "description": "Internet-wide scanning data",
        "requires_key": True,
        "rate_limit": "1/second",
        "website": "https://www.shodan.io/",
    },
    {
        "name": "censys",
        "display_name": "Censys",
        "description": "Internet scanning and certificate data",
        "requires_key": True,
        "rate_limit": "0.4/second, 250/day (free)",
        "website": "https://censys.io/",
    },
    {
        "name": "securitytrails",
        "display_name": "SecurityTrails",
        "description": "Historical DNS and WHOIS data",
        "requires_key": True,
        "rate_limit": "50/month (free)",
        "website": "https://securitytrails.com/",
    },
]

FREE_SERVICES_INFO = [
    {
        "name": "crtsh",
        "display_name": "crt.sh",
        "description": "Certificate transparency log search",
        "requires_key": False,
        "rate_limit": "Be respectful",
        "website": "https://crt.sh/",
    },
    {
        "name": "wayback",
        "display_name": "Wayback Machine",
        "description": "Historical web crawl data",
        "requires_key": False,
        "rate_limit": "1/second recommended",
        "website": "https://web.archive.org/",
    },
    {
        "name": "rapiddns",
        "display_name": "RapidDNS",
        "description": "DNS database subdomain lookup",
        "requires_key": False,
        "rate_limit": "Unknown",
        "website": "https://rapiddns.io/",
    },
    {
        "name": "m365",
        "display_name": "Microsoft 365",
        "description": "Federated domain discovery via autodiscover",
        "requires_key": False,
        "rate_limit": "1/second recommended",
        "website": "https://www.microsoft.com/",
    },
]














