"""Discovery schemas for request/response validation."""

from typing import Optional, List, Any
from pydantic import BaseModel, Field


class DiscoveryRequest(BaseModel):
    """Schema for initiating a discovery scan."""
    domain: str = Field(..., description="Target domain to discover (e.g., rockwellautomation.com)")
    organization_id: int = Field(..., description="Organization ID to associate assets with")
    include_subdomains: bool = Field(default=True, description="Whether to enumerate subdomains")
    include_technology_scan: bool = Field(default=True, description="Whether to run Wappalyzer detection")
    custom_wordlist: Optional[List[str]] = Field(default=None, description="Custom subdomain wordlist")


class DiscoveryProgressResponse(BaseModel):
    """Schema for discovery progress updates."""
    scan_id: int
    current_step: str
    progress: int
    assets_found: int
    technologies_found: int
    errors: List[str] = []


class DiscoveryResultResponse(BaseModel):
    """Schema for discovery results."""
    success: bool
    domain: str
    scan_id: Optional[int] = None
    duration_seconds: float
    assets_discovered: int
    technologies_detected: int
    errors: List[str] = []
    summary: dict = {}


class DNSRecordResponse(BaseModel):
    """Schema for DNS record response."""
    record_type: str
    values: List[Any]


class SubdomainResponse(BaseModel):
    """Schema for discovered subdomain."""
    subdomain: str
    ip_addresses: List[str] = []
    source: str
    is_alive: bool = False


class TechnologyScanRequest(BaseModel):
    """Schema for technology-only scan request."""
    urls: List[str] = Field(..., description="URLs to scan for technologies")
    asset_ids: Optional[List[int]] = Field(default=None, description="Asset IDs to associate results with")


class TechnologyScanResultResponse(BaseModel):
    """Schema for technology scan results."""
    url: str
    technologies: List[dict] = []
    error: Optional[str] = None



