"""Netblock schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field


class NetblockBase(BaseModel):
    """Base netblock schema."""
    inetnum: str
    start_ip: str
    end_ip: str
    cidr_notation: Optional[str] = None
    ip_count: int = 0
    ip_version: str = "ipv4"


class NetblockCreate(NetblockBase):
    """Schema for creating a new netblock."""
    organization_id: int
    is_owned: bool = False
    in_scope: bool = True
    ownership_confidence: int = 0
    
    # ASN info
    asn: Optional[str] = None
    as_name: Optional[str] = None
    as_type: Optional[str] = None
    route: Optional[str] = None
    as_domain: Optional[str] = None
    
    # Network details
    netname: Optional[str] = None
    nethandle: Optional[str] = None
    description: Optional[str] = None
    
    # Geographic
    country: Optional[str] = None
    city: Optional[str] = None
    address: Optional[str] = None
    
    # Org details from WHOIS
    org_name: Optional[str] = None
    org_email: Optional[str] = None
    org_phone: Optional[str] = None
    org_country: Optional[str] = None
    org_city: Optional[str] = None
    org_postal_code: Optional[str] = None
    
    discovery_source: str = "manual"
    tags: List[str] = []


class NetblockUpdate(BaseModel):
    """Schema for updating a netblock."""
    is_owned: Optional[bool] = None
    in_scope: Optional[bool] = None
    ownership_confidence: Optional[int] = Field(None, ge=0, le=100)
    description: Optional[str] = None
    tags: Optional[List[str]] = None


class NetblockResponse(NetblockBase):
    """Schema for netblock response."""
    id: int
    organization_id: int
    
    is_owned: bool
    in_scope: bool
    ownership_confidence: int
    
    # ASN info
    asn: Optional[str] = None
    as_name: Optional[str] = None
    as_type: Optional[str] = None
    route: Optional[str] = None
    as_domain: Optional[str] = None
    
    # Network details
    netname: Optional[str] = None
    nethandle: Optional[str] = None
    description: Optional[str] = None
    
    # Geographic
    country: Optional[str] = None
    city: Optional[str] = None
    address: Optional[str] = None
    
    # Org details from WHOIS
    org_name: Optional[str] = None
    org_email: Optional[str] = None
    org_phone: Optional[str] = None
    org_country: Optional[str] = None
    org_city: Optional[str] = None
    org_postal_code: Optional[str] = None
    
    # Discovery
    discovery_source: Optional[str] = None
    discovered_at: datetime
    last_verified: Optional[datetime] = None
    
    # Scan tracking
    last_scanned: Optional[datetime] = None
    scan_count: int = 0
    
    tags: List[str] = []
    
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class NetblockSummary(BaseModel):
    """Summary statistics for netblocks."""
    total_netblocks: int = 0
    owned_netblocks: int = 0
    in_scope_netblocks: int = 0
    out_of_scope_netblocks: int = 0
    total_ips: int = 0
    owned_ips: int = 0
    in_scope_ips: int = 0
    ipv4_netblocks: int = 0
    ipv6_netblocks: int = 0
    scanned_netblocks: int = 0
    unscanned_netblocks: int = 0


class NetblockDiscoveryRequest(BaseModel):
    """Request to discover netblocks for an organization."""
    organization_id: int
    search_terms: List[str]  # Organization names to search for
    include_variations: bool = True  # Include variations like "Inc", "Inc." etc.


class NetblockDiscoveryResponse(BaseModel):
    """Response from netblock discovery."""
    organization_id: int
    search_terms: List[str]
    netblocks_found: int
    netblocks_created: int
    owned_count: int
    total_ips: int
    details: List[dict] = []
