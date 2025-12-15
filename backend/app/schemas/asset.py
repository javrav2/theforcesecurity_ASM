"""Asset schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field

from app.models.asset import AssetType, AssetStatus


class AssetBase(BaseModel):
    """Base asset schema."""
    name: str = Field(..., min_length=1, max_length=255)
    asset_type: AssetType
    value: str = Field(..., min_length=1, max_length=500)


class AssetCreate(AssetBase):
    """Schema for creating a new asset."""
    organization_id: int
    parent_id: Optional[int] = None
    description: Optional[str] = None
    tags: List[str] = []
    metadata_: dict[str, Any] = Field(default={})
    discovery_source: Optional[str] = None
    criticality: str = "medium"
    is_monitored: bool = True


class AssetUpdate(BaseModel):
    """Schema for updating an asset."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    asset_type: Optional[AssetType] = None
    value: Optional[str] = Field(None, min_length=1, max_length=500)
    status: Optional[AssetStatus] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata_: Optional[dict[str, Any]] = Field(default=None)
    risk_score: Optional[int] = Field(None, ge=0, le=100)
    criticality: Optional[str] = None
    is_monitored: Optional[bool] = None


class TechnologySummary(BaseModel):
    """Summary of a technology associated with an asset."""
    name: str
    slug: str
    categories: List[str] = []
    version: Optional[str] = None


class PortServiceSummary(BaseModel):
    """Summary of a port service for asset response."""
    id: int
    port: int
    protocol: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    state: str
    is_ssl: bool = False
    is_risky: bool = False
    port_string: str  # e.g., "443-tcp-https"


class AssetResponse(AssetBase):
    """Schema for asset response."""
    id: int
    organization_id: int
    parent_id: Optional[int] = None
    status: AssetStatus
    description: Optional[str] = None
    tags: List[str] = []
    metadata_: dict[str, Any] = Field(default={})
    discovery_source: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    criticality: str
    is_monitored: bool
    
    # HTTP info
    http_status: Optional[int] = None
    http_title: Optional[str] = None
    
    # DNS info
    dns_records: dict = {}
    
    # Geo-location info
    ip_address: Optional[str] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    isp: Optional[str] = None
    
    # Scope and ownership
    in_scope: bool = True
    is_owned: bool = False
    netblock_id: Optional[int] = None
    asn: Optional[str] = None
    
    # Technologies
    technologies: List[TechnologySummary] = []
    
    # Port services
    port_services: List[PortServiceSummary] = []
    open_ports_count: int = 0
    risky_ports_count: int = 0
    
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class AssetWithPortsResponse(AssetResponse):
    """Asset response with detailed port information."""
    
    # Detailed port breakdown
    ports_by_protocol: dict = {}  # {"tcp": [...], "udp": [...]}
    ports_by_service: dict = {}   # {"https": [...], "ssh": [...]}


class AssetTreeResponse(BaseModel):
    """Hierarchical view of assets for a domain."""
    domain: str
    total_assets: int
    total_ports: int
    total_risky_ports: int
    asset_tree: dict


class AssetPortsSummary(BaseModel):
    """Summary of ports for an asset."""
    asset_id: int
    asset_value: str
    total_ports: int
    open_ports: int
    filtered_ports: int
    risky_ports: int
    tcp_ports: int
    udp_ports: int
    services: List[str]
    ports: List[PortServiceSummary]
