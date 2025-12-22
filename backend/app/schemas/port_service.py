"""Port and Service schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field

from app.models.port_service import Protocol, PortState


class PortServiceBase(BaseModel):
    """Base port service schema."""
    port: int = Field(..., ge=1, le=65535, description="Port number (1-65535)")
    protocol: Protocol = Field(default=Protocol.TCP, description="Network protocol")
    service_name: Optional[str] = Field(None, description="Service name (e.g., https, ssh)")


class PortServiceCreate(PortServiceBase):
    """Schema for creating a new port service."""
    asset_id: int
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_extra_info: Optional[str] = None
    cpe: Optional[str] = None
    banner: Optional[str] = None
    state: PortState = PortState.OPEN
    reason: Optional[str] = None
    discovered_by: Optional[str] = None
    is_ssl: bool = False
    ssl_version: Optional[str] = None
    ssl_cipher: Optional[str] = None
    ssl_cert_subject: Optional[str] = None
    ssl_cert_issuer: Optional[str] = None
    ssl_cert_expiry: Optional[datetime] = None
    is_risky: bool = False
    risk_reason: Optional[str] = None
    tags: List[str] = []
    metadata_: dict[str, Any] = Field(default={}, alias="metadata")


class PortServiceUpdate(BaseModel):
    """Schema for updating a port service."""
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_extra_info: Optional[str] = None
    cpe: Optional[str] = None
    banner: Optional[str] = None
    state: Optional[PortState] = None
    is_ssl: Optional[bool] = None
    ssl_version: Optional[str] = None
    ssl_cipher: Optional[str] = None
    is_risky: Optional[bool] = None
    risk_reason: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata_: Optional[dict[str, Any]] = Field(default=None, alias="metadata")


class PortServiceResponse(PortServiceBase):
    """Schema for port service response."""
    id: int
    asset_id: int
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_extra_info: Optional[str] = None
    cpe: Optional[str] = None
    banner: Optional[str] = None
    state: PortState
    reason: Optional[str] = None
    discovered_by: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    is_ssl: bool
    ssl_version: Optional[str] = None
    ssl_cipher: Optional[str] = None
    ssl_cert_subject: Optional[str] = None
    ssl_cert_issuer: Optional[str] = None
    ssl_cert_expiry: Optional[datetime] = None
    is_risky: bool
    risk_reason: Optional[str] = None
    tags: List[str] = []
    
    # Computed fields
    port_string: str = ""
    display_name: str = ""
    
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class PortServiceBulkCreate(BaseModel):
    """Schema for bulk creating port services."""
    asset_id: int
    ports: List[PortServiceCreate]


class PortServiceSummary(BaseModel):
    """Summary of a port service for compact display."""
    port: int
    protocol: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    state: str
    is_ssl: bool = False
    is_risky: bool = False


# ==================== REPORTING SCHEMAS ====================

class PortsByAssetReport(BaseModel):
    """Report of ports grouped by asset."""
    asset_id: int
    asset_name: str
    asset_value: str
    total_ports: int
    open_ports: int
    risky_ports: int
    ports: List[PortServiceSummary]


class PortDistributionReport(BaseModel):
    """Report showing port distribution across all assets."""
    port: int
    protocol: str
    service: Optional[str]
    count: int
    assets: List[str]  # List of asset values with this port


class ServiceDistributionReport(BaseModel):
    """Report showing service distribution across all assets."""
    service: str
    count: int
    ports: List[int]
    assets: List[str]


class RiskyPortsReport(BaseModel):
    """Report of risky/dangerous exposed ports."""
    total_risky_ports: int
    by_risk_type: dict[str, int]
    ports: List[dict]


class ExposedServicesReport(BaseModel):
    """Comprehensive report of exposed services."""
    total_assets: int
    total_ports: int
    total_services: int
    risky_ports_count: int
    
    # Top statistics
    top_ports: List[dict]
    top_services: List[dict]
    
    # By protocol
    tcp_ports: int
    udp_ports: int
    
    # By state
    open_ports: int
    filtered_ports: int
    
    # Risky findings
    risky_ports: List[dict]
    
    # SSL/TLS stats
    ssl_enabled_ports: int
    expiring_certs: int


class PortSearchRequest(BaseModel):
    """Schema for searching ports."""
    organization_id: Optional[int] = None
    ports: Optional[List[int]] = None
    protocols: Optional[List[Protocol]] = None
    services: Optional[List[str]] = None
    state: Optional[PortState] = None
    is_risky: Optional[bool] = None
    is_ssl: Optional[bool] = None
    asset_ids: Optional[List[int]] = None
















