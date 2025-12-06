"""Port scanner schemas for request/response validation."""

from typing import Optional, List
from pydantic import BaseModel, Field

from app.services.port_scanner_service import ScannerType


class PortScanRequest(BaseModel):
    """Schema for initiating a port scan."""
    targets: List[str] = Field(..., description="List of targets (IPs, domains, CIDRs)")
    organization_id: int = Field(..., description="Organization ID to associate results with")
    scanner: ScannerType = Field(default=ScannerType.NAABU, description="Scanner to use: naabu, masscan, nmap")
    ports: Optional[str] = Field(default=None, description="Port specification (e.g., '80,443' or '1-1000' or '-' for all)")
    
    # Naabu options
    top_ports: int = Field(default=100, ge=1, le=65535, description="Top N ports to scan (naabu)")
    exclude_cdn: bool = Field(default=True, description="Exclude CDN IPs (naabu)")
    
    # Rate limiting
    rate: int = Field(default=1000, ge=1, le=100000, description="Packets per second")
    
    # Nmap options
    service_detection: bool = Field(default=True, description="Enable service detection (nmap)")
    
    # Import options
    create_assets: bool = Field(default=True, description="Create assets for new hosts")
    import_results: bool = Field(default=True, description="Import results to database")


class PortScanResultResponse(BaseModel):
    """Schema for port scan results."""
    success: bool
    scanner: str
    targets_scanned: int
    ports_found: int
    duration_seconds: float
    errors: List[str] = []
    
    # Import summary
    ports_imported: int = 0
    ports_updated: int = 0
    assets_created: int = 0


class PortResultItem(BaseModel):
    """Schema for a single port result."""
    host: str
    ip: str
    port: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None
    scanner: str


class ImportPortsRequest(BaseModel):
    """Schema for importing port scan results from external tools."""
    organization_id: int
    scanner: ScannerType = Field(..., description="Scanner that produced the output")
    output: str = Field(..., description="Raw scanner output (JSON for naabu/masscan, XML for nmap)")
    create_assets: bool = Field(default=True, description="Create assets for new hosts")


class ImportPortsResponse(BaseModel):
    """Schema for import results."""
    success: bool
    ports_imported: int
    ports_updated: int
    assets_created: int
    errors: List[str] = []


class ScannerStatusResponse(BaseModel):
    """Schema for scanner status."""
    naabu: bool
    masscan: bool
    nmap: bool




