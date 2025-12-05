"""Port findings schemas for request/response validation."""

from typing import Optional, List
from pydantic import BaseModel, Field


class GenerateFindingsRequest(BaseModel):
    """Schema for generating findings from port scans."""
    organization_id: int
    scan_id: Optional[int] = Field(default=None, description="Scan ID to associate findings with")
    asset_ids: Optional[List[int]] = Field(default=None, description="Specific assets to generate findings for")
    port_ids: Optional[List[int]] = Field(default=None, description="Specific ports to generate findings for")


class FindingSummary(BaseModel):
    """Summary of a generated finding."""
    id: int
    title: str
    severity: str
    asset: Optional[str]
    port: int


class GenerateFindingsResponse(BaseModel):
    """Schema for findings generation response."""
    success: bool
    findings_created: int
    findings_updated: int
    by_severity: dict
    findings: List[FindingSummary] = []


class PortRiskSummary(BaseModel):
    """Summary of port-based risks."""
    total_open_ports: int
    critical_exposures: int
    high_risk_exposures: int
    medium_risk_exposures: int
    critical_ports: List[dict]
    high_risk_ports: List[dict]
    recommendations: List[str]


class PortFindingRule(BaseModel):
    """Schema for a port finding rule."""
    ports: List[int]
    title: str
    description: str
    severity: str
    remediation: str
    tags: List[str]
    cwe_id: Optional[str] = None



