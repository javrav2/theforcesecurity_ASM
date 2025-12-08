"""Scan schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, Field

from app.models.scan import ScanType, ScanStatus


class ScanBase(BaseModel):
    """Base scan schema."""
    name: str = Field(..., min_length=1, max_length=255)
    scan_type: ScanType


class ScanCreate(ScanBase):
    """Schema for creating a new scan."""
    organization_id: int
    targets: List[str] = []
    config: dict[str, Any] = {}


class ScanUpdate(BaseModel):
    """Schema for updating a scan."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[ScanStatus] = None
    progress: Optional[int] = Field(None, ge=0, le=100)
    error_message: Optional[str] = None
    results: Optional[dict[str, Any]] = None


class ScanResponse(ScanBase):
    """Schema for scan response."""
    id: int
    organization_id: int
    targets: List[str] = []
    config: dict[str, Any] = {}
    status: ScanStatus
    progress: int
    assets_discovered: int
    vulnerabilities_found: int
    started_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    results: dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True






