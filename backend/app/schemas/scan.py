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
    label_ids: List[int] = []  # Optional: scan assets with these labels
    match_all_labels: bool = False  # If true, assets must have ALL specified labels
    config: dict[str, Any] = {}


class ScanByLabelRequest(BaseModel):
    """Schema for starting a scan by label."""
    name: str = Field(..., min_length=1, max_length=255)
    scan_type: ScanType
    organization_id: int
    label_ids: List[int]
    match_all_labels: bool = False
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
    organization_name: Optional[str] = None
    targets: List[str] = []
    config: dict[str, Any] = {}
    status: ScanStatus
    progress: Optional[int] = 0
    assets_discovered: Optional[int] = 0
    technologies_found: Optional[int] = 0
    vulnerabilities_found: Optional[int] = 0
    targets_count: Optional[int] = 0
    findings_count: Optional[int] = 0
    started_by: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    results: Optional[dict[str, Any]] = {}
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True













