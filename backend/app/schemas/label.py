"""Label schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class LabelBase(BaseModel):
    """Base label schema."""
    name: str = Field(..., min_length=1, max_length=100)
    color: str = Field(default="#6366f1", pattern="^#[0-9a-fA-F]{6}$")
    description: Optional[str] = None


class LabelCreate(LabelBase):
    """Schema for creating a new label."""
    organization_id: int


class LabelUpdate(BaseModel):
    """Schema for updating a label."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    color: Optional[str] = Field(None, pattern="^#[0-9a-fA-F]{6}$")
    description: Optional[str] = None


class LabelResponse(LabelBase):
    """Schema for label response."""
    id: int
    organization_id: int
    asset_count: int = 0
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class LabelWithAssets(LabelResponse):
    """Label response with asset IDs."""
    asset_ids: List[int] = []


class AssetLabelAssignment(BaseModel):
    """Schema for assigning/removing labels from assets."""
    asset_ids: List[int]
    label_ids: List[int]


class BulkLabelRequest(BaseModel):
    """Schema for bulk label operations."""
    asset_ids: List[int]
    add_labels: List[int] = []
    remove_labels: List[int] = []


# Predefined label colors for UI
LABEL_COLORS = [
    "#ef4444",  # Red
    "#f97316",  # Orange
    "#f59e0b",  # Amber
    "#eab308",  # Yellow
    "#84cc16",  # Lime
    "#22c55e",  # Green
    "#10b981",  # Emerald
    "#14b8a6",  # Teal
    "#06b6d4",  # Cyan
    "#0ea5e9",  # Sky
    "#3b82f6",  # Blue
    "#6366f1",  # Indigo
    "#8b5cf6",  # Violet
    "#a855f7",  # Purple
    "#d946ef",  # Fuchsia
    "#ec4899",  # Pink
    "#f43f5e",  # Rose
    "#64748b",  # Slate
]

