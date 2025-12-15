"""Organization schemas for request/response validation."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class OrganizationBase(BaseModel):
    """Base organization schema."""
    name: str = Field(..., min_length=2, max_length=255)
    description: Optional[str] = None
    domain: Optional[str] = None
    industry: Optional[str] = None


class OrganizationCreate(OrganizationBase):
    """Schema for creating a new organization."""
    pass


class OrganizationUpdate(BaseModel):
    """Schema for updating an organization."""
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    description: Optional[str] = None
    domain: Optional[str] = None
    industry: Optional[str] = None
    is_active: Optional[bool] = None


class OrganizationResponse(OrganizationBase):
    """Schema for organization response."""
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    # Asset and vulnerability counts (computed)
    asset_count: int = 0
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    class Config:
        from_attributes = True














