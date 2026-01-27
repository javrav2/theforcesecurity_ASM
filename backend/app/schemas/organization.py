"""Organization schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List
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
    # Discovery keyword settings
    commoncrawl_org_name: Optional[str] = None
    commoncrawl_keywords: Optional[List[str]] = None
    sni_keywords: Optional[List[str]] = None


class OrganizationResponse(OrganizationBase):
    """Schema for organization response."""
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    # Discovery keyword settings
    commoncrawl_org_name: Optional[str] = None
    commoncrawl_keywords: Optional[List[str]] = None
    sni_keywords: Optional[List[str]] = None
    
    # Asset and vulnerability counts (computed)
    asset_count: int = 0
    vulnerability_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    class Config:
        from_attributes = True


class DiscoverySettingsUpdate(BaseModel):
    """Schema for updating discovery keyword settings."""
    commoncrawl_org_name: Optional[str] = None
    commoncrawl_keywords: Optional[List[str]] = None
    sni_keywords: Optional[List[str]] = None


class DiscoverySettingsResponse(BaseModel):
    """Schema for discovery settings response."""
    organization_id: int
    commoncrawl_org_name: Optional[str] = None
    commoncrawl_keywords: List[str] = []
    sni_keywords: List[str] = []
    
    class Config:
        from_attributes = True

















