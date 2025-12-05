"""Technology schemas for request/response validation."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


class TechnologyBase(BaseModel):
    """Base technology schema."""
    name: str
    slug: str
    categories: List[str] = []


class TechnologyCreate(TechnologyBase):
    """Schema for creating a new technology."""
    description: Optional[str] = None
    website: Optional[str] = None
    icon: Optional[str] = None
    cpe: Optional[str] = None


class TechnologyResponse(TechnologyBase):
    """Schema for technology response."""
    id: int
    description: Optional[str] = None
    website: Optional[str] = None
    icon: Optional[str] = None
    cpe: Optional[str] = None
    created_at: datetime
    
    class Config:
        from_attributes = True


class DetectedTechnologyResponse(BaseModel):
    """Schema for detected technology in scan results."""
    name: str
    slug: str
    version: Optional[str] = None
    confidence: int = 100
    categories: List[str] = []
    website: Optional[str] = None


class AssetTechnologyResponse(BaseModel):
    """Schema for technology associated with an asset."""
    technology: TechnologyResponse
    confidence: int
    version: Optional[str] = None
    detected_at: datetime
