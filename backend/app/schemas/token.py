"""Token schemas for JWT authentication."""

from typing import Optional
from pydantic import BaseModel


class Token(BaseModel):
    """Schema for token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    """Schema for decoded token payload."""
    sub: Optional[str] = None
    type: Optional[str] = None
    exp: Optional[int] = None




