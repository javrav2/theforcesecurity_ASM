"""API dependencies for authentication and authorization."""

from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.db.database import get_db
from app.models.user import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_current_user_optional(
    db: Session = Depends(get_db),
    token: Optional[str] = Depends(oauth2_scheme_optional)
) -> Optional[User]:
    """Get the current authenticated user from JWT token, or None if not authenticated."""
    if not token:
        return None
    
    payload = decode_token(token)
    if payload is None:
        return None
    
    # Check token type
    if payload.get("type") != "access":
        return None
    
    subject: str = payload.get("sub")
    if subject is None:
        return None
    
    user = db.query(User).filter(
        (User.username == subject) | (User.email == subject)
    ).first()
    
    return user


def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(oauth2_scheme)
) -> User:
    """Get the current authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception
    
    # Check token type
    if payload.get("type") != "access":
        raise credentials_exception
    
    subject: str = payload.get("sub")
    if subject is None:
        raise credentials_exception
    
    user = db.query(User).filter(
        (User.username == subject) | (User.email == subject)
    ).first()
    if user is None:
        raise credentials_exception
    
    return user


def get_current_user_active_only(
    current_user: User = Depends(get_current_user)
) -> User:
    """Active-user check WITHOUT the password-change gate.

    Used only by the endpoints a pending-reset user must still reach:
    GET /auth/me and POST /auth/change-password.
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


def get_current_active_user(
    current_user: User = Depends(get_current_user_active_only)
) -> User:
    """Get current active user, enforcing the forced-password-change gate.

    A user flagged must_change_password can authenticate but cannot use the
    platform until they set a new password, so every route built on this
    dependency (and the role checkers below) is blocked with 403 until then.
    """
    if getattr(current_user, "must_change_password", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="password_change_required",
        )
    return current_user


def get_current_superuser(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current superuser."""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough privileges"
        )
    return current_user


class RoleChecker:
    """Dependency class for role-based access control."""
    
    def __init__(self, allowed_roles: list[UserRole]):
        self.allowed_roles = allowed_roles
    
    def __call__(self, user: User = Depends(get_current_active_user)) -> User:
        if user.is_superuser:
            return user
        if user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not permitted for your role"
            )
        return user


# Pre-configured role checkers
require_admin = RoleChecker([UserRole.ADMIN])
require_analyst = RoleChecker([UserRole.ADMIN, UserRole.ANALYST])
require_viewer = RoleChecker([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])






