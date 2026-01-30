"""Finding Exception routes for tracking risk accepted and mitigated findings."""

from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.database import get_db
from app.models.finding_exception import FindingException, ExceptionType, ExceptionStatus
from app.models.vulnerability import Vulnerability, VulnerabilityStatus
from app.models.asset import Asset
from app.models.user import User
from app.api.deps import get_current_active_user, require_analyst

router = APIRouter(prefix="/exceptions", tags=["Exceptions"])


# Pydantic schemas
class ExceptionCreate(BaseModel):
    title: str
    exception_type: str  # risk_accepted, mitigated, false_positive, deferred
    justification: str
    business_impact: Optional[str] = None
    compensating_controls: Optional[str] = None
    residual_risk: Optional[str] = None  # low, medium, high, critical
    organization_id: int
    expiration_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    finding_ids: Optional[List[int]] = None  # Findings to link to this exception
    tags: Optional[List[str]] = None


class ExceptionUpdate(BaseModel):
    title: Optional[str] = None
    exception_type: Optional[str] = None
    status: Optional[str] = None
    justification: Optional[str] = None
    business_impact: Optional[str] = None
    compensating_controls: Optional[str] = None
    residual_risk: Optional[str] = None
    expiration_date: Optional[datetime] = None
    review_date: Optional[datetime] = None
    approved_by: Optional[str] = None
    tags: Optional[List[str]] = None


class ExceptionResponse(BaseModel):
    id: int
    title: str
    exception_type: str
    status: str
    justification: str
    business_impact: Optional[str]
    compensating_controls: Optional[str]
    residual_risk: Optional[str]
    organization_id: int
    requested_by: str
    approved_by: Optional[str]
    effective_date: datetime
    expiration_date: Optional[datetime]
    review_date: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    approved_at: Optional[datetime]
    findings_count: int
    is_expired: bool
    is_active: bool
    tags: List[str]

    class Config:
        from_attributes = True


def check_org_access(user: User, organization_id: int) -> bool:
    """Check if user has access to organization."""
    if user.is_superuser:
        return True
    return user.organization_id == organization_id


def build_exception_response(exc: FindingException) -> dict:
    """Build exception response with computed fields."""
    return {
        "id": exc.id,
        "title": exc.title,
        "exception_type": exc.exception_type.value,
        "status": exc.status.value,
        "justification": exc.justification,
        "business_impact": exc.business_impact,
        "compensating_controls": exc.compensating_controls,
        "residual_risk": exc.residual_risk,
        "organization_id": exc.organization_id,
        "requested_by": exc.requested_by,
        "approved_by": exc.approved_by,
        "effective_date": exc.effective_date,
        "expiration_date": exc.expiration_date,
        "review_date": exc.review_date,
        "created_at": exc.created_at,
        "updated_at": exc.updated_at,
        "approved_at": exc.approved_at,
        "findings_count": len(exc.findings) if exc.findings else 0,
        "is_expired": exc.is_expired,
        "is_active": exc.is_active,
        "tags": exc.tags or [],
    }


@router.get("/")
def list_exceptions(
    organization_id: Optional[int] = None,
    exception_type: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    include_expired: bool = False,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """List all exceptions with filtering options."""
    query = db.query(FindingException)
    
    # Organization filter
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return []
        query = query.filter(FindingException.organization_id == current_user.organization_id)
    elif organization_id:
        query = query.filter(FindingException.organization_id == organization_id)
    
    # Type filter
    if exception_type:
        try:
            type_enum = ExceptionType(exception_type)
            query = query.filter(FindingException.exception_type == type_enum)
        except ValueError:
            pass
    
    # Status filter
    if status_filter:
        try:
            status_enum = ExceptionStatus(status_filter)
            query = query.filter(FindingException.status == status_enum)
        except ValueError:
            pass
    
    # Expiration filter
    if not include_expired:
        query = query.filter(
            (FindingException.expiration_date == None) | 
            (FindingException.expiration_date > datetime.utcnow())
        )
    
    exceptions = query.order_by(FindingException.created_at.desc()).offset(skip).limit(limit).all()
    
    return [build_exception_response(e) for e in exceptions]


@router.get("/stats")
def get_exception_stats(
    organization_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get exception statistics."""
    query = db.query(FindingException)
    
    if not current_user.is_superuser:
        if not current_user.organization_id:
            return {"total": 0, "by_type": {}, "by_status": {}, "active": 0, "expired": 0}
        query = query.filter(FindingException.organization_id == current_user.organization_id)
    elif organization_id:
        query = query.filter(FindingException.organization_id == organization_id)
    
    exceptions = query.all()
    
    by_type = {}
    by_status = {}
    active_count = 0
    expired_count = 0
    total_findings = 0
    
    for exc in exceptions:
        # Count by type
        type_key = exc.exception_type.value
        by_type[type_key] = by_type.get(type_key, 0) + 1
        
        # Count by status
        status_key = exc.status.value
        by_status[status_key] = by_status.get(status_key, 0) + 1
        
        # Count active/expired
        if exc.is_active:
            active_count += 1
        if exc.is_expired:
            expired_count += 1
        
        # Count linked findings
        total_findings += len(exc.findings) if exc.findings else 0
    
    return {
        "total": len(exceptions),
        "by_type": by_type,
        "by_status": by_status,
        "active": active_count,
        "expired": expired_count,
        "total_linked_findings": total_findings,
    }


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_exception(
    data: ExceptionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Create a new exception."""
    if not check_org_access(current_user, data.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this organization"
        )
    
    # Validate exception type
    try:
        exc_type = ExceptionType(data.exception_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid exception type. Must be one of: {[e.value for e in ExceptionType]}"
        )
    
    # Create exception
    exception = FindingException(
        title=data.title,
        exception_type=exc_type,
        status=ExceptionStatus.APPROVED,  # Auto-approve for now
        justification=data.justification,
        business_impact=data.business_impact,
        compensating_controls=data.compensating_controls,
        residual_risk=data.residual_risk,
        organization_id=data.organization_id,
        requested_by=current_user.email or current_user.username,
        approved_by=current_user.email or current_user.username,  # Auto-approve
        approved_at=datetime.utcnow(),
        expiration_date=data.expiration_date,
        review_date=data.review_date,
        tags=data.tags or [],
    )
    
    db.add(exception)
    db.flush()  # Get the ID
    
    # Link findings if provided
    linked_count = 0
    if data.finding_ids:
        for finding_id in data.finding_ids:
            finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
            if finding:
                # Check access
                asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
                if asset and check_org_access(current_user, asset.organization_id):
                    finding.exception_id = exception.id
                    # Update finding status based on exception type
                    if exc_type == ExceptionType.RISK_ACCEPTED:
                        finding.status = VulnerabilityStatus.ACCEPTED
                    elif exc_type == ExceptionType.MITIGATED:
                        finding.status = VulnerabilityStatus.MITIGATED
                    elif exc_type == ExceptionType.FALSE_POSITIVE:
                        finding.status = VulnerabilityStatus.FALSE_POSITIVE
                    linked_count += 1
    
    db.commit()
    db.refresh(exception)
    
    response = build_exception_response(exception)
    response["linked_findings"] = linked_count
    return response


@router.get("/{exception_id}")
def get_exception(
    exception_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get exception by ID."""
    exception = db.query(FindingException).filter(FindingException.id == exception_id).first()
    
    if not exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exception not found"
        )
    
    if not check_org_access(current_user, exception.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    response = build_exception_response(exception)
    
    # Include linked findings details
    response["findings"] = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value if f.severity else None,
            "status": f.status.value if f.status else None,
            "asset_id": f.asset_id,
            "host": f.asset.value if f.asset else None,
        }
        for f in exception.findings
    ]
    
    return response


@router.put("/{exception_id}")
def update_exception(
    exception_id: int,
    data: ExceptionUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Update an exception."""
    exception = db.query(FindingException).filter(FindingException.id == exception_id).first()
    
    if not exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exception not found"
        )
    
    if not check_org_access(current_user, exception.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    update_dict = data.model_dump(exclude_unset=True)
    
    # Handle enum fields
    if "exception_type" in update_dict:
        try:
            update_dict["exception_type"] = ExceptionType(update_dict["exception_type"])
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid exception type")
    
    if "status" in update_dict:
        try:
            new_status = ExceptionStatus(update_dict["status"])
            update_dict["status"] = new_status
            # Set approved timestamp if approving
            if new_status == ExceptionStatus.APPROVED and exception.status != ExceptionStatus.APPROVED:
                update_dict["approved_at"] = datetime.utcnow()
                update_dict["approved_by"] = current_user.email or current_user.username
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status")
    
    for field, value in update_dict.items():
        setattr(exception, field, value)
    
    db.commit()
    db.refresh(exception)
    
    return build_exception_response(exception)


@router.delete("/{exception_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_exception(
    exception_id: int,
    unlink_findings: bool = Query(True, description="Unlink findings and reset their status to open"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Delete an exception."""
    exception = db.query(FindingException).filter(FindingException.id == exception_id).first()
    
    if not exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exception not found"
        )
    
    if not check_org_access(current_user, exception.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Unlink findings if requested
    if unlink_findings:
        for finding in exception.findings:
            finding.exception_id = None
            finding.status = VulnerabilityStatus.OPEN
    
    db.delete(exception)
    db.commit()
    
    return None


@router.post("/{exception_id}/link-findings")
def link_findings_to_exception(
    exception_id: int,
    finding_ids: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Link findings to an exception."""
    exception = db.query(FindingException).filter(FindingException.id == exception_id).first()
    
    if not exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exception not found"
        )
    
    if not check_org_access(current_user, exception.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    linked_count = 0
    for finding_id in finding_ids:
        finding = db.query(Vulnerability).filter(Vulnerability.id == finding_id).first()
        if finding:
            asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
            if asset and check_org_access(current_user, asset.organization_id):
                finding.exception_id = exception.id
                # Update status based on exception type
                if exception.exception_type == ExceptionType.RISK_ACCEPTED:
                    finding.status = VulnerabilityStatus.ACCEPTED
                elif exception.exception_type == ExceptionType.MITIGATED:
                    finding.status = VulnerabilityStatus.MITIGATED
                elif exception.exception_type == ExceptionType.FALSE_POSITIVE:
                    finding.status = VulnerabilityStatus.FALSE_POSITIVE
                linked_count += 1
    
    db.commit()
    
    return {
        "success": True,
        "linked_count": linked_count,
        "exception_id": exception_id
    }


@router.post("/{exception_id}/unlink-findings")
def unlink_findings_from_exception(
    exception_id: int,
    finding_ids: List[int],
    reset_status: bool = Query(True, description="Reset finding status to open"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst)
):
    """Unlink findings from an exception."""
    exception = db.query(FindingException).filter(FindingException.id == exception_id).first()
    
    if not exception:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Exception not found"
        )
    
    if not check_org_access(current_user, exception.organization_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    unlinked_count = 0
    for finding_id in finding_ids:
        finding = db.query(Vulnerability).filter(
            Vulnerability.id == finding_id,
            Vulnerability.exception_id == exception_id
        ).first()
        if finding:
            finding.exception_id = None
            if reset_status:
                finding.status = VulnerabilityStatus.OPEN
            unlinked_count += 1
    
    db.commit()
    
    return {
        "success": True,
        "unlinked_count": unlinked_count,
        "exception_id": exception_id
    }
