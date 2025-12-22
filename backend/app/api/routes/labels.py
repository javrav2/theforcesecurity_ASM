"""Label management API routes."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.database import get_db
from app.api.deps import get_current_user
from app.models.user import User
from app.models.label import Label, asset_labels
from app.models.asset import Asset
from app.schemas.label import (
    LabelCreate,
    LabelUpdate,
    LabelResponse,
    LabelWithAssets,
    AssetLabelAssignment,
    BulkLabelRequest,
    LABEL_COLORS,
)

router = APIRouter(prefix="/labels", tags=["labels"])


@router.get("/", response_model=List[LabelResponse])
def list_labels(
    organization_id: Optional[int] = None,
    search: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all labels, optionally filtered by organization."""
    query = db.query(Label)
    
    if organization_id:
        query = query.filter(Label.organization_id == organization_id)
    elif current_user.organization_id:
        query = query.filter(Label.organization_id == current_user.organization_id)
    
    if search:
        query = query.filter(Label.name.ilike(f"%{search}%"))
    
    labels = query.order_by(Label.name).offset(skip).limit(limit).all()
    
    # Add asset count to each label
    result = []
    for label in labels:
        label_dict = {
            "id": label.id,
            "name": label.name,
            "color": label.color,
            "description": label.description,
            "organization_id": label.organization_id,
            "asset_count": len(label.assets),
            "created_at": label.created_at,
            "updated_at": label.updated_at,
        }
        result.append(label_dict)
    
    return result


@router.get("/colors")
def get_label_colors():
    """Get list of predefined label colors."""
    return {"colors": LABEL_COLORS}


@router.get("/{label_id}", response_model=LabelWithAssets)
def get_label(
    label_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single label with its assets."""
    label = db.query(Label).filter(Label.id == label_id).first()
    if not label:
        raise HTTPException(status_code=404, detail="Label not found")
    
    return {
        "id": label.id,
        "name": label.name,
        "color": label.color,
        "description": label.description,
        "organization_id": label.organization_id,
        "asset_count": len(label.assets),
        "asset_ids": [a.id for a in label.assets],
        "created_at": label.created_at,
        "updated_at": label.updated_at,
    }


@router.post("/", response_model=LabelResponse, status_code=status.HTTP_201_CREATED)
def create_label(
    label_in: LabelCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new label."""
    # Check if label with same name exists in the organization
    existing = db.query(Label).filter(
        Label.organization_id == label_in.organization_id,
        Label.name == label_in.name
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Label '{label_in.name}' already exists in this organization"
        )
    
    label = Label(
        name=label_in.name,
        color=label_in.color,
        description=label_in.description,
        organization_id=label_in.organization_id,
    )
    db.add(label)
    db.commit()
    db.refresh(label)
    
    return {
        "id": label.id,
        "name": label.name,
        "color": label.color,
        "description": label.description,
        "organization_id": label.organization_id,
        "asset_count": 0,
        "created_at": label.created_at,
        "updated_at": label.updated_at,
    }


@router.post("/quick-create", response_model=LabelResponse)
def quick_create_label(
    name: str = Query(..., min_length=1, max_length=100),
    organization_id: int = Query(...),
    color: Optional[str] = Query(None, pattern="^#[0-9a-fA-F]{6}$"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Quick create a label with just a name (for inline creation in UI)."""
    # Check if label exists
    existing = db.query(Label).filter(
        Label.organization_id == organization_id,
        Label.name == name
    ).first()
    
    if existing:
        # Return existing label instead of error
        return {
            "id": existing.id,
            "name": existing.name,
            "color": existing.color,
            "description": existing.description,
            "organization_id": existing.organization_id,
            "asset_count": len(existing.assets),
            "created_at": existing.created_at,
            "updated_at": existing.updated_at,
        }
    
    # Pick a random color if not provided
    import random
    label_color = color or random.choice(LABEL_COLORS)
    
    label = Label(
        name=name,
        color=label_color,
        organization_id=organization_id,
    )
    db.add(label)
    db.commit()
    db.refresh(label)
    
    return {
        "id": label.id,
        "name": label.name,
        "color": label.color,
        "description": label.description,
        "organization_id": label.organization_id,
        "asset_count": 0,
        "created_at": label.created_at,
        "updated_at": label.updated_at,
    }


@router.put("/{label_id}", response_model=LabelResponse)
def update_label(
    label_id: int,
    label_in: LabelUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a label."""
    label = db.query(Label).filter(Label.id == label_id).first()
    if not label:
        raise HTTPException(status_code=404, detail="Label not found")
    
    # Check for duplicate name if updating name
    if label_in.name and label_in.name != label.name:
        existing = db.query(Label).filter(
            Label.organization_id == label.organization_id,
            Label.name == label_in.name
        ).first()
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Label '{label_in.name}' already exists"
            )
    
    if label_in.name is not None:
        label.name = label_in.name
    if label_in.color is not None:
        label.color = label_in.color
    if label_in.description is not None:
        label.description = label_in.description
    
    db.commit()
    db.refresh(label)
    
    return {
        "id": label.id,
        "name": label.name,
        "color": label.color,
        "description": label.description,
        "organization_id": label.organization_id,
        "asset_count": len(label.assets),
        "created_at": label.created_at,
        "updated_at": label.updated_at,
    }


@router.delete("/{label_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_label(
    label_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Delete a label."""
    label = db.query(Label).filter(Label.id == label_id).first()
    if not label:
        raise HTTPException(status_code=404, detail="Label not found")
    
    db.delete(label)
    db.commit()


@router.post("/{label_id}/assets", response_model=LabelWithAssets)
def assign_assets_to_label(
    label_id: int,
    asset_ids: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Assign assets to a label."""
    label = db.query(Label).filter(Label.id == label_id).first()
    if not label:
        raise HTTPException(status_code=404, detail="Label not found")
    
    # Get assets
    assets = db.query(Asset).filter(Asset.id.in_(asset_ids)).all()
    
    # Add assets that aren't already assigned
    for asset in assets:
        if asset not in label.assets:
            label.assets.append(asset)
    
    db.commit()
    db.refresh(label)
    
    return {
        "id": label.id,
        "name": label.name,
        "color": label.color,
        "description": label.description,
        "organization_id": label.organization_id,
        "asset_count": len(label.assets),
        "asset_ids": [a.id for a in label.assets],
        "created_at": label.created_at,
        "updated_at": label.updated_at,
    }


@router.delete("/{label_id}/assets", response_model=LabelWithAssets)
def remove_assets_from_label(
    label_id: int,
    asset_ids: List[int] = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove assets from a label."""
    label = db.query(Label).filter(Label.id == label_id).first()
    if not label:
        raise HTTPException(status_code=404, detail="Label not found")
    
    # Remove specified assets
    label.assets = [a for a in label.assets if a.id not in asset_ids]
    
    db.commit()
    db.refresh(label)
    
    return {
        "id": label.id,
        "name": label.name,
        "color": label.color,
        "description": label.description,
        "organization_id": label.organization_id,
        "asset_count": len(label.assets),
        "asset_ids": [a.id for a in label.assets],
        "created_at": label.created_at,
        "updated_at": label.updated_at,
    }


@router.post("/bulk-assign")
def bulk_assign_labels(
    request: BulkLabelRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Bulk assign or remove labels from multiple assets."""
    assets = db.query(Asset).filter(Asset.id.in_(request.asset_ids)).all()
    
    add_labels = db.query(Label).filter(Label.id.in_(request.add_labels)).all() if request.add_labels else []
    remove_labels = db.query(Label).filter(Label.id.in_(request.remove_labels)).all() if request.remove_labels else []
    
    for asset in assets:
        # Add labels
        for label in add_labels:
            if label not in asset.labels:
                asset.labels.append(label)
        
        # Remove labels
        for label in remove_labels:
            if label in asset.labels:
                asset.labels.remove(label)
    
    db.commit()
    
    return {
        "success": True,
        "assets_updated": len(assets),
        "labels_added": len(add_labels),
        "labels_removed": len(remove_labels),
    }


@router.get("/by-asset/{asset_id}", response_model=List[LabelResponse])
def get_labels_for_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get all labels assigned to an asset."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    
    return [
        {
            "id": label.id,
            "name": label.name,
            "color": label.color,
            "description": label.description,
            "organization_id": label.organization_id,
            "asset_count": len(label.assets),
            "created_at": label.created_at,
            "updated_at": label.updated_at,
        }
        for label in asset.labels
    ]


@router.get("/search-assets")
def search_assets_by_labels(
    label_ids: List[int] = Query(...),
    match_all: bool = Query(False, description="If true, assets must have ALL specified labels"),
    organization_id: Optional[int] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Search for assets that have specific labels."""
    if match_all:
        # Assets must have ALL specified labels
        query = db.query(Asset)
        
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
        
        for label_id in label_ids:
            query = query.filter(Asset.labels.any(Label.id == label_id))
        
        assets = query.offset(skip).limit(limit).all()
    else:
        # Assets must have ANY of the specified labels
        query = db.query(Asset).filter(Asset.labels.any(Label.id.in_(label_ids)))
        
        if organization_id:
            query = query.filter(Asset.organization_id == organization_id)
        
        assets = query.distinct().offset(skip).limit(limit).all()
    
    return {
        "total": len(assets),
        "assets": [
            {
                "id": a.id,
                "name": a.name,
                "value": a.value,
                "asset_type": a.asset_type.value,
                "labels": [{"id": l.id, "name": l.name, "color": l.color} for l in a.labels],
            }
            for a in assets
        ]
    }


