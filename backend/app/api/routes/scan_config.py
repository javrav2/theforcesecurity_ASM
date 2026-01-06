"""Scan Configuration API routes for managing port lists and scan settings."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.db.database import get_db
from app.models.scan_config import ScanConfig, DEFAULT_PORT_LISTS, seed_default_port_lists
from app.models.user import User
from app.api.deps import get_current_active_user, require_analyst

router = APIRouter(prefix="/scan-config", tags=["Scan Configuration"])


# ==================== SCHEMAS ====================

class PortListCreate(BaseModel):
    """Create a new port list."""
    name: str = Field(..., min_length=1, max_length=100, description="Unique name for the port list")
    description: Optional[str] = None
    ports: List[int] = Field(..., description="List of port numbers")
    categories: Optional[dict] = Field(None, description="Optional categorization of ports")


class PortListUpdate(BaseModel):
    """Update an existing port list."""
    description: Optional[str] = None
    ports: Optional[List[int]] = None
    categories: Optional[dict] = None
    is_active: Optional[bool] = None


class PortListResponse(BaseModel):
    """Port list response."""
    id: int
    name: str
    description: Optional[str]
    ports: List[int]
    ports_string: str
    port_count: int
    categories: Optional[dict]
    is_default: bool
    is_active: bool
    
    class Config:
        from_attributes = True


class PortCategoryInfo(BaseModel):
    """Information about a port category."""
    name: str
    ports: List[int]
    port_count: int


# ==================== ENDPOINTS ====================

@router.get("/port-lists", response_model=List[PortListResponse])
def list_port_lists(
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """List all available port lists."""
    query = db.query(ScanConfig).filter(ScanConfig.config_type == "port_list")
    
    if not include_inactive:
        query = query.filter(ScanConfig.is_active == True)
    
    configs = query.order_by(ScanConfig.name).all()
    
    results = []
    for config in configs:
        ports = config.config.get("ports", [])
        results.append(PortListResponse(
            id=config.id,
            name=config.name,
            description=config.description,
            ports=ports,
            ports_string=",".join(str(p) for p in ports),
            port_count=len(ports),
            categories=config.config.get("categories"),
            is_default=config.is_default,
            is_active=config.is_active,
        ))
    
    return results


@router.get("/port-lists/{name}", response_model=PortListResponse)
def get_port_list(
    name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get a specific port list by name."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=ports,
        ports_string=",".join(str(p) for p in ports),
        port_count=len(ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.post("/port-lists", response_model=PortListResponse, status_code=status.HTTP_201_CREATED)
def create_port_list(
    data: PortListCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Create a new custom port list."""
    # Check for duplicate name
    existing = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == data.name
    ).first()
    
    if existing:
        raise HTTPException(status_code=400, detail=f"Port list '{data.name}' already exists")
    
    # Validate ports
    for port in data.ports:
        if not 0 <= port <= 65535:
            raise HTTPException(status_code=400, detail=f"Invalid port number: {port}")
    
    config = ScanConfig(
        config_type="port_list",
        name=data.name,
        description=data.description,
        config={
            "ports": sorted(set(data.ports)),
            "categories": data.categories or {},
        },
        is_default=False,
        is_active=True,
        created_by=current_user.username,
    )
    
    db.add(config)
    db.commit()
    db.refresh(config)
    
    ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=ports,
        ports_string=",".join(str(p) for p in ports),
        port_count=len(ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.put("/port-lists/{name}", response_model=PortListResponse)
def update_port_list(
    name: str,
    data: PortListUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update an existing port list."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    if data.description is not None:
        config.description = data.description
    
    if data.ports is not None:
        for port in data.ports:
            if not 0 <= port <= 65535:
                raise HTTPException(status_code=400, detail=f"Invalid port number: {port}")
        config.config["ports"] = sorted(set(data.ports))
    
    if data.categories is not None:
        config.config["categories"] = data.categories
    
    if data.is_active is not None:
        config.is_active = data.is_active
    
    db.commit()
    db.refresh(config)
    
    ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=ports,
        ports_string=",".join(str(p) for p in ports),
        port_count=len(ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.post("/port-lists/{name}/add-ports", response_model=PortListResponse)
def add_ports_to_list(
    name: str,
    ports: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Add ports to an existing port list."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    for port in ports:
        if not 0 <= port <= 65535:
            raise HTTPException(status_code=400, detail=f"Invalid port number: {port}")
    
    existing_ports = set(config.config.get("ports", []))
    existing_ports.update(ports)
    config.config["ports"] = sorted(existing_ports)
    
    db.commit()
    db.refresh(config)
    
    result_ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=result_ports,
        ports_string=",".join(str(p) for p in result_ports),
        port_count=len(result_ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.post("/port-lists/{name}/remove-ports", response_model=PortListResponse)
def remove_ports_from_list(
    name: str,
    ports: List[int],
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Remove ports from an existing port list."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    existing_ports = set(config.config.get("ports", []))
    existing_ports.difference_update(ports)
    config.config["ports"] = sorted(existing_ports)
    
    db.commit()
    db.refresh(config)
    
    result_ports = config.config.get("ports", [])
    return PortListResponse(
        id=config.id,
        name=config.name,
        description=config.description,
        ports=result_ports,
        ports_string=",".join(str(p) for p in result_ports),
        port_count=len(result_ports),
        categories=config.config.get("categories"),
        is_default=config.is_default,
        is_active=config.is_active,
    )


@router.delete("/port-lists/{name}", status_code=status.HTTP_204_NO_CONTENT)
def delete_port_list(
    name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Delete a custom port list (cannot delete default lists)."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == name
    ).first()
    
    if not config:
        raise HTTPException(status_code=404, detail=f"Port list '{name}' not found")
    
    if config.is_default:
        raise HTTPException(status_code=400, detail="Cannot delete default port lists")
    
    db.delete(config)
    db.commit()


@router.post("/seed-defaults")
def seed_default_configs(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Seed the database with default port lists."""
    seed_default_port_lists(db)
    return {"success": True, "message": "Default port lists seeded"}


@router.get("/port-categories")
def get_port_categories(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get all port categories from the 'critical' port list."""
    config = db.query(ScanConfig).filter(
        ScanConfig.config_type == "port_list",
        ScanConfig.name == "critical"
    ).first()
    
    if not config or not config.config.get("categories"):
        # Return from DEFAULT_PORT_LISTS
        categories = DEFAULT_PORT_LISTS.get("critical", {}).get("categories", {})
    else:
        categories = config.config.get("categories", {})
    
    return {
        name: PortCategoryInfo(
            name=name,
            ports=ports,
            port_count=len(ports)
        ).model_dump()
        for name, ports in categories.items()
    }


@router.get("/default-ports")
def get_default_port_lists():
    """Get all default port list configurations (no auth required for reference)."""
    return DEFAULT_PORT_LISTS

