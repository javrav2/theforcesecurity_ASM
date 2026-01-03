"""
Asset labeling helpers.

Centralizes logic for converting detections (e.g., technologies) into persistent
`Label` records and attaching them to assets.
"""

from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.label import Label
from app.models.technology import Technology


TECH_LABEL_PREFIX = "tech:"
DEFAULT_TECH_LABEL_COLOR = "#22c55e"  # Tailwind green-500


def _ensure_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return list(value)


def get_or_create_label(
    db: Session,
    *,
    organization_id: int,
    name: str,
    color: Optional[str] = None,
    description: Optional[str] = None,
) -> Label:
    """Get or create a label by (org_id, name)."""
    existing = (
        db.query(Label)
        .filter(Label.organization_id == organization_id, Label.name == name)
        .first()
    )
    if existing:
        # Opportunistically fill missing metadata
        if color and not existing.color:
            existing.color = color
        if description and not existing.description:
            existing.description = description
        return existing

    label = Label(
        organization_id=organization_id,
        name=name,
        color=color or DEFAULT_TECH_LABEL_COLOR,
        description=description,
    )
    db.add(label)
    db.flush()
    return label


def ensure_tech_label(
    db: Session,
    *,
    organization_id: int,
    tech_slug: str,
    tech_name: Optional[str] = None,
) -> Label:
    """Create/get a technology label using the `tech:<slug>` convention."""
    label_name = f"{TECH_LABEL_PREFIX}{tech_slug}"
    description = f"Detected technology: {tech_name}" if tech_name else "Detected technology"
    return get_or_create_label(
        db,
        organization_id=organization_id,
        name=label_name,
        color=DEFAULT_TECH_LABEL_COLOR,
        description=description,
    )


def attach_label(asset: Asset, label: Label) -> bool:
    """Attach label to asset if missing. Returns True if added."""
    if label in (asset.labels or []):
        return False
    asset.labels.append(label)
    return True


def add_tech_to_asset(
    db: Session,
    *,
    organization_id: int,
    asset: Asset,
    tech: Technology,
    also_tag_asset: bool = True,
    tag_parent: bool = True,
) -> None:
    """
    Attach a `Technology` to an asset and ensure a corresponding `Label` exists.

    This creates:
    - Technology association (asset.technologies)
    - Label association (asset.labels) with name `tech:<slug>`
    - Optional tag string (asset.tags) with `tech:<slug>` for backwards compatibility/UI
    """
    if tech not in (asset.technologies or []):
        asset.technologies.append(tech)

    label = ensure_tech_label(
        db,
        organization_id=organization_id,
        tech_slug=tech.slug,
        tech_name=tech.name,
    )
    attach_label(asset, label)

    if also_tag_asset:
        tags = _ensure_list(asset.tags)
        tag_value = f"{TECH_LABEL_PREFIX}{tech.slug}"
        if tag_value not in tags:
            tags.append(tag_value)
            asset.tags = tags

    if tag_parent and getattr(asset, "parent", None):
        parent = asset.parent
        attach_label(parent, label)
        if also_tag_asset:
            parent_tags = _ensure_list(parent.tags)
            tag_value = f"{TECH_LABEL_PREFIX}{tech.slug}"
            if tag_value not in parent_tags:
                parent_tags.append(tag_value)
                parent.tags = parent_tags


