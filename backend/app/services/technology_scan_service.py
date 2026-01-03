"""
Technology scan service.

Runs Wappalyzer-style detection against hosts/URLs and persists results to:
- `asset_technologies` association
- `labels` / `asset_labels` association (via `tech:<slug>` labels)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Iterable, Optional

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.technology import Technology
from app.services.asset_labeling_service import add_tech_to_asset
from app.services.wappalyzer_service import WappalyzerService

logger = logging.getLogger(__name__)


def _get_or_create_technology(db: Session, detected) -> Technology:
    """Get or create a technology record from a DetectedTechnology-like object."""
    existing = db.query(Technology).filter(Technology.slug == detected.slug).first()
    if existing:
        return existing

    db_tech = Technology(
        name=detected.name,
        slug=detected.slug,
        categories=detected.categories,
        website=getattr(detected, "website", None),
        icon=getattr(detected, "icon", None),
        cpe=getattr(detected, "cpe", None),
    )
    db.add(db_tech)
    db.flush()
    return db_tech


def _get_or_create_url_asset(
    db: Session,
    *,
    organization_id: int,
    url: str,
    parent_asset_id: Optional[int],
    discovery_source: str = "wappalyzer",
) -> Asset:
    existing = (
        db.query(Asset)
        .filter(
            Asset.organization_id == organization_id,
            Asset.asset_type == AssetType.URL,
            Asset.value == url,
        )
        .first()
    )
    if existing:
        return existing

    asset = Asset(
        organization_id=organization_id,
        asset_type=AssetType.URL,
        name=url,
        value=url,
        parent_id=parent_asset_id,
        discovery_source=discovery_source,
        status=AssetStatus.DISCOVERED,
        metadata_={},
    )
    db.add(asset)
    db.flush()
    return asset


async def _scan_hosts_async(
    db: Session,
    *,
    organization_id: int,
    hosts: list[str],
    max_hosts: int = 25,
) -> None:
    wappalyzer = WappalyzerService()

    for host in hosts[:max_hosts]:
        host = (host or "").strip().lower()
        if not host:
            continue

        host_asset = (
            db.query(Asset)
            .filter(
                Asset.organization_id == organization_id,
                Asset.value == host,
                Asset.asset_type.in_([AssetType.SUBDOMAIN, AssetType.DOMAIN]),
            )
            .first()
        )
        if not host_asset:
            continue

        # Try https first, then http
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"

            try:
                detected_techs = await wappalyzer.analyze_url(url)
            except Exception as e:
                logger.warning(f"Wappalyzer scan failed for {url}: {e}")
                continue

            if not detected_techs:
                continue

            url_asset = _get_or_create_url_asset(
                db,
                organization_id=organization_id,
                url=url,
                parent_asset_id=host_asset.id,
            )

            for dt in detected_techs:
                db_tech = _get_or_create_technology(db, dt)
                add_tech_to_asset(
                    db,
                    organization_id=organization_id,
                    asset=url_asset,
                    tech=db_tech,
                    also_tag_asset=True,
                    tag_parent=True,
                )

            # If we got detections on one scheme, don't duplicate on the other.
            break

    db.commit()


def run_technology_scan_for_hosts(
    *,
    organization_id: int,
    hosts: Iterable[str],
    max_hosts: int = 25,
) -> None:
    """
    Synchronous entrypoint (FastAPI BackgroundTasks-friendly).
    Creates its own DB session and runs the async scanner.
    """
    db = SessionLocal()
    try:
        asyncio.run(
            _scan_hosts_async(
                db,
                organization_id=organization_id,
                hosts=list(hosts),
                max_hosts=max_hosts,
            )
        )
    finally:
        db.close()


