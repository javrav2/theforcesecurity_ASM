"""
Technology scan service.

Runs Wappalyzer-style detection against hosts/URLs and persists results to:
- `asset_technologies` association
- `labels` / `asset_labels` association (via `tech:<slug>` labels)

Supports batch processing with concurrency limits for scanning large numbers
of hosts discovered during external discovery.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Iterable, Optional, List

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.technology import Technology
from app.services.asset_labeling_service import add_tech_to_asset
from app.services.wappalyzer_service import WappalyzerService

logger = logging.getLogger(__name__)

# Concurrency settings for batch processing
BATCH_SIZE = 10  # How many hosts to scan in parallel
BATCH_DELAY = 1.0  # Seconds to wait between batches


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


async def _scan_single_host(
    wappalyzer: WappalyzerService,
    db: Session,
    organization_id: int,
    host: str,
) -> dict:
    """Scan a single host for technologies. Returns stats dict."""
    host = (host or "").strip().lower()
    if not host:
        return {"host": host, "scanned": False, "techs_found": 0}

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
        return {"host": host, "scanned": False, "techs_found": 0, "reason": "no_asset"}

    techs_found = 0
    
    # Try https first, then http
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"

        try:
            detected_techs = await wappalyzer.analyze_url(url)
        except Exception as e:
            logger.debug(f"Wappalyzer scan failed for {url}: {e}")
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
            techs_found += 1

        # If we got detections on one scheme, don't duplicate on the other.
        break

    return {"host": host, "scanned": True, "techs_found": techs_found}


async def _scan_hosts_batch(
    wappalyzer: WappalyzerService,
    db: Session,
    organization_id: int,
    hosts: List[str],
) -> List[dict]:
    """Scan a batch of hosts concurrently."""
    tasks = [
        _scan_single_host(wappalyzer, db, organization_id, host)
        for host in hosts
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)


async def _scan_hosts_async(
    db: Session,
    *,
    organization_id: int,
    hosts: list[str],
    max_hosts: int = 500,
) -> dict:
    """
    Scan hosts for technologies using batch processing.
    
    Args:
        db: Database session
        organization_id: Organization ID
        hosts: List of hostnames to scan
        max_hosts: Maximum hosts to scan
        
    Returns:
        Summary dict with scan statistics
    """
    wappalyzer = WappalyzerService()
    
    hosts_to_scan = [h.strip().lower() for h in hosts[:max_hosts] if h and h.strip()]
    total_hosts = len(hosts_to_scan)
    
    logger.info(f"Starting technology scan for {total_hosts} hosts (organization_id={organization_id})")
    
    total_scanned = 0
    total_techs_found = 0
    
    # Process in batches
    for i in range(0, total_hosts, BATCH_SIZE):
        batch = hosts_to_scan[i:i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        total_batches = (total_hosts + BATCH_SIZE - 1) // BATCH_SIZE
        
        logger.info(f"Scanning batch {batch_num}/{total_batches} ({len(batch)} hosts)")
        
        results = await _scan_hosts_batch(wappalyzer, db, organization_id, batch)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Batch scan error: {result}")
                continue
            if result.get("scanned"):
                total_scanned += 1
                total_techs_found += result.get("techs_found", 0)
        
        # Commit after each batch to avoid long transactions
        db.commit()
        
        # Small delay between batches to avoid overwhelming targets
        if i + BATCH_SIZE < total_hosts:
            await asyncio.sleep(BATCH_DELAY)
    
    logger.info(f"Technology scan complete: {total_scanned}/{total_hosts} hosts scanned, {total_techs_found} technologies detected")
    
    return {
        "total_hosts": total_hosts,
        "hosts_scanned": total_scanned,
        "technologies_found": total_techs_found,
    }


def run_technology_scan_for_hosts(
    *,
    organization_id: int,
    hosts: Iterable[str],
    max_hosts: int = 500,
) -> dict:
    """
    Synchronous entrypoint (FastAPI BackgroundTasks-friendly).
    Creates its own DB session and runs the async scanner.
    
    Args:
        organization_id: Organization ID
        hosts: Iterable of hostnames to scan
        max_hosts: Maximum hosts to scan (default 500)
        
    Returns:
        Summary dict with scan statistics
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting background technology scan for organization {organization_id}")
        result = asyncio.run(
            _scan_hosts_async(
                db,
                organization_id=organization_id,
                hosts=list(hosts),
                max_hosts=max_hosts,
            )
        )
        logger.info(f"Background technology scan complete: {result}")
        return result
    except Exception as e:
        logger.error(f"Technology scan failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()


async def scan_all_org_hosts(
    organization_id: int,
    max_hosts: int = 1000,
) -> dict:
    """
    Scan all domains and subdomains in an organization for technologies.
    
    This is useful for running a comprehensive technology scan on the entire
    asset inventory of an organization.
    
    Args:
        organization_id: Organization ID
        max_hosts: Maximum hosts to scan
        
    Returns:
        Summary dict with scan statistics
    """
    db = SessionLocal()
    try:
        # Get all domains and subdomains for the organization
        hosts = db.query(Asset.value).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        ).limit(max_hosts).all()
        
        host_list = [h[0] for h in hosts]
        
        if not host_list:
            return {"total_hosts": 0, "message": "No domains/subdomains found"}
        
        logger.info(f"Scanning {len(host_list)} hosts for organization {organization_id}")
        
        return await _scan_hosts_async(
            db,
            organization_id=organization_id,
            hosts=host_list,
            max_hosts=max_hosts,
        )
    finally:
        db.close()


