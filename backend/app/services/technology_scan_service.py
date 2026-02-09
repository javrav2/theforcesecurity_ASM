"""
Technology scan service.

Runs Wappalyzer-style detection against hosts/URLs and persists results to:
- `asset_technologies` association
- `labels` / `asset_labels` association (via `tech:<slug>` labels)

Supports batch processing with concurrency limits for scanning large numbers
of hosts discovered during external discovery.

Enhanced with WhatRuns API integration for more comprehensive technology detection.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Iterable, Optional, List, Literal

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.technology import Technology
from app.services.asset_labeling_service import add_tech_to_asset
from app.services.wappalyzer_service import WappalyzerService, DetectedTechnology
from app.services.whatruns_service import WhatRunsService, get_whatruns_service

logger = logging.getLogger(__name__)

# Concurrency settings for batch processing
BATCH_SIZE = 10  # How many hosts to scan in parallel
BATCH_DELAY = 1.0  # Seconds to wait between batches

# Technology detection sources
TechSource = Literal["wappalyzer", "whatruns", "both"]


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


def _update_asset_with_url(
    db: Session,
    *,
    asset: Asset,
    url: str,
) -> Asset:
    """
    Update an existing asset with the live URL it responded on.
    Wappalyzer should ENRICH existing assets, not create new ones.
    """
    # Update the asset with the live URL (don't change discovery_source)
    if not asset.live_url:
        asset.live_url = url
    asset.is_live = True
    db.flush()
    return asset


def _wappalyzer_options_from_config(config: Optional[dict]) -> dict:
    """Extract Wappalyzer options from project settings config."""
    if not config:
        return {}
    return {
        "min_confidence": max(0, min(100, int(config.get("min_confidence_threshold", 0)))),
        "require_html": bool(config.get("require_html", False)),
    }


async def _scan_single_host(
    wappalyzer: WappalyzerService,
    db: Session,
    organization_id: int,
    host: str,
    source: TechSource = "wappalyzer",
    whatruns: Optional[WhatRunsService] = None,
    wappalyzer_options: Optional[dict] = None,
) -> dict:
    """Scan a single host for technologies. Returns stats dict."""
    host = (host or "").strip().lower()
    if not host:
        return {"host": host, "scanned": False, "techs_found": 0}

    # Look up asset - support DOMAIN, SUBDOMAIN, and IP_ADDRESS types
    host_asset = (
        db.query(Asset)
        .filter(
            Asset.organization_id == organization_id,
            Asset.value == host,
            Asset.asset_type.in_([AssetType.SUBDOMAIN, AssetType.DOMAIN, AssetType.IP_ADDRESS]),
        )
        .first()
    )
    if not host_asset:
        return {"host": host, "scanned": False, "techs_found": 0, "reason": "no_asset"}

    techs_found = 0
    all_detected_techs: List[DetectedTechnology] = []
    live_url = None
    
    # Build list of URLs to try
    # Priority: 1) asset.live_url, 2) https://{host}, 3) http://{host}
    urls_to_try = []
    
    # If asset has a live_url from HTTP probe, try that first (most reliable)
    if host_asset.live_url:
        urls_to_try.append(host_asset.live_url)
        # Also extract hostname from live_url for WhatRuns
        try:
            from urllib.parse import urlparse
            parsed = urlparse(host_asset.live_url)
            live_hostname = parsed.netloc.split(':')[0]  # Remove port if present
        except Exception:
            live_hostname = host
    else:
        live_hostname = host
    
    # For IP addresses, we should prefer live_url if available
    # Otherwise construct URLs - for IPs this may not work well with WhatRuns
    is_ip = host_asset.asset_type == AssetType.IP_ADDRESS
    
    # Add constructed URLs if not already covered by live_url
    for scheme in ("https", "http"):
        constructed_url = f"{scheme}://{host}"
        if constructed_url not in urls_to_try:
            urls_to_try.append(constructed_url)
    
    # Try each URL until we get results
    for url in urls_to_try:
        # Wappalyzer detection (works with any URL including IPs)
        if source in ("wappalyzer", "both"):
            try:
                opts = wappalyzer_options or {}
                wappalyzer_techs = await wappalyzer.analyze_url(
                    url,
                    min_confidence=opts.get("min_confidence", 0),
                    require_html=opts.get("require_html", False),
                )
                if wappalyzer_techs:
                    live_url = url
                    all_detected_techs.extend(wappalyzer_techs)
            except Exception as e:
                logger.debug(f"Wappalyzer scan failed for {url}: {e}")
        
        # WhatRuns detection (needs hostname, not IP - use live_hostname)
        # WhatRuns doesn't work well with raw IPs, so only try if we have a hostname
        if source in ("whatruns", "both") and whatruns and not is_ip:
            try:
                whatruns_techs = await whatruns.detect_technologies(live_hostname, url)
                if whatruns_techs:
                    live_url = url
                    # Convert WhatRuns results to DetectedTechnology format
                    for wt in whatruns_techs:
                        all_detected_techs.append(wt.to_detected_technology())
            except Exception as e:
                logger.debug(f"WhatRuns scan failed for {url}: {e}")
        
        # If we got any detections on this URL, break
        if all_detected_techs:
            break

    if not all_detected_techs:
        return {"host": host, "scanned": True, "techs_found": 0}

    # Update the domain/subdomain asset with live_url
    if live_url:
        _update_asset_with_url(db, asset=host_asset, url=live_url)

    # Deduplicate technologies by slug
    seen_slugs = set()
    unique_techs = []
    for dt in all_detected_techs:
        if dt.slug not in seen_slugs:
            seen_slugs.add(dt.slug)
            unique_techs.append(dt)

    # Attach technologies directly to the domain/subdomain asset
    for dt in unique_techs:
        db_tech = _get_or_create_technology(db, dt)
        add_tech_to_asset(
            db,
            organization_id=organization_id,
            asset=host_asset,
            tech=db_tech,
            also_tag_asset=True,
            tag_parent=False,
        )
        techs_found += 1

    return {"host": host, "scanned": True, "techs_found": techs_found}


async def _scan_hosts_batch(
    wappalyzer: WappalyzerService,
    db: Session,
    organization_id: int,
    hosts: List[str],
    source: TechSource = "wappalyzer",
    whatruns: Optional[WhatRunsService] = None,
    wappalyzer_options: Optional[dict] = None,
) -> List[dict]:
    """Scan a batch of hosts concurrently."""
    tasks = [
        _scan_single_host(
            wappalyzer, db, organization_id, host, source, whatruns,
            wappalyzer_options=wappalyzer_options,
        )
        for host in hosts
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)


async def _scan_hosts_async(
    db: Session,
    *,
    organization_id: int,
    hosts: list[str],
    max_hosts: int = 500,
    source: TechSource = "wappalyzer",
    wappalyzer_config: Optional[dict] = None,
) -> dict:
    """
    Scan hosts for technologies using batch processing.
    
    Args:
        db: Database session
        organization_id: Organization ID
        hosts: List of hostnames to scan
        max_hosts: Maximum hosts to scan
        source: Technology detection source ("wappalyzer", "whatruns", or "both")
        
    Returns:
        Summary dict with scan statistics
    """
    wappalyzer = WappalyzerService()
    whatruns = get_whatruns_service() if source in ("whatruns", "both") else None
    
    hosts_to_scan = [h.strip().lower() for h in hosts[:max_hosts] if h and h.strip()]
    total_hosts = len(hosts_to_scan)
    
    logger.info(f"Starting technology scan for {total_hosts} hosts (organization_id={organization_id}, source={source})")
    
    total_scanned = 0
    total_techs_found = 0
    
    # For WhatRuns, use smaller batch size due to rate limiting
    batch_size = 3 if source == "whatruns" else (5 if source == "both" else BATCH_SIZE)
    batch_delay = 2.0 if source in ("whatruns", "both") else BATCH_DELAY
    
    # Process in batches
    for i in range(0, total_hosts, batch_size):
        batch = hosts_to_scan[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (total_hosts + batch_size - 1) // batch_size
        
        logger.info(f"Scanning batch {batch_num}/{total_batches} ({len(batch)} hosts)")
        
        wappalyzer_options = _wappalyzer_options_from_config(wappalyzer_config)
        results = await _scan_hosts_batch(
            wappalyzer, db, organization_id, batch, source, whatruns,
            wappalyzer_options=wappalyzer_options,
        )
        
        # Process results with detailed logging
        skipped_no_asset = 0
        skipped_errors = 0
        for result in results:
            if isinstance(result, Exception):
                logger.warning(f"Batch scan error: {result}")
                skipped_errors += 1
                continue
            if result.get("scanned"):
                total_scanned += 1
                total_techs_found += result.get("techs_found", 0)
                if result.get("techs_found", 0) == 0:
                    logger.debug(f"Host {result.get('host')} scanned but no technologies detected")
            else:
                reason = result.get("reason", "unknown")
                if reason == "no_asset":
                    skipped_no_asset += 1
                logger.debug(f"Host {result.get('host')} skipped: {reason}")
        
        if skipped_no_asset > 0 or skipped_errors > 0:
            logger.info(f"Batch {batch_num}: {skipped_no_asset} hosts skipped (no matching asset), {skipped_errors} errors")
        
        # Commit after each batch to avoid long transactions
        db.commit()
        
        # Small delay between batches to avoid overwhelming targets
        if i + batch_size < total_hosts:
            await asyncio.sleep(batch_delay)
    
    logger.info(f"Technology scan complete: {total_scanned}/{total_hosts} hosts scanned, {total_techs_found} technologies detected")
    
    return {
        "total_hosts": total_hosts,
        "hosts_scanned": total_scanned,
        "technologies_found": total_techs_found,
        "source": source,
    }


def run_technology_scan_for_hosts(
    *,
    organization_id: int,
    hosts: Iterable[str],
    max_hosts: int = 500,
    source: TechSource = "wappalyzer",
    wappalyzer_config: Optional[dict] = None,
) -> dict:
    """
    Synchronous entrypoint (FastAPI BackgroundTasks-friendly).
    Creates its own DB session and runs the async scanner.
    
    Args:
        organization_id: Organization ID
        hosts: Iterable of hostnames to scan
        max_hosts: Maximum hosts to scan (default 500)
        source: Technology detection source ("wappalyzer", "whatruns", or "both")
        wappalyzer_config: Optional project settings for Wappalyzer (min_confidence_threshold, require_html, etc.)
        
    Returns:
        Summary dict with scan statistics
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting background technology scan for organization {organization_id} (source={source})")
        result = asyncio.run(
            _scan_hosts_async(
                db,
                organization_id=organization_id,
                hosts=list(hosts),
                max_hosts=max_hosts,
                source=source,
                wappalyzer_config=wappalyzer_config,
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
    source: TechSource = "wappalyzer",
) -> dict:
    """
    Scan all domains and subdomains in an organization for technologies.
    
    This is useful for running a comprehensive technology scan on the entire
    asset inventory of an organization.
    
    Args:
        organization_id: Organization ID
        max_hosts: Maximum hosts to scan
        source: Technology detection source ("wappalyzer", "whatruns", or "both")
        
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
        
        logger.info(f"Scanning {len(host_list)} hosts for organization {organization_id} (source={source})")
        
        return await _scan_hosts_async(
            db,
            organization_id=organization_id,
            hosts=host_list,
            max_hosts=max_hosts,
            source=source,
        )
    finally:
        db.close()


async def scan_single_host_whatruns(
    hostname: str,
    url: Optional[str] = None,
) -> List[DetectedTechnology]:
    """
    Scan a single host using WhatRuns API only.
    
    This is a convenience function for testing or one-off scans.
    Returns DetectedTechnology objects for compatibility.
    
    Args:
        hostname: The hostname to scan
        url: Optional full URL to scan
        
    Returns:
        List of detected technologies
    """
    whatruns = get_whatruns_service()
    whatruns_techs = await whatruns.detect_technologies(hostname, url)
    return [wt.to_detected_technology() for wt in whatruns_techs]


