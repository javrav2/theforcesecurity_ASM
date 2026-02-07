"""
Screenshot Service for automated screenshot capture.

Provides background task functions to capture screenshots for 
discovered domains and subdomains using EyeWitness.
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import Iterable, List, Optional
from urllib.parse import urlparse

from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType
from app.models.screenshot import Screenshot, ScreenshotStatus
from app.services.eyewitness_service import (
    get_eyewitness_service,
    EyeWitnessConfig,
    ScreenshotResult,
)

logger = logging.getLogger(__name__)

# Batch settings
BATCH_SIZE = 20  # How many hosts to screenshot in parallel
BATCH_DELAY = 2.0  # Seconds between batches


def _extract_hostname_from_url(url_or_host: str) -> str:
    """
    Extract the hostname from a URL or return the input if it's already a hostname.
    
    Examples:
        'https://example.com/path' -> 'example.com'
        'https://192.168.1.1:8443/login' -> '192.168.1.1'
        'example.com' -> 'example.com'
        '192.168.1.1' -> '192.168.1.1'
    """
    url_or_host = url_or_host.strip()
    
    # If it starts with http:// or https://, parse it
    if url_or_host.startswith('http://') or url_or_host.startswith('https://'):
        parsed = urlparse(url_or_host)
        hostname = parsed.hostname or parsed.netloc
        # Remove port if present
        if ':' in hostname and not hostname.startswith('['):  # Not IPv6
            hostname = hostname.split(':')[0]
        return hostname.lower() if hostname else url_or_host.lower()
    
    # Otherwise it's already a hostname/IP
    return url_or_host.lower()


def _normalize_url(url_or_host: str) -> str:
    """
    Normalize to a full URL, handling cases where input is already a URL.
    
    Examples:
        'example.com' -> 'https://example.com'
        'https://example.com' -> 'https://example.com' (unchanged)
        'http://example.com/path' -> 'http://example.com/path' (unchanged)
    """
    url_or_host = url_or_host.strip()
    
    if url_or_host.startswith('http://') or url_or_host.startswith('https://'):
        return url_or_host
    
    return f"https://{url_or_host}"


async def _capture_screenshots_async(
    db: Session,
    *,
    organization_id: int,
    hosts: List[str],
    max_hosts: int = 200,
    timeout: int = 30,
) -> dict:
    """
    Capture screenshots for hosts asynchronously.
    
    Args:
        db: Database session
        organization_id: Organization ID
        hosts: List of hostnames to screenshot
        max_hosts: Maximum hosts to process
        timeout: Timeout per screenshot
        
    Returns:
        Summary dict with capture statistics
    """
    service = get_eyewitness_service()
    
    # Check if EyeWitness is available
    install_status = service.check_installation()
    if not install_status.get("installed"):
        logger.warning(f"EyeWitness not available: {install_status.get('error')}")
        return {
            "error": "EyeWitness not installed",
            "hosts_requested": len(hosts),
            "screenshots_captured": 0,
        }
    
    # Normalize inputs - can be hostnames or full URLs (from live_url)
    hosts_to_scan = [h.strip() for h in hosts[:max_hosts] if h and h.strip()]
    total_hosts = len(hosts_to_scan)
    
    logger.info(f"Starting screenshot capture for {total_hosts} hosts (organization_id={organization_id})")
    
    total_captured = 0
    total_failed = 0
    assets_updated = 0
    
    # Build URLs from hosts, handling both hostnames and full URLs
    urls = []
    url_to_original = {}  # Map normalized URL -> original input
    url_to_hostname = {}  # Map normalized URL -> extracted hostname/IP
    
    for host in hosts_to_scan:
        # Normalize to full URL (handles case where host is already a URL)
        url = _normalize_url(host)
        urls.append(url)
        url_to_original[url] = host
        url_to_hostname[url] = _extract_hostname_from_url(host)
    
    # Process in batches
    config = EyeWitnessConfig(timeout=timeout, threads=BATCH_SIZE)
    
    for i in range(0, len(urls), BATCH_SIZE):
        batch_urls = urls[i:i + BATCH_SIZE]
        batch_num = (i // BATCH_SIZE) + 1
        total_batches = (len(urls) + BATCH_SIZE - 1) // BATCH_SIZE
        
        logger.info(f"Capturing screenshots batch {batch_num}/{total_batches} ({len(batch_urls)} URLs)")
        
        try:
            results = await service.capture_screenshots(batch_urls, organization_id, config)
            
            # Process results and create screenshot records
            for result in results:
                # Extract hostname from the result URL for matching
                result_hostname = _extract_hostname_from_url(result.url)
                original_input = url_to_original.get(result.url)
                
                # Find matching asset using multiple strategies
                asset = None
                
                # Strategy 1: Match by value (hostname/IP)
                asset = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == result_hostname,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS]),
                ).first()
                
                # Strategy 2: Match by live_url (for assets where HTTP probe saved the URL)
                if not asset and original_input:
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.live_url == original_input,
                    ).first()
                
                # Strategy 3: Match by IP address field
                if not asset:
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.ip_address == result_hostname,
                    ).first()
                
                # Strategy 4: Match IP in the ip_addresses JSON array
                if not asset:
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.ip_addresses.contains([result_hostname]),
                    ).first()
                
                if not asset:
                    logger.debug(f"No matching asset found for {result.url} (hostname: {result_hostname})")
                    total_failed += 1
                    continue
                
                # Get previous screenshot for change detection
                previous = db.query(Screenshot).filter(
                    Screenshot.asset_id == asset.id,
                    Screenshot.status == ScreenshotStatus.SUCCESS
                ).order_by(Screenshot.captured_at.desc()).first()
                
                # Create screenshot record
                screenshot = Screenshot(
                    asset_id=asset.id,
                    url=result.url,
                    status=ScreenshotStatus.SUCCESS if result.success else ScreenshotStatus.FAILED,
                    file_path=result.file_path,
                    thumbnail_path=result.thumbnail_path,
                    source_path=result.source_path,
                    http_status=result.http_status,
                    page_title=result.page_title,
                    server_header=result.server_header,
                    response_headers=result.response_headers,
                    category=result.category,
                    default_creds_detected=bool(result.default_creds),
                    default_creds_info=result.default_creds,
                    width=result.width,
                    height=result.height,
                    file_size=result.file_size,
                    image_hash=result.image_hash,
                    error_message=result.error_message,
                    captured_at=datetime.utcnow(),
                )
                
                # Check for changes
                if previous and result.image_hash:
                    if previous.image_hash != result.image_hash:
                        screenshot.has_changed = True
                        screenshot.previous_screenshot_id = previous.id
                
                db.add(screenshot)
                db.flush()  # Get the screenshot ID
                
                if result.success:
                    total_captured += 1
                    # Update asset's cached screenshot ID for faster list queries
                    if screenshot.file_path:
                        asset.latest_screenshot_id = screenshot.id
                        assets_updated += 1
                else:
                    total_failed += 1
            
            # Commit after each batch
            db.commit()
            
        except Exception as e:
            logger.error(f"Batch screenshot error: {e}", exc_info=True)
            db.rollback()
            total_failed += len(batch_urls)
        
        # Delay between batches
        if i + BATCH_SIZE < len(urls):
            await asyncio.sleep(BATCH_DELAY)
    
    logger.info(f"Screenshot capture complete: {total_captured} captured, {total_failed} failed, {assets_updated} assets updated")
    
    return {
        "hosts_requested": total_hosts,
        "screenshots_captured": total_captured,
        "screenshots_failed": total_failed,
        "assets_updated": assets_updated,
    }


def run_screenshots_for_hosts(
    *,
    organization_id: int,
    hosts: Iterable[str],
    max_hosts: int = 200,
    timeout: int = 30,
) -> dict:
    """
    Synchronous entrypoint (FastAPI BackgroundTasks-friendly).
    Creates its own DB session and runs the async screenshot capture.
    
    Args:
        organization_id: Organization ID
        hosts: Iterable of hostnames to screenshot
        max_hosts: Maximum hosts to screenshot
        timeout: Timeout per screenshot
        
    Returns:
        Summary dict with capture statistics
    """
    db = SessionLocal()
    try:
        logger.info(f"Starting background screenshot capture for organization {organization_id}")
        result = asyncio.run(
            _capture_screenshots_async(
                db,
                organization_id=organization_id,
                hosts=list(hosts),
                max_hosts=max_hosts,
                timeout=timeout,
            )
        )
        logger.info(f"Background screenshot capture complete: {result}")
        return result
    except Exception as e:
        logger.error(f"Screenshot capture failed: {e}")
        return {"error": str(e)}
    finally:
        db.close()


async def capture_all_org_screenshots(
    organization_id: int,
    max_hosts: int = 500,
    timeout: int = 30,
    live_only: bool = True,
) -> dict:
    """
    Capture screenshots for all web assets in an organization.
    
    Includes domains, subdomains, and IP addresses. Prefers using the live_url
    (from HTTP probe) when available for accurate screenshots of the actual
    responding endpoint.
    
    Args:
        organization_id: Organization ID
        max_hosts: Maximum hosts to screenshot
        timeout: Timeout per screenshot
        live_only: Only include assets marked as live (recommended)
        
    Returns:
        Summary dict with capture statistics
    """
    db = SessionLocal()
    try:
        # Get all web assets for the organization
        # Include DOMAIN, SUBDOMAIN, and IP_ADDRESS types
        query = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS]),
        )
        
        # Optionally filter to live assets only
        if live_only:
            query = query.filter(Asset.is_live == True)
        
        assets = query.limit(max_hosts).all()
        
        if not assets:
            return {
                "total_hosts": 0, 
                "message": "No assets found" + (" (try with live_only=False)" if live_only else "")
            }
        
        # Build URL list - prefer live_url (from HTTP probe) when available
        # This ensures we screenshot the actual responding endpoint
        # e.g., https://131.200.250.120/global-protect/login.esp instead of just https://131.200.250.120
        url_list = []
        for asset in assets:
            if asset.live_url:
                # Use the actual live URL from HTTP probe
                url_list.append(asset.live_url)
            elif asset.asset_type == AssetType.IP_ADDRESS:
                # For IP assets without live_url, try both HTTP and HTTPS
                url_list.append(f"https://{asset.value}")
            else:
                # For domains/subdomains without live_url
                url_list.append(f"https://{asset.value}")
        
        logger.info(f"Capturing screenshots for {len(url_list)} assets in organization {organization_id}")
        
        return await _capture_screenshots_async(
            db,
            organization_id=organization_id,
            hosts=url_list,
            max_hosts=max_hosts,
            timeout=timeout,
        )
    finally:
        db.close()

