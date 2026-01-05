"""
Screenshot Service for automated screenshot capture.

Provides background task functions to capture screenshots for 
discovered domains and subdomains using EyeWitness.
"""

import asyncio
import logging
from datetime import datetime
from typing import Iterable, List, Optional

from sqlalchemy.orm import Session

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
    
    hosts_to_scan = [h.strip().lower() for h in hosts[:max_hosts] if h and h.strip()]
    total_hosts = len(hosts_to_scan)
    
    logger.info(f"Starting screenshot capture for {total_hosts} hosts (organization_id={organization_id})")
    
    total_captured = 0
    total_failed = 0
    
    # Build URLs from hosts
    urls = []
    host_url_map = {}
    for host in hosts_to_scan:
        url = f"https://{host}"
        urls.append(url)
        host_url_map[url] = host
        host_url_map[host] = host
    
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
                # Find matching asset
                host = host_url_map.get(result.url) or host_url_map.get(
                    result.url.replace("https://", "").replace("http://", "")
                )
                
                if not host:
                    continue
                
                # Find asset
                asset = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == host,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                ).first()
                
                if not asset:
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
                
                if result.success:
                    total_captured += 1
                else:
                    total_failed += 1
            
            # Commit after each batch
            db.commit()
            
        except Exception as e:
            logger.error(f"Batch screenshot error: {e}")
            total_failed += len(batch_urls)
        
        # Delay between batches
        if i + BATCH_SIZE < len(urls):
            await asyncio.sleep(BATCH_DELAY)
    
    logger.info(f"Screenshot capture complete: {total_captured} captured, {total_failed} failed")
    
    return {
        "hosts_requested": total_hosts,
        "screenshots_captured": total_captured,
        "screenshots_failed": total_failed,
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
) -> dict:
    """
    Capture screenshots for all domains and subdomains in an organization.
    
    Args:
        organization_id: Organization ID
        max_hosts: Maximum hosts to screenshot
        timeout: Timeout per screenshot
        
    Returns:
        Summary dict with capture statistics
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
        
        logger.info(f"Capturing screenshots for {len(host_list)} hosts in organization {organization_id}")
        
        return await _capture_screenshots_async(
            db,
            organization_id=organization_id,
            hosts=host_list,
            max_hosts=max_hosts,
            timeout=timeout,
        )
    finally:
        db.close()

