"""
Screenshot Scheduler Worker

This worker runs scheduled screenshot jobs for all organizations.
Can be triggered via cron job or as a background task.

Usage:
    # Run as a standalone script
    python -m app.workers.screenshot_scheduler
    
    # Or schedule via cron (daily at 2 AM UTC)
    0 2 * * * cd /app && python -m app.workers.screenshot_scheduler
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy.orm import Session

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.screenshot import Screenshot, ScreenshotStatus, ScreenshotSchedule
from app.models.organization import Organization
from app.services.eyewitness_service import (
    get_eyewitness_service,
    EyeWitnessConfig,
    ScreenshotResult,
)

logger = logging.getLogger(__name__)


class ScreenshotScheduler:
    """
    Scheduler for running automated screenshot jobs.
    """
    
    # Default web-accessible asset types
    WEB_ASSET_TYPES = [AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.URL]
    
    def __init__(self):
        self.service = get_eyewitness_service()
    
    async def run_scheduled_jobs(self) -> dict:
        """
        Run all due scheduled screenshot jobs.
        
        Returns:
            Summary of jobs run and results
        """
        db = SessionLocal()
        results = {
            "jobs_run": 0,
            "successful": 0,
            "failed": 0,
            "total_screenshots": 0,
            "errors": []
        }
        
        try:
            # Check if EyeWitness is available
            status = self.service.check_installation()
            if not status["installed"]:
                logger.error(f"EyeWitness not available: {status.get('error')}")
                results["errors"].append(f"EyeWitness not available: {status.get('error')}")
                return results
            
            # Get all active schedules that are due
            now = datetime.utcnow()
            schedules = db.query(ScreenshotSchedule).filter(
                ScreenshotSchedule.is_active == True,
                ScreenshotSchedule.next_run <= now
            ).all()
            
            if not schedules:
                logger.info("No scheduled screenshot jobs due at this time")
                # Also run default daily screenshots for orgs without schedules
                await self._run_default_screenshots(db, results)
                return results
            
            for schedule in schedules:
                try:
                    logger.info(f"Running scheduled job: {schedule.name} for org {schedule.organization_id}")
                    job_result = await self._run_schedule(db, schedule)
                    
                    results["jobs_run"] += 1
                    results["total_screenshots"] += job_result["total"]
                    results["successful"] += job_result["successful"]
                    results["failed"] += job_result["failed"]
                    
                    # Update schedule
                    schedule.last_run = now
                    schedule.total_runs += 1
                    schedule.successful_captures += job_result["successful"]
                    schedule.failed_captures += job_result["failed"]
                    
                    # Calculate next run
                    schedule.next_run = self._calculate_next_run(schedule)
                    
                    db.commit()
                    
                except Exception as e:
                    logger.error(f"Error running schedule {schedule.id}: {e}")
                    results["errors"].append(f"Schedule {schedule.id}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error in scheduled jobs: {e}")
            results["errors"].append(str(e))
        finally:
            db.close()
        
        return results
    
    async def _run_schedule(self, db: Session, schedule: ScreenshotSchedule) -> dict:
        """
        Run a specific schedule.
        
        Args:
            db: Database session
            schedule: The schedule to run
            
        Returns:
            Results dictionary
        """
        # Build asset query
        query = db.query(Asset).filter(
            Asset.organization_id == schedule.organization_id,
            Asset.status != AssetStatus.ARCHIVED,
            Asset.is_monitored == True
        )
        
        # Filter by asset types
        if schedule.asset_types:
            type_enums = [AssetType(t) for t in schedule.asset_types if t in [e.value for e in AssetType]]
            query = query.filter(Asset.asset_type.in_(type_enums))
        else:
            query = query.filter(Asset.asset_type.in_(self.WEB_ASSET_TYPES))
        
        # Filter by tags
        if schedule.include_tags:
            from sqlalchemy import or_
            tag_conditions = [Asset.tags.contains([tag]) for tag in schedule.include_tags]
            query = query.filter(or_(*tag_conditions))
        
        if schedule.exclude_tags:
            for tag in schedule.exclude_tags:
                query = query.filter(~Asset.tags.contains([tag]))
        
        assets = query.all()
        
        if not assets:
            logger.info(f"No assets found for schedule {schedule.id}")
            return {"total": 0, "successful": 0, "failed": 0}
        
        # Build URLs
        urls = []
        asset_url_map = {}
        for asset in assets:
            url = asset.value
            if asset.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
                url = f"https://{asset.value}"
            urls.append(url)
            asset_url_map[url] = asset
            asset_url_map[asset.value] = asset
        
        # Capture screenshots
        config = EyeWitnessConfig(
            timeout=schedule.timeout,
            threads=schedule.threads,
            delay=schedule.delay,
            jitter=schedule.jitter
        )
        
        results = await self.service.capture_screenshots(
            urls, schedule.organization_id, config
        )
        
        # Process results
        successful = 0
        failed = 0
        
        for result in results:
            asset = asset_url_map.get(result.url) or asset_url_map.get(
                result.url.replace("https://", "").replace("http://", "")
            )
            
            if not asset:
                continue
            
            # Get previous screenshot
            previous = db.query(Screenshot).filter(
                Screenshot.asset_id == asset.id,
                Screenshot.status == ScreenshotStatus.SUCCESS
            ).order_by(Screenshot.captured_at.desc()).first()
            
            # Create record
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
                    screenshot.change_percentage = self.service.calculate_change_percentage(
                        previous.image_hash,
                        result.image_hash
                    )
                    screenshot.previous_screenshot_id = previous.id
            
            db.add(screenshot)
            
            if result.success:
                successful += 1
            else:
                failed += 1
        
        db.commit()
        
        return {
            "total": len(results),
            "successful": successful,
            "failed": failed
        }
    
    async def _run_default_screenshots(self, db: Session, results: dict):
        """
        Run default daily screenshots for organizations without schedules.
        """
        # Get organizations without active schedules
        orgs_with_schedules = db.query(ScreenshotSchedule.organization_id).filter(
            ScreenshotSchedule.is_active == True
        ).distinct().all()
        orgs_with_schedules_ids = [o[0] for o in orgs_with_schedules]
        
        # Get all organizations
        all_orgs = db.query(Organization).filter(
            ~Organization.id.in_(orgs_with_schedules_ids) if orgs_with_schedules_ids else True
        ).all()
        
        for org in all_orgs:
            # Get web assets for this org
            assets = db.query(Asset).filter(
                Asset.organization_id == org.id,
                Asset.status != AssetStatus.ARCHIVED,
                Asset.is_monitored == True,
                Asset.asset_type.in_(self.WEB_ASSET_TYPES)
            ).all()
            
            if not assets:
                continue
            
            logger.info(f"Running default screenshots for org {org.id}: {len(assets)} assets")
            
            # Build URLs
            urls = []
            asset_url_map = {}
            for asset in assets:
                url = asset.value
                if asset.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
                    url = f"https://{asset.value}"
                urls.append(url)
                asset_url_map[url] = asset
                asset_url_map[asset.value] = asset
            
            # Capture with default config
            config = EyeWitnessConfig()
            screenshot_results = await self.service.capture_screenshots(
                urls, org.id, config
            )
            
            # Process results
            for result in screenshot_results:
                asset = asset_url_map.get(result.url) or asset_url_map.get(
                    result.url.replace("https://", "").replace("http://", "")
                )
                
                if not asset:
                    continue
                
                previous = db.query(Screenshot).filter(
                    Screenshot.asset_id == asset.id,
                    Screenshot.status == ScreenshotStatus.SUCCESS
                ).order_by(Screenshot.captured_at.desc()).first()
                
                screenshot = Screenshot(
                    asset_id=asset.id,
                    url=result.url,
                    status=ScreenshotStatus.SUCCESS if result.success else ScreenshotStatus.FAILED,
                    file_path=result.file_path,
                    http_status=result.http_status,
                    page_title=result.page_title,
                    server_header=result.server_header,
                    image_hash=result.image_hash,
                    error_message=result.error_message,
                    captured_at=datetime.utcnow(),
                )
                
                if previous and result.image_hash:
                    if previous.image_hash != result.image_hash:
                        screenshot.has_changed = True
                        screenshot.previous_screenshot_id = previous.id
                
                db.add(screenshot)
                
                if result.success:
                    results["successful"] += 1
                else:
                    results["failed"] += 1
                
                results["total_screenshots"] += 1
            
            db.commit()
    
    def _calculate_next_run(self, schedule: ScreenshotSchedule) -> datetime:
        """Calculate the next run time based on frequency."""
        now = datetime.utcnow()
        
        if schedule.frequency == "daily":
            # Next day at 2 AM UTC
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run
        
        elif schedule.frequency == "weekly":
            # Next week, same day at 2 AM UTC
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            next_run += timedelta(days=7)
            return next_run
        
        elif schedule.frequency == "monthly":
            # Next month, same day at 2 AM UTC
            next_run = now.replace(hour=2, minute=0, second=0, microsecond=0)
            if now.month == 12:
                next_run = next_run.replace(year=now.year + 1, month=1)
            else:
                next_run = next_run.replace(month=now.month + 1)
            return next_run
        
        else:
            # Default to daily
            return now + timedelta(days=1)


async def main():
    """Main entry point for the scheduler."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    logger.info("Starting Screenshot Scheduler")
    
    scheduler = ScreenshotScheduler()
    results = await scheduler.run_scheduled_jobs()
    
    logger.info(f"Screenshot Scheduler completed:")
    logger.info(f"  Jobs run: {results['jobs_run']}")
    logger.info(f"  Total screenshots: {results['total_screenshots']}")
    logger.info(f"  Successful: {results['successful']}")
    logger.info(f"  Failed: {results['failed']}")
    
    if results['errors']:
        logger.warning(f"  Errors: {results['errors']}")


if __name__ == "__main__":
    asyncio.run(main())














