"""
Cleanup Service for maintenance tasks.

Handles cleanup of:
- Old scan result files
- Temporary files from scanning tools
- Old/orphaned screenshots
- Stale database records
- Log rotation
"""

import asyncio
import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional

from sqlalchemy.orm import Session
from sqlalchemy import and_

logger = logging.getLogger(__name__)

# Default retention periods (in days)
DEFAULT_RETENTION = {
    'screenshots': 90,           # Keep screenshots for 90 days
    'scan_results': 30,          # Keep scan result files for 30 days
    'temp_files': 1,             # Clean temp files older than 1 day
    'failed_scans': 14,          # Clean failed scan records after 14 days
    'old_findings': 180,         # Archive findings older than 180 days
    'orphaned_assets': 30,       # Clean orphaned assets after 30 days
}

# Directories to clean
TEMP_DIRECTORIES = [
    '/tmp/nuclei*',
    '/tmp/paramspider*',
    '/tmp/katana*',
    '/tmp/eyewitness*',
    '/tmp/masscan*',
    '/app/scans/*',
]


class CleanupService:
    """
    Service for cleaning up old files and stale data.
    """
    
    def __init__(self, db: Optional[Session] = None):
        """
        Initialize the cleanup service.
        
        Args:
            db: Optional database session
        """
        self.db = db
        self.stats = {
            'files_deleted': 0,
            'bytes_freed': 0,
            'records_cleaned': 0,
            'errors': [],
        }
    
    async def run_full_cleanup(
        self,
        retention_days: Optional[Dict[str, int]] = None,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Run full cleanup of all areas.
        
        Args:
            retention_days: Optional override for retention periods
            dry_run: If True, only report what would be cleaned
            
        Returns:
            Cleanup statistics
        """
        retention = {**DEFAULT_RETENTION, **(retention_days or {})}
        
        self.stats = {
            'files_deleted': 0,
            'bytes_freed': 0,
            'records_cleaned': 0,
            'errors': [],
            'dry_run': dry_run,
            'started_at': datetime.utcnow().isoformat(),
        }
        
        logger.info(f"Starting cleanup (dry_run={dry_run})")
        
        # Clean temp files
        await self.cleanup_temp_files(
            max_age_days=retention['temp_files'],
            dry_run=dry_run
        )
        
        # Clean old screenshots
        await self.cleanup_screenshots(
            max_age_days=retention['screenshots'],
            dry_run=dry_run
        )
        
        # Clean scan result files
        await self.cleanup_scan_files(
            max_age_days=retention['scan_results'],
            dry_run=dry_run
        )
        
        # Clean database records if we have a session
        if self.db:
            await self.cleanup_failed_scans(
                max_age_days=retention['failed_scans'],
                dry_run=dry_run
            )
        
        self.stats['completed_at'] = datetime.utcnow().isoformat()
        
        logger.info(
            f"Cleanup complete: {self.stats['files_deleted']} files deleted, "
            f"{self.stats['bytes_freed'] / 1024 / 1024:.2f} MB freed"
        )
        
        return self.stats
    
    async def cleanup_temp_files(
        self,
        max_age_days: int = 1,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Clean up temporary files from scanning tools.
        
        Args:
            max_age_days: Delete files older than this
            dry_run: If True, only report
            
        Returns:
            Cleanup stats for this operation
        """
        stats = {'files': 0, 'bytes': 0, 'dirs': []}
        cutoff = datetime.now() - timedelta(days=max_age_days)
        
        # Clean /tmp directories
        tmp_patterns = [
            '/tmp/nuclei-*',
            '/tmp/paramspider_*',
            '/tmp/katana_*',
            '/tmp/eyewitness_*',
            '/tmp/masscan_*',
            '/tmp/naabu_*',
            '/tmp/subfinder_*',
        ]
        
        import glob
        for pattern in tmp_patterns:
            for path in glob.glob(pattern):
                try:
                    if os.path.isdir(path):
                        mtime = datetime.fromtimestamp(os.path.getmtime(path))
                        if mtime < cutoff:
                            size = self._get_dir_size(path)
                            if not dry_run:
                                shutil.rmtree(path, ignore_errors=True)
                            stats['files'] += 1
                            stats['bytes'] += size
                            stats['dirs'].append(path)
                    elif os.path.isfile(path):
                        mtime = datetime.fromtimestamp(os.path.getmtime(path))
                        if mtime < cutoff:
                            size = os.path.getsize(path)
                            if not dry_run:
                                os.remove(path)
                            stats['files'] += 1
                            stats['bytes'] += size
                except Exception as e:
                    self.stats['errors'].append(f"Error cleaning {path}: {e}")
        
        self.stats['files_deleted'] += stats['files']
        self.stats['bytes_freed'] += stats['bytes']
        
        logger.info(f"Temp cleanup: {stats['files']} items, {stats['bytes']/1024:.1f} KB")
        return stats
    
    async def cleanup_screenshots(
        self,
        max_age_days: int = 90,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Clean up old screenshot files.
        
        Args:
            max_age_days: Delete screenshots older than this
            dry_run: If True, only report
            
        Returns:
            Cleanup stats
        """
        stats = {'files': 0, 'bytes': 0}
        cutoff = datetime.now() - timedelta(days=max_age_days)
        
        screenshots_dir = os.environ.get('SCREENSHOTS_DIR', '/app/data/screenshots')
        
        if not os.path.exists(screenshots_dir):
            return stats
        
        for root, dirs, files in os.walk(screenshots_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                    if mtime < cutoff:
                        size = os.path.getsize(filepath)
                        if not dry_run:
                            os.remove(filepath)
                        stats['files'] += 1
                        stats['bytes'] += size
                except Exception as e:
                    self.stats['errors'].append(f"Error cleaning screenshot {filepath}: {e}")
        
        # Clean empty directories
        for root, dirs, files in os.walk(screenshots_dir, topdown=False):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                try:
                    if not os.listdir(dir_path):
                        if not dry_run:
                            os.rmdir(dir_path)
                except Exception:
                    pass
        
        self.stats['files_deleted'] += stats['files']
        self.stats['bytes_freed'] += stats['bytes']
        
        logger.info(f"Screenshot cleanup: {stats['files']} files, {stats['bytes']/1024/1024:.2f} MB")
        return stats
    
    async def cleanup_scan_files(
        self,
        max_age_days: int = 30,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Clean up old scan result files.
        
        Args:
            max_age_days: Delete files older than this
            dry_run: If True, only report
            
        Returns:
            Cleanup stats
        """
        stats = {'files': 0, 'bytes': 0}
        cutoff = datetime.now() - timedelta(days=max_age_days)
        
        scan_dirs = [
            '/app/scans',
            '/app/data/scans',
            '/app/results',
        ]
        
        for scan_dir in scan_dirs:
            if not os.path.exists(scan_dir):
                continue
            
            for root, dirs, files in os.walk(scan_dir):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    try:
                        mtime = datetime.fromtimestamp(os.path.getmtime(filepath))
                        if mtime < cutoff:
                            size = os.path.getsize(filepath)
                            if not dry_run:
                                os.remove(filepath)
                            stats['files'] += 1
                            stats['bytes'] += size
                    except Exception as e:
                        self.stats['errors'].append(f"Error cleaning scan file {filepath}: {e}")
        
        self.stats['files_deleted'] += stats['files']
        self.stats['bytes_freed'] += stats['bytes']
        
        logger.info(f"Scan file cleanup: {stats['files']} files, {stats['bytes']/1024/1024:.2f} MB")
        return stats
    
    async def cleanup_failed_scans(
        self,
        max_age_days: int = 14,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Clean up old failed scan records from database.
        
        Args:
            max_age_days: Delete failed scans older than this
            dry_run: If True, only report
            
        Returns:
            Cleanup stats
        """
        stats = {'records': 0}
        
        if not self.db:
            return stats
        
        from app.models.scan import Scan, ScanStatus
        
        cutoff = datetime.utcnow() - timedelta(days=max_age_days)
        
        try:
            # Find old failed scans
            old_failed = self.db.query(Scan).filter(
                and_(
                    Scan.status == ScanStatus.FAILED,
                    Scan.created_at < cutoff
                )
            ).all()
            
            stats['records'] = len(old_failed)
            
            if not dry_run and old_failed:
                for scan in old_failed:
                    self.db.delete(scan)
                self.db.commit()
            
            self.stats['records_cleaned'] += stats['records']
            
            logger.info(f"Failed scan cleanup: {stats['records']} records")
            
        except Exception as e:
            self.stats['errors'].append(f"Error cleaning failed scans: {e}")
            if self.db:
                self.db.rollback()
        
        return stats
    
    async def cleanup_orphaned_screenshots(
        self,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Clean up screenshot files that don't have corresponding database records.
        
        Args:
            dry_run: If True, only report
            
        Returns:
            Cleanup stats
        """
        stats = {'files': 0, 'bytes': 0}
        
        if not self.db:
            return stats
        
        from app.models.screenshot import Screenshot
        
        screenshots_dir = os.environ.get('SCREENSHOTS_DIR', '/app/data/screenshots')
        
        if not os.path.exists(screenshots_dir):
            return stats
        
        # Get all screenshot paths from database
        db_paths = set()
        for screenshot in self.db.query(Screenshot.image_path).all():
            if screenshot.image_path:
                db_paths.add(screenshot.image_path)
        
        # Find orphaned files
        for root, dirs, files in os.walk(screenshots_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                relative_path = os.path.relpath(filepath, screenshots_dir)
                
                if relative_path not in db_paths:
                    try:
                        size = os.path.getsize(filepath)
                        if not dry_run:
                            os.remove(filepath)
                        stats['files'] += 1
                        stats['bytes'] += size
                    except Exception as e:
                        self.stats['errors'].append(f"Error cleaning orphaned screenshot: {e}")
        
        self.stats['files_deleted'] += stats['files']
        self.stats['bytes_freed'] += stats['bytes']
        
        logger.info(f"Orphaned screenshot cleanup: {stats['files']} files")
        return stats
    
    def _get_dir_size(self, path: str) -> int:
        """Get total size of a directory."""
        total = 0
        try:
            for entry in os.scandir(path):
                if entry.is_file():
                    total += entry.stat().st_size
                elif entry.is_dir():
                    total += self._get_dir_size(entry.path)
        except Exception:
            pass
        return total


async def run_cleanup(
    db: Optional[Session] = None,
    dry_run: bool = False
) -> Dict[str, Any]:
    """
    Convenience function to run cleanup.
    
    Args:
        db: Optional database session
        dry_run: If True, only report what would be cleaned
        
    Returns:
        Cleanup statistics
    """
    service = CleanupService(db)
    return await service.run_full_cleanup(dry_run=dry_run)
