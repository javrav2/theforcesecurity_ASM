"""
ASM Platform - Schedule Worker

This worker runs in the background and triggers scheduled scans
at their configured times. It checks for due schedules and creates
scan jobs that are then processed by the scanner worker.
"""

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.models.scan_schedule import ScanSchedule, ScheduleFrequency, CONTINUOUS_SCAN_TYPES, ALL_CRITICAL_PORTS
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.asset import Asset, AssetType
from app.models.label import Label
from app.models.netblock import Netblock

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
CHECK_INTERVAL = int(os.getenv("SCHEDULE_CHECK_INTERVAL", "60"))  # Check every minute

# Global shutdown flag
shutdown_requested = False


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_requested = True


class ScheduleWorker:
    """
    Schedule worker that processes scan schedules and creates scan jobs.
    
    Responsibilities:
    - Check for schedules that are due
    - Create scan jobs for due schedules
    - Update schedule next_run_at times
    - Handle schedule errors
    """
    
    def __init__(self):
        """Initialize the schedule worker."""
        if DATABASE_URL:
            self.engine = create_engine(DATABASE_URL)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        else:
            logger.warning("DATABASE_URL not set")
            self.engine = None
            self.SessionLocal = None
        
        logger.info("Schedule worker initialized")
    
    def get_db_session(self) -> Optional[Session]:
        """Get a database session."""
        if self.SessionLocal:
            return self.SessionLocal()
        return None
    
    async def check_and_run_schedules(self):
        """Check for due schedules and trigger them."""
        db = self.get_db_session()
        if not db:
            return
        
        try:
            now = datetime.now(timezone.utc)
            
            # Find schedules that are due
            due_schedules = db.query(ScanSchedule).filter(
                ScanSchedule.is_enabled == True,
                ScanSchedule.next_run_at <= now,
                ScanSchedule.consecutive_failures < 5  # Skip schedules with too many failures
            ).all()
            
            for schedule in due_schedules:
                try:
                    await self.run_schedule(db, schedule)
                except Exception as e:
                    logger.error(f"Error running schedule {schedule.id}: {e}")
                    schedule.consecutive_failures += 1
                    schedule.last_error = str(e)
                    db.commit()
            
        except Exception as e:
            logger.error(f"Error checking schedules: {e}")
        finally:
            db.close()
    
    async def run_schedule(self, db: Session, schedule: ScanSchedule):
        """Run a single schedule by creating a scan job."""
        logger.info(f"Running schedule: {schedule.name} (ID: {schedule.id})")
        
        # Get targets from various sources
        targets = []
        
        # 1. Check for explicit targets on the schedule
        if schedule.targets:
            targets = schedule.targets
        
        # 2. Check for label-based targeting
        elif schedule.label_ids:
            query = db.query(Asset).filter(
                Asset.organization_id == schedule.organization_id,
                Asset.in_scope == True
            )
            
            if schedule.match_all_labels:
                for label_id in schedule.label_ids:
                    query = query.filter(Asset.labels.any(Label.id == label_id))
            else:
                query = query.filter(Asset.labels.any(Label.id.in_(schedule.label_ids)))
            
            assets = query.distinct().all()
            targets = [a.value for a in assets]
        
        # 3. If no explicit targets, use ALL in-scope assets and netblocks for the organization
        else:
            # Get all in-scope assets (domains, subdomains, IPs)
            assets = db.query(Asset).filter(
                Asset.organization_id == schedule.organization_id,
                Asset.in_scope == True,
                Asset.asset_type.in_([
                    AssetType.DOMAIN,
                    AssetType.SUBDOMAIN,
                    AssetType.IP_ADDRESS,
                    AssetType.IP_RANGE,
                ])
            ).all()
            
            # For port scans and critical_ports, only use IPv4 netblocks
            # IPv6 has a much larger address space and requires different scanning strategies
            netblock_query = db.query(Netblock).filter(
                Netblock.organization_id == schedule.organization_id,
                Netblock.in_scope == True
            )
            
            if schedule.scan_type in ["port_scan", "masscan", "critical_ports"]:
                netblock_query = netblock_query.filter(Netblock.ip_version == "ipv4")
                logger.info(f"Filtering netblocks to IPv4 only for {schedule.scan_type}")
            
            netblocks = netblock_query.all()
            
            # Collect targets
            asset_targets = [a.value for a in assets]
            
            # Add CIDR notations from netblocks
            netblock_targets = []
            for nb in netblocks:
                if nb.cidr_notation:
                    # Handle multiple CIDRs (semicolon or comma-separated)
                    # WhoisXML uses semicolon, but also support comma for flexibility
                    cidr_str = nb.cidr_notation
                    if ';' in cidr_str:
                        cidrs = [c.strip() for c in cidr_str.split(';') if c.strip()]
                    elif ',' in cidr_str:
                        cidrs = [c.strip() for c in cidr_str.split(',') if c.strip()]
                    else:
                        cidrs = [cidr_str.strip()] if cidr_str.strip() else []
                    netblock_targets.extend(cidrs)
            
            # Combine and deduplicate
            targets = list(set(asset_targets + netblock_targets))
            logger.info(f"Auto-targeting {len(asset_targets)} assets + {len(netblock_targets)} netblock CIDRs")
        
        if not targets:
            # Check what's missing to give a better error message
            all_assets_count = db.query(Asset).filter(
                Asset.organization_id == schedule.organization_id
            ).count()
            
            all_netblocks_count = db.query(Netblock).filter(
                Netblock.organization_id == schedule.organization_id
            ).count()
            
            in_scope_netblocks = db.query(Netblock).filter(
                Netblock.organization_id == schedule.organization_id,
                Netblock.in_scope == True
            ).count()
            
            if all_assets_count == 0 and all_netblocks_count == 0:
                error_msg = "No assets or netblocks found - run External Discovery first"
            elif all_netblocks_count > 0 and in_scope_netblocks == 0:
                error_msg = f"Found {all_netblocks_count} netblocks but none are marked in-scope. Go to Netblocks page and mark them as in-scope."
            elif all_assets_count > 0:
                error_msg = f"Found {all_assets_count} assets but none are marked in-scope"
            else:
                error_msg = "No in-scope targets found - check asset/netblock scope settings"
            
            logger.warning(f"No targets for schedule {schedule.id}: {error_msg}")
            schedule.last_error = error_msg
            schedule.next_run_at = schedule.calculate_next_run()
            db.commit()
            return
        
        # Map schedule scan_type to ScanType enum
        scan_type_map = {
            "nuclei": ScanType.VULNERABILITY,
            "port_scan": ScanType.PORT_SCAN,
            "masscan": ScanType.PORT_SCAN,
            "critical_ports": ScanType.PORT_SCAN,
            "discovery": ScanType.FULL_DISCOVERY,
            "screenshot": ScanType.SCREENSHOT,
            "technology": ScanType.TECHNOLOGY,
        }
        
        scan_type = scan_type_map.get(schedule.scan_type, ScanType.VULNERABILITY)
        
        # Build config
        config = {
            **(schedule.config or {}),
            "triggered_by_schedule": schedule.id,
            "schedule_name": schedule.name,
        }
        
        # Special handling for critical_ports - use masscan for speed on CIDR blocks
        if schedule.scan_type == "critical_ports":
            config["ports"] = ",".join(str(p) for p in ALL_CRITICAL_PORTS)
            config["generate_findings"] = True
            config["scanner"] = config.get("scanner", "masscan")  # Masscan is faster for CIDR blocks
            config["rate"] = config.get("rate", 10000)  # 10k packets/sec default
        
        # Create the scan
        scan = Scan(
            name=f"[Scheduled] {schedule.name}",
            scan_type=scan_type,
            organization_id=schedule.organization_id,
            targets=targets,
            config=config,
            started_by="scheduler",
            status=ScanStatus.PENDING,
        )
        
        db.add(scan)
        
        # Update schedule
        schedule.last_run_at = datetime.now(timezone.utc)
        schedule.last_scan_id = scan.id
        schedule.run_count += 1
        schedule.consecutive_failures = 0
        schedule.last_error = None
        schedule.next_run_at = schedule.calculate_next_run()
        
        db.commit()
        db.refresh(scan)
        
        logger.info(f"Created scan {scan.id} for schedule {schedule.name}, {len(targets)} targets")
    
    async def run(self):
        """Main worker loop."""
        logger.info("Starting schedule worker...")
        
        while not shutdown_requested:
            try:
                await self.check_and_run_schedules()
                await asyncio.sleep(CHECK_INTERVAL)
            except Exception as e:
                logger.error(f"Error in schedule worker loop: {e}")
                await asyncio.sleep(CHECK_INTERVAL)
        
        logger.info("Schedule worker shutting down...")


async def main():
    """Main entry point."""
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    worker = ScheduleWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())

