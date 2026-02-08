"""
ASM Platform - Scanner Worker

This worker polls SQS for scan jobs and executes them using the appropriate
scanning tools (Nuclei, Nmap, etc.)

Runs as a separate container in AWS ECS with full network access for scanning.
"""

import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime
from typing import Optional

import boto3
from botocore.exceptions import ClientError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.models.scan import Scan, ScanType, ScanStatus
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.netblock import Netblock
from app.models.port_service import PortService, PortState, Protocol
from app.services.nuclei_service import NucleiService
from app.services.nuclei_findings_service import NucleiFindingsService
from app.services.port_scanner_service import PortScannerService, ScannerType
from app.services.port_findings_service import PortFindingsService
from app.services.discovery_service import DiscoveryService
from app.services.dns_resolution_service import DNSResolutionService
from app.services.geolocation_service import get_geolocation_service
import ipaddress
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
DATABASE_URL = os.getenv("DATABASE_URL")
SQS_QUEUE_URL = os.getenv("SQS_QUEUE_URL")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "20"))
VISIBILITY_TIMEOUT = int(os.getenv("VISIBILITY_TIMEOUT", "3600"))

# Multi-scan configuration
MAX_CONCURRENT_SCANS = int(os.getenv("MAX_CONCURRENT_SCANS", "3"))  # Max parallel scans
PRIORITY_AD_HOC = True  # Prioritize ad-hoc scans over scheduled

# Performance tuning from environment
DEFAULT_PORT_SCAN_RATE = int(os.getenv("PORT_SCAN_RATE", "500"))  # Packets per second
DEFAULT_NUCLEI_RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))  # Requests per second

# Global shutdown flag
shutdown_requested = False

# Active scans tracking
active_scans = set()
scan_semaphore = None  # Initialized in worker


def _calculate_targets_expanded(targets: list) -> int:
    """
    Calculate total number of IPs from a list of targets (CIDRs, domains, IPs).
    """
    if not targets:
        return 0
    
    total = 0
    cidr_pattern = re.compile(r'^[\d.:a-fA-F]+/\d+$')
    
    for target in targets:
        if not target:
            continue
        target = str(target).strip()
        
        if cidr_pattern.match(target):
            try:
                network = ipaddress.ip_network(target, strict=False)
                total += network.num_addresses
            except ValueError:
                total += 1
        else:
            total += 1
    
    return total


def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global shutdown_requested
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_requested = True


class ScannerWorker:
    """
    Scanner worker that processes scan jobs from SQS or database.
    
    Features:
    - Concurrent scan execution (configurable via MAX_CONCURRENT_SCANS)
    - Priority handling (ad-hoc scans run before scheduled scans)
    - Graceful shutdown with active scan tracking
    
    Job Types:
    - NUCLEI_SCAN: Run Nuclei vulnerability scan
    - PORT_SCAN: Run port scan (naabu/nmap/masscan)
    - DISCOVERY: Full asset discovery
    - SUBDOMAIN_ENUM: Subdomain enumeration
    - And more...
    """
    
    def __init__(self):
        """Initialize the scanner worker."""
        global scan_semaphore
        
        # Database connection
        if DATABASE_URL:
            self.engine = create_engine(
                DATABASE_URL,
                pool_pre_ping=True,  # Verify connections before use
                pool_reset_on_return='rollback'  # Ensure clean state on connection return
            )
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        else:
            logger.warning("DATABASE_URL not set, running in test mode")
            self.engine = None
            self.SessionLocal = None
        
        # SQS client
        if SQS_QUEUE_URL:
            self.sqs = boto3.client('sqs', region_name=AWS_REGION)
            self.queue_url = SQS_QUEUE_URL
        else:
            logger.warning("SQS_QUEUE_URL not set, running in test mode")
            self.sqs = None
            self.queue_url = None
        
        # Initialize services (lazy init for discovery which needs db)
        self.nuclei_service = NucleiService()
        self.port_scanner_service = PortScannerService()
        self._discovery_service = None  # Lazy initialized with db session
        
        # Initialize semaphore for concurrent scan limiting
        scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        self.scan_semaphore = scan_semaphore
        
        logger.info(f"Scanner worker initialized (max_concurrent={MAX_CONCURRENT_SCANS})")
    
    def get_discovery_service(self, db):
        """Get or create discovery service with db session."""
        return DiscoveryService(db)
    
    def get_db_session(self):
        """Get a fresh database session with clean transaction state."""
        if self.SessionLocal:
            session = self.SessionLocal()
            # Ensure we start with a clean transaction state
            try:
                session.rollback()
            except Exception:
                pass  # Ignore if no transaction to rollback
            return session
        return None
    
    async def poll_for_jobs(self):
        """Poll for scan jobs from SQS and database (hybrid approach).
        
        This ensures scans are processed whether they were queued to SQS or not.
        SQS messages are processed first, then database PENDING scans are checked.
        """
        messages = []
        
        # If SQS is configured, poll it first
        if self.sqs and self.queue_url:
            try:
                response = self.sqs.receive_message(
                    QueueUrl=self.queue_url,
                    MaxNumberOfMessages=1,
                    WaitTimeSeconds=5,  # Shorter wait for hybrid polling
                    VisibilityTimeout=VISIBILITY_TIMEOUT,
                    MessageAttributeNames=['All']
                )
                messages = response.get('Messages', [])
            except ClientError as e:
                logger.error(f"Error polling SQS: {e}")
        
        # Also check database for any PENDING scans not in SQS
        # This catches scheduled scans that failed to queue, or scans created when SQS was down
        if not messages:
            db_messages = await self.poll_database_for_jobs()
            if db_messages:
                messages.extend(db_messages)
        
        # If no messages from either source, wait before next poll
        if not messages:
            await asyncio.sleep(POLL_INTERVAL)
        
        return messages
    
    async def poll_database_for_jobs(self):
        """
        Poll database for pending scans.
        
        Supports concurrent execution by fetching multiple scans.
        Prioritizes ad-hoc scans (not triggered by scheduler) over scheduled scans.
        """
        db = self.get_db_session()
        if not db:
            return []
        
        try:
            # Calculate how many more scans we can run
            available_slots = MAX_CONCURRENT_SCANS - len(active_scans)
            if available_slots <= 0:
                await asyncio.sleep(5)  # Brief wait when at capacity
                return []
            
            # Find pending scans, prioritizing ad-hoc over scheduled
            # Ad-hoc scans don't have 'triggered_by_schedule' in config
            # Note: We order by created_at to process oldest first (FIFO)
            # The is_scheduled flag is determined after fetching, not in the query
            pending_scans = db.query(Scan).filter(
                Scan.status == ScanStatus.PENDING,
                ~Scan.id.in_(active_scans)  # Exclude already active
            ).order_by(
                Scan.created_at.asc()  # Process oldest scans first (FIFO)
            ).limit(available_slots).all()
            
            if not pending_scans:
                await asyncio.sleep(POLL_INTERVAL)
                return []
            
            # Convert to message format
            job_type_map = {
                ScanType.VULNERABILITY: 'NUCLEI_SCAN',
                ScanType.PORT_SCAN: 'PORT_SCAN',
                ScanType.PORT_VERIFY: 'PORT_VERIFY',
                ScanType.SERVICE_DETECT: 'SERVICE_DETECT',
                ScanType.DISCOVERY: 'DISCOVERY',
                ScanType.FULL: 'DISCOVERY',  # FULL uses the same discovery handler
                ScanType.SUBDOMAIN_ENUM: 'SUBDOMAIN_ENUM',
                ScanType.DNS_RESOLUTION: 'DNS_RESOLUTION',
                ScanType.HTTP_PROBE: 'HTTP_PROBE',
                ScanType.DNS_ENUM: 'DNS_RESOLUTION',  # Alias
                ScanType.LOGIN_PORTAL: 'LOGIN_PORTAL',
                ScanType.SCREENSHOT: 'SCREENSHOT',
                ScanType.PARAMSPIDER: 'PARAMSPIDER',
                ScanType.WAYBACKURLS: 'WAYBACKURLS',
                ScanType.KATANA: 'KATANA',
                ScanType.CLEANUP: 'CLEANUP',
                ScanType.TECHNOLOGY: 'TECHNOLOGY_SCAN',
            }
            
            messages = []
            for pending_scan in pending_scans:
                job_type = job_type_map.get(pending_scan.scan_type, 'NUCLEI_SCAN')
                config = pending_scan.config or {}
                is_scheduled = config.get('triggered_by_schedule') is not None
                
                # Build job data with config values extracted
                job_data = {
                    'job_type': job_type,
                    'scan_id': pending_scan.id,
                    'organization_id': pending_scan.organization_id,
                    'targets': pending_scan.targets or [],
                    'config': config,
                    'is_scheduled': is_scheduled,
                    # Extract common config fields for easier access
                    'scanner': config.get('scanner', 'naabu'),
                    'ports': config.get('ports'),
                    'severity': config.get('severity'),
                    'tags': config.get('tags'),
                    'exclude_tags': config.get('exclude_tags'),
                    'service_detection': config.get('service_detection', True),
                    'domain': pending_scan.targets[0] if pending_scan.targets else None,
                }
                
                message = {
                    'MessageId': f'db-{pending_scan.id}',
                    'ReceiptHandle': f'db-{pending_scan.id}',
                    'Body': json.dumps(job_data)
                }
                messages.append(message)
                
                scan_type_str = 'scheduled' if is_scheduled else 'ad-hoc'
                logger.info(f"Found {scan_type_str} scan {pending_scan.id} ({pending_scan.scan_type.value})")
            
            return messages
            
        except Exception as e:
            logger.error(f"Error polling database: {e}")
            return []
        finally:
            db.close()
    
    def _mark_scan_running(self, scan_id: int) -> bool:
        """Mark a scan as RUNNING immediately. Returns True if successful."""
        db = self.get_db_session()
        if not db:
            logger.error(f"Scan {scan_id}: No database connection to mark RUNNING")
            return False
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.status == ScanStatus.PENDING:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                db.commit()
                logger.info(f"Scan {scan_id} marked as RUNNING")
                return True
            elif scan:
                logger.warning(f"Scan {scan_id} already has status {scan.status.value}, skipping")
                return False
            else:
                logger.error(f"Scan {scan_id} not found in database")
                return False
        except Exception as e:
            logger.error(f"Failed to mark scan {scan_id} as RUNNING: {e}")
            db.rollback()
            return False
        finally:
            db.close()
    
    def _mark_scan_failed(self, scan_id: int, error_message: str):
        """Mark a scan as FAILED."""
        db = self.get_db_session()
        if not db:
            logger.error(f"Scan {scan_id}: No database connection to mark FAILED")
            return
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.status != ScanStatus.COMPLETED:
                scan.status = ScanStatus.FAILED
                scan.error_message = error_message[:500] if error_message else "Unknown error"
                scan.completed_at = datetime.utcnow()
                db.commit()
                logger.info(f"Scan {scan_id} marked as FAILED: {error_message[:100]}")
        except Exception as e:
            logger.error(f"Failed to mark scan {scan_id} as FAILED: {e}")
            db.rollback()
        finally:
            db.close()
    
    async def recover_stale_scans(self) -> int:
        """
        Detect and recover scans that are stuck in RUNNING status.
        
        Scans are considered stale if they:
        - Have been RUNNING for more than STALE_SCAN_THRESHOLD_MINUTES
        - Are not currently being processed by this worker (not in active_scans)
        
        Stale scans are reset to PENDING to be retried.
        
        Returns the count of recovered scans.
        """
        STALE_SCAN_THRESHOLD_MINUTES = 60  # Scans running > 1 hour are considered stale
        
        db = self.get_db_session()
        if not db:
            return 0
        
        try:
            from datetime import timedelta
            threshold = datetime.utcnow() - timedelta(minutes=STALE_SCAN_THRESHOLD_MINUTES)
            
            # Find scans that are RUNNING but started too long ago
            stale_scans = db.query(Scan).filter(
                Scan.status == ScanStatus.RUNNING,
                Scan.started_at < threshold,
                ~Scan.id.in_(active_scans)  # Exclude scans actively being processed
            ).all()
            
            recovered_count = 0
            for scan in stale_scans:
                # Reset to PENDING so it will be retried
                old_error = scan.error_message or ""
                scan.status = ScanStatus.PENDING
                scan.started_at = None
                scan.error_message = f"Recovered from stale RUNNING state after {STALE_SCAN_THRESHOLD_MINUTES}+ minutes. Previous error: {old_error[:200]}"
                
                # Track retry count in config
                config = scan.config or {}
                retry_count = config.get('_retry_count', 0) + 1
                config['_retry_count'] = retry_count
                config['_last_recovery'] = datetime.utcnow().isoformat()
                scan.config = config
                
                # If too many retries, mark as failed instead
                if retry_count >= 3:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = f"Failed after {retry_count} automatic recovery attempts. Manual investigation required."
                    scan.completed_at = datetime.utcnow()
                    logger.warning(f"Scan {scan.id} failed after {retry_count} recovery attempts")
                else:
                    logger.info(f"Recovered stale scan {scan.id} (attempt {retry_count})")
                    recovered_count += 1
            
            if stale_scans:
                db.commit()
                logger.info(f"Recovered {recovered_count} stale scans, {len(stale_scans) - recovered_count} marked as failed")
            
            return recovered_count
            
        except Exception as e:
            logger.error(f"Error recovering stale scans: {e}")
            db.rollback()
            return 0
        finally:
            db.close()

    def _delete_sqs_message_safe(self, message_id: str, receipt_handle: str, is_db_message: bool, scan_id: int = None):
        """Safely delete an SQS message with comprehensive logging."""
        if is_db_message:
            logger.debug(f"Skipping SQS delete for database message {message_id}")
            return
        
        if not self.sqs:
            logger.warning(f"Cannot delete SQS message for scan {scan_id}: SQS client not initialized")
            return
            
        if not self.queue_url:
            logger.warning(f"Cannot delete SQS message for scan {scan_id}: Queue URL not configured")
            return
            
        if not receipt_handle:
            logger.warning(f"Cannot delete SQS message for scan {scan_id}: No receipt handle")
            return
        
        try:
            self.sqs.delete_message(
                QueueUrl=self.queue_url,
                ReceiptHandle=receipt_handle
            )
            logger.info(f"Deleted SQS message {message_id} for scan {scan_id}")
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            logger.error(f"AWS error deleting SQS message for scan {scan_id}: {error_code} - {e}")
        except Exception as e:
            logger.error(f"Failed to delete SQS message for scan {scan_id}: {type(e).__name__}: {e}")

    async def _auto_close_stale_findings(
        self,
        db,
        organization_id: int,
        scanned_hosts: set,
        current_findings: list,
        scan_id: int
    ) -> int:
        """
        Auto-close findings that were not detected in the current scan.
        
        This compares previous open findings against what was found in this scan.
        If a finding existed before but wasn't re-detected on the same host+template,
        it's marked as resolved (auto-closed).
        
        Returns the count of auto-resolved findings.
        """
        from app.models.vulnerability import Vulnerability, VulnerabilityStatus
        from urllib.parse import urlparse
        
        # Normalize scanned hosts (remove protocol/port)
        normalized_hosts = set()
        for host in scanned_hosts:
            if host.startswith(("http://", "https://")):
                normalized = urlparse(host).netloc.split(":")[0]
            else:
                normalized = host.split(":")[0]
            if normalized:
                normalized_hosts.add(normalized.lower())
        
        if not normalized_hosts:
            return 0
        
        # Build a set of (host, template_id) tuples from current findings
        current_finding_keys = set()
        for finding in current_findings:
            if finding.host and finding.template_id:
                host = finding.host
                if host.startswith(("http://", "https://")):
                    host = urlparse(host).netloc.split(":")[0]
                else:
                    host = host.split(":")[0]
                if host:
                    current_finding_keys.add((host.lower(), finding.template_id))
        
        # Get assets that were scanned
        from app.models.asset import Asset
        scanned_assets = db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.value.in_(list(normalized_hosts))
        ).all()
        
        if not scanned_assets:
            return 0
        
        scanned_asset_ids = [a.id for a in scanned_assets]
        scanned_asset_values = {a.id: a.value.lower() for a in scanned_assets}
        
        # Find all open findings for scanned assets
        open_findings = db.query(Vulnerability).filter(
            Vulnerability.asset_id.in_(scanned_asset_ids),
            Vulnerability.status == VulnerabilityStatus.OPEN
        ).all()
        
        auto_resolved_count = 0
        for finding in open_findings:
            if not finding.template_id:
                continue  # Skip findings without template_id
            
            asset_value = scanned_asset_values.get(finding.asset_id, "").lower()
            if not asset_value:
                continue
            
            # Check if this finding was re-detected
            finding_key = (asset_value, finding.template_id)
            if finding_key not in current_finding_keys:
                # Finding was not re-detected - auto-close it
                finding.status = VulnerabilityStatus.RESOLVED
                finding.resolved_at = datetime.utcnow()
                if finding.metadata_ is None:
                    finding.metadata_ = {}
                finding.metadata_['auto_resolved'] = True
                finding.metadata_['auto_resolved_scan_id'] = scan_id
                finding.metadata_['auto_resolved_reason'] = 'Not detected in rescan'
                auto_resolved_count += 1
        
        if auto_resolved_count > 0:
            db.commit()
        
        return auto_resolved_count

    async def process_message(self, message: dict):
        """Process a single scan job message."""
        message_id = message.get('MessageId')
        receipt_handle = message.get('ReceiptHandle')
        is_db_message = message_id.startswith('db-') if message_id else False
        
        try:
            body = json.loads(message.get('Body', '{}'))
            job_type = body.get('job_type')
            scan_id = body.get('scan_id')
            
            logger.info(f"Processing job {message_id}: type={job_type}, scan_id={scan_id}")
            
            # CRITICAL: Mark scan as RUNNING immediately to prevent re-polling
            if scan_id and not self._mark_scan_running(scan_id):
                logger.warning(f"Scan {scan_id} could not be marked RUNNING, skipping")
                # IMPORTANT: Delete the SQS message even when skipping to prevent infinite reprocessing
                self._delete_sqs_message_safe(message_id, receipt_handle, is_db_message, scan_id)
                return
            
            try:
                # Route to appropriate handler
                if job_type == 'NUCLEI_SCAN':
                    await self.handle_nuclei_scan(body)
                elif job_type == 'PORT_SCAN':
                    await self.handle_port_scan(body)
                elif job_type == 'PORT_VERIFY':
                    await self.handle_port_verify(body)
                elif job_type == 'SERVICE_DETECT':
                    await self.handle_service_detect(body)
                elif job_type == 'DISCOVERY':
                    await self.handle_discovery(body)
                elif job_type == 'SUBDOMAIN_ENUM':
                    await self.handle_subdomain_enum(body)
                elif job_type == 'DNS_RESOLUTION':
                    await self.handle_dns_resolution(body)
                elif job_type == 'HTTP_PROBE':
                    await self.handle_http_probe(body)
                elif job_type == 'LOGIN_PORTAL':
                    await self.handle_login_portal_scan(body)
                elif job_type == 'SCREENSHOT':
                    await self.handle_screenshot_scan(body)
                elif job_type == 'PARAMSPIDER':
                    await self.handle_paramspider_scan(body)
                elif job_type == 'WAYBACKURLS':
                    await self.handle_waybackurls_scan(body)
                elif job_type == 'KATANA':
                    await self.handle_katana_scan(body)
                elif job_type == 'CLEANUP':
                    await self.handle_cleanup(body)
                elif job_type == 'TECHNOLOGY_SCAN':
                    await self.handle_technology_scan(body)
                else:
                    logger.warning(f"Unknown job type: {job_type}")
                    if scan_id:
                        self._mark_scan_failed(scan_id, f"Unknown job type: {job_type}")
                    # Delete message for unknown job types to prevent infinite reprocessing
                    self._delete_sqs_message_safe(message_id, receipt_handle, is_db_message, scan_id)
                    return
            except Exception as handler_error:
                logger.error(f"Scan {scan_id} handler failed: {handler_error}", exc_info=True)
                if scan_id:
                    self._mark_scan_failed(scan_id, str(handler_error))
                # Delete message even on failure to prevent infinite reprocessing
                self._delete_sqs_message_safe(message_id, receipt_handle, is_db_message, scan_id)
                raise
            
            # Delete message from SQS queue after successful processing
            self._delete_sqs_message_safe(message_id, receipt_handle, is_db_message, scan_id)
            
            logger.info(f"Job {message_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Error processing message {message_id}: {e}", exc_info=True)
            # Message will return to queue after visibility timeout (SQS)
            # For DB messages, the scan status will be set to FAILED by handlers
    
    async def handle_nuclei_scan(self, job_data: dict):
        """Handle Nuclei vulnerability scan job."""
        scan_id = job_data.get('scan_id')
        targets = job_data.get('targets', [])
        organization_id = job_data.get('organization_id')
        # Default to all severities to catch all findings (including info for asset discovery)
        severity = job_data.get('severity') or ['critical', 'high', 'medium', 'low', 'info']
        tags = job_data.get('tags') or []
        exclude_tags = job_data.get('exclude_tags') or []
        
        # Normalize targets - ensure URLs have protocol
        normalized_targets = []
        for target in targets:
            target = target.strip()
            if not target:
                continue
            # If it's a domain without protocol, add https://
            if not target.startswith(('http://', 'https://')) and '/' not in target:
                # It's a bare domain - try https first
                normalized_targets.append(f"https://{target}")
            else:
                normalized_targets.append(target)
        
        if normalized_targets:
            targets = normalized_targets
            logger.info(f"Normalized {len(targets)} targets for Nuclei scan")
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection for Nuclei scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return
        
        try:
            # Status is already set to RUNNING in process_message
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            
            # IMPORTANT: Create assets for ALL targets BEFORE scanning
            # This ensures assets appear in the assets table even if no vulnerabilities are found
            from urllib.parse import urlparse
            assets_created = 0
            assets_updated = 0
            
            if scan:
                scan.current_step = "Creating assets for scan targets"
                db.commit()
            
            for target in targets:
                try:
                    # Extract hostname from URL
                    target_str = target.strip()
                    if target_str.startswith(('http://', 'https://')):
                        parsed = urlparse(target_str)
                        hostname = parsed.hostname or parsed.netloc
                        if hostname and ':' in hostname:
                            hostname = hostname.split(':')[0]
                    else:
                        hostname = target_str.split(':')[0] if ':' in target_str else target_str
                    
                    if not hostname:
                        continue
                    
                    hostname = hostname.lower().strip()
                    
                    # Check if asset already exists
                    existing_asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == hostname
                    ).first()
                    
                    if existing_asset:
                        # Update last seen
                        existing_asset.last_seen = datetime.utcnow()
                        assets_updated += 1
                    else:
                        # Determine asset type based on hostname pattern
                        import re
                        is_ip = bool(re.match(r'^[\d.]+$', hostname) or ':' in hostname)  # IPv4 or IPv6
                        
                        # Determine if it's a subdomain or root domain
                        parts = hostname.split('.')
                        if is_ip:
                            asset_type = AssetType.IP_ADDRESS
                        elif len(parts) > 2:
                            asset_type = AssetType.SUBDOMAIN
                        else:
                            asset_type = AssetType.DOMAIN
                        
                        # Extract root domain for subdomain assets
                        root_domain = None
                        if asset_type == AssetType.SUBDOMAIN and len(parts) >= 2:
                            # Get last two parts (e.g., rockwell.com from sub.domain.rockwell.com)
                            root_domain = '.'.join(parts[-2:])
                        
                        # Create the asset
                        new_asset = Asset(
                            organization_id=organization_id,
                            name=hostname,
                            value=hostname,
                            asset_type=asset_type,
                            root_domain=root_domain,
                            discovery_source="nuclei_scan",
                            association_reason=f"Added as target for vulnerability scan {scan_id}",
                            status=AssetStatus.DISCOVERED,
                            in_scope=True,
                            # For IP assets, also populate ip_address fields
                            ip_address=hostname if is_ip else None,
                            ip_addresses=[hostname] if is_ip else [],
                        )
                        db.add(new_asset)
                        assets_created += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to create asset for target {target}: {e}")
                    continue
            
            # Commit assets before running scan
            if assets_created > 0 or assets_updated > 0:
                db.commit()
                logger.info(f"Pre-scan asset creation: {assets_created} created, {assets_updated} updated")
            
            if scan:
                scan.current_step = "Running Nuclei vulnerability scan"
                db.commit()
            
            # Run Nuclei scan
            logger.info(f"Starting Nuclei scan on {len(targets)} targets with severity: {severity}")
            logger.debug(f"Nuclei targets: {targets[:5]}{'...' if len(targets) > 5 else ''}")
            
            # Get rate limit from config or use environment default
            config = job_data.get('config', {})
            rate_limit = config.get('rate_limit', DEFAULT_NUCLEI_RATE_LIMIT)
            
            result = await self.nuclei_service.scan_targets(
                targets=targets,
                severity=severity,
                tags=tags if tags else None,
                exclude_tags=exclude_tags if exclude_tags else None,
                rate_limit=rate_limit
            )
            
            # Log Nuclei results
            logger.info(
                f"Nuclei scan returned: {len(result.findings)} findings, "
                f"success={result.success}, errors={len(result.errors)}, "
                f"duration={result.duration_seconds:.2f}s"
            )
            
            if result.errors:
                logger.warning(f"Nuclei scan errors: {result.errors}")
            
            if not result.findings:
                logger.info(
                    f"Nuclei found no vulnerabilities for targets. This could mean: "
                    f"1) The site is secure, 2) WAF is blocking scans, or "
                    f"3) Templates don't match the target technologies."
                )
            
            # Import findings
            findings_service = NucleiFindingsService(db)
            import_summary = findings_service.import_scan_results(
                scan_result=result,
                organization_id=organization_id,
                scan_id=scan_id,
                create_assets=True,
                create_labels=True
            )
            
            # Mark scanned assets as live (we got a response from Nuclei)
            live_assets_count = 0
            for finding in result.findings:
                if finding.host:
                    hostname = finding.host
                    # Strip protocol/port if present
                    if hostname.startswith(("http://", "https://")):
                        from urllib.parse import urlparse
                        hostname = urlparse(hostname).netloc.split(":")[0]
                    else:
                        hostname = hostname.split(":")[0]
                    
                    # Update asset to mark as live
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == hostname
                    ).first()
                    
                    if asset and not asset.is_live:
                        asset.is_live = True
                        live_assets_count += 1
            
            if live_assets_count > 0:
                db.commit()
                logger.info(f"Marked {live_assets_count} assets as live from Nuclei scan")
            
            # Calculate unique hosts that responded
            unique_hosts = set()
            for finding in result.findings:
                if finding.host:
                    unique_hosts.add(finding.host)
            
            # Auto-close findings not found in rescan
            # Only do this if we scanned specific assets and got results
            auto_resolved_count = 0
            if unique_hosts and organization_id:
                try:
                    auto_resolved_count = await self._auto_close_stale_findings(
                        db=db,
                        organization_id=organization_id,
                        scanned_hosts=unique_hosts,
                        current_findings=result.findings,
                        scan_id=scan_id
                    )
                    if auto_resolved_count > 0:
                        logger.info(f"Auto-resolved {auto_resolved_count} findings not found in rescan")
                except Exception as e:
                    logger.warning(f"Failed to auto-close stale findings: {e}")
                    # Rollback failed transaction to allow subsequent queries
                    try:
                        db.rollback()
                    except Exception:
                        pass
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.vulnerabilities_found = import_summary['findings_created']
                scan.assets_discovered = assets_created  # Record assets created from targets
                scan.results = {
                    'summary': result.summary,
                    'import_summary': import_summary,
                    'targets_original': result.targets_original,
                    'targets_expanded': result.targets_expanded,
                    'targets_scanned': result.targets_scanned,
                    'live_hosts': len(unique_hosts),
                    'findings_count': import_summary['findings_created'],
                    'auto_resolved_count': auto_resolved_count,
                    'assets_created_from_targets': assets_created,
                    'assets_updated': assets_updated,
                }
                db.commit()
            
            logger.info(
                f"Nuclei scan complete: {import_summary['findings_created']} findings, "
                f"{len(import_summary.get('cves_found', []))} CVEs, {len(unique_hosts)} live hosts"
            )
            
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    # Rollback any failed transaction first
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_port_scan(self, job_data: dict):
        """Handle port scan job."""
        scan_id = job_data.get('scan_id')
        targets = job_data.get('targets', [])
        organization_id = job_data.get('organization_id')
        scanner = job_data.get('scanner', 'naabu')
        ports = job_data.get('ports')
        service_detection = job_data.get('service_detection', True)
        
        # Get advanced config options with sensible defaults for reliability
        config = job_data.get('config', {})
        rate = config.get('rate', DEFAULT_PORT_SCAN_RATE)  # Use env var for default rate
        timeout = config.get('timeout', 30)  # Longer timeout
        retries = config.get('retries', 2)  # Retry on failure
        chunk_size = config.get('chunk_size', 64)  # Chunk large scans
        
        # Naabu-specific options
        top_ports = config.get('top_ports', 100)  # Top N ports if no ports specified
        exclude_cdn = config.get('exclude_cdn', True)  # Exclude CDN IPs
        exclude_ports = config.get('exclude_ports')  # Ports to exclude (e.g., "22,23")
        scan_type = config.get('scan_type', 'c')  # 'c' = CONNECT (no root), 's' = SYN
        host_discovery = config.get('host_discovery', False)  # Enable host discovery
        
        # Masscan-specific options
        banner_grab = config.get('banner_grab', True)  # Grab banners for service ID
        one_port_at_a_time = config.get('one_port_at_a_time', False)  # ASM Recon mode
        
        # Filter out IPv6 targets (not supported for port scanning)
        from app.services.port_scanner_service import PortScannerService
        scanner_svc = PortScannerService()
        original_count = len(targets)
        targets, ipv6_skipped = scanner_svc.filter_ipv4_only(targets)
        if ipv6_skipped > 0:
            logger.info(f"Filtered out {ipv6_skipped} IPv6 targets (not supported for port scanning)")
        
        if not targets:
            logger.warning(f"No valid IPv4 targets after filtering (skipped {ipv6_skipped} IPv6)")
            # Mark scan as completed with no results instead of leaving it pending
            db = self.get_db_session()
            if db:
                try:
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.COMPLETED
                        scan.completed_at = datetime.utcnow()
                        scan.results = {"error": "No valid IPv4 targets", "ipv6_skipped": ipv6_skipped}
                        db.commit()
                        logger.info(f"Scan {scan_id} marked completed (no valid targets)")
                finally:
                    db.close()
            return
        
        # IMPORTANT: Set default ports if not specified (don't scan all 65535!)
        # This prevents accidental 33+ minute scans
        if not ports or ports == "-":
            # Default to top 100 common ports for reasonable scan time
            ports = config.get('ports') or "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1723,3306,3389,5432,5900,8080,8443"
            logger.info(f"No ports specified, defaulting to top common ports")
        
        # Log scan estimate
        num_ports = scanner_svc._count_ports(ports) if hasattr(scanner_svc, '_count_ports') else 0
        num_hosts = scanner_svc._estimate_hosts(targets) if hasattr(scanner_svc, '_estimate_hosts') else len(targets)
        logger.info(f"Port scan: {num_hosts} hosts × {num_ports} ports = ~{num_hosts * num_ports:,} probes")
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection for port scan")
            self._mark_scan_failed(scan_id, "No database connection")
            return
        
        try:
            # Status is already set to RUNNING in process_message
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            
            # Map scanner type
            scanner_type_map = {
                'naabu': ScannerType.NAABU,
                'masscan': ScannerType.MASSCAN,
                'nmap': ScannerType.NMAP
            }
            selected_scanner = scanner_type_map.get(scanner, ScannerType.NAABU)
            
            # Run port scan with scanner-specific options
            # Base kwargs that all scanners accept
            scan_kwargs = {
                "targets": targets, 
                "ports": ports,
            }
            
            # Add scanner-specific options
            if selected_scanner == ScannerType.NAABU:
                scan_kwargs["rate"] = rate
                scan_kwargs["timeout"] = timeout
                scan_kwargs["retries"] = retries
                scan_kwargs["chunk_size"] = chunk_size
                scan_kwargs["top_ports"] = top_ports
                scan_kwargs["exclude_cdn"] = exclude_cdn
            elif selected_scanner == ScannerType.MASSCAN:
                scan_kwargs["rate"] = rate
                scan_kwargs["timeout"] = timeout
                scan_kwargs["banner_grab"] = banner_grab
                scan_kwargs["one_port_at_a_time"] = one_port_at_a_time
            elif selected_scanner == ScannerType.NMAP:
                # Nmap doesn't use rate/timeout in the same way
                scan_kwargs["service_detection"] = service_detection
                # Pass NSE scripts for ICS/OT protocol detection
                nse_scripts = config.get('nse_scripts', [])
                if nse_scripts:
                    scan_kwargs["scripts"] = nse_scripts
                    logger.info(f"Using NSE scripts for ICS detection: {nse_scripts}")
            
            logger.info(f"Starting port scan with rate={rate}, timeout={timeout}, retries={retries}")
            
            result = await self.port_scanner_service.scan(
                scanner=selected_scanner,
                **scan_kwargs
            )
            
            logger.info(f"Scan {scan_id}: masscan/naabu completed with {len(result.ports_found)} ports found")
            
            # Import results with error handling
            try:
                import_summary = self.port_scanner_service.import_results_to_assets(
                    db=db,
                    scan_result=result,
                    organization_id=organization_id,
                    create_assets=True
                )
                logger.info(f"Scan {scan_id}: imported {import_summary.get('ports_imported', 0)} ports")
            except Exception as import_error:
                logger.error(f"Scan {scan_id}: import_results_to_assets failed: {import_error}", exc_info=True)
                # CRITICAL: Rollback the failed transaction to allow subsequent queries
                try:
                    db.rollback()
                except Exception:
                    pass
                import_summary = {"ports_imported": 0, "ports_updated": 0, "errors": [str(import_error)]}
            
            # Generate findings from port scan results
            try:
                findings_service = PortFindingsService()
                findings_summary = findings_service.create_findings_from_scan(
                    db=db,
                    organization_id=organization_id,
                    scan_id=scan_id
                )
                logger.info(f"Scan {scan_id}: created {findings_summary.get('findings_created', 0)} findings")
            except Exception as findings_error:
                logger.error(f"Scan {scan_id}: create_findings_from_scan failed: {findings_error}", exc_info=True)
                # CRITICAL: Rollback the failed transaction to allow subsequent queries
                try:
                    db.rollback()
                except Exception:
                    pass
                findings_summary = {"findings_created": 0, "by_severity": {}}
            
            # Calculate unique live hosts (assets discovered)
            unique_hosts = set()
            for p in result.ports_found:
                unique_hosts.add(p.ip or p.host)
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.assets_discovered = len(unique_hosts)  # Live hosts with open ports
                scan.vulnerabilities_found = findings_summary.get('findings_created', 0)
                
                # Convert PortResult objects to dicts for JSON serialization
                ports_data = [
                    {"host": p.host, "ip": p.ip, "port": p.port, "protocol": p.protocol, "state": p.state}
                    for p in result.ports_found
                ]
                
                # Build host_results for frontend display
                # Group ports by host
                host_ports = {}
                for p in result.ports_found:
                    host_key = p.ip or p.host
                    if host_key not in host_ports:
                        host_ports[host_key] = []
                    host_ports[host_key].append(p.port)
                
                # Also get host results from import_summary if available
                host_results = import_summary.get('host_results', [])
                if not host_results:
                    # Build from our port data
                    host_results = []
                    for host, ports in host_ports.items():
                        host_results.append({
                            'host': host,
                            'ip': host,
                            'is_live': len(ports) > 0,
                            'open_ports': sorted(set(ports)),
                            'port_count': len(set(ports)),
                        })
                
                # Get pre-calculated targets stats from config (set during schedule trigger)
                # or calculate from targets
                config_target_stats = scan.config.get('target_stats', {}) if scan.config else {}
                existing_results = scan.results or {}
                
                # Prefer pre-calculated value, then existing, then fallback
                targets_expanded = (
                    config_target_stats.get('targets_expanded') or 
                    existing_results.get('targets_expanded') or
                    _calculate_targets_expanded(scan.targets)
                )
                targets_original = (
                    config_target_stats.get('targets_original') or 
                    existing_results.get('targets_original') or
                    len(scan.targets) if scan.targets else 0
                )
                cidr_count = config_target_stats.get('cidr_count', 0)
                host_count = config_target_stats.get('host_count', 0)
                
                scan.results = {
                    # Frontend expects ports_found as a NUMBER, not array
                    'ports_found': len(result.ports_found),
                    'ports_data': ports_data,  # Keep array data under different key
                    'ports_imported': import_summary.get('ports_imported', 0),
                    'ports_updated': import_summary.get('ports_updated', 0),
                    'live_hosts': len(unique_hosts),
                    'host_results': host_results,  # Array for frontend table display
                    'targets_scanned': result.targets_scanned,
                    'targets_original': targets_original,
                    'targets_expanded': targets_expanded,
                    'cidr_count': cidr_count,
                    'host_count': host_count,
                    'scanner': result.scanner.value,
                    'duration_seconds': result.duration_seconds,
                    'errors': result.errors,
                    'import_summary': import_summary,
                    'findings_summary': findings_summary
                }
                # If there were scanner errors but scan "succeeded", note it
                if result.errors:
                    scan.error_message = "; ".join(result.errors[:3])  # First 3 errors
                
                # Update netblocks that were scanned
                # Check if any scanned targets match netblock CIDR ranges
                scanned_netblocks = 0
                for target in targets:
                    # Check if target is a CIDR range
                    if '/' in target:
                        try:
                            # Find matching netblock by CIDR notation
                            netblock = db.query(Netblock).filter(
                                Netblock.organization_id == organization_id,
                                Netblock.cidr_notation.contains(target)
                            ).first()
                            
                            if netblock:
                                netblock.last_scanned = datetime.utcnow()
                                netblock.scan_count = (netblock.scan_count or 0) + 1
                                scanned_netblocks += 1
                        except Exception as e:
                            logger.warning(f"Failed to update netblock for {target}: {e}")
                    else:
                        # Single IP - try to find containing netblock
                        try:
                            ip_obj = ipaddress.ip_address(target)
                            # Find netblocks where this IP falls within the range
                            org_netblocks = db.query(Netblock).filter(
                                Netblock.organization_id == organization_id
                            ).all()
                            
                            for netblock in org_netblocks:
                                if netblock.cidr_notation:
                                    for cidr in netblock.cidr_notation.split(';'):
                                        cidr = cidr.strip()
                                        if cidr:
                                            try:
                                                network = ipaddress.ip_network(cidr, strict=False)
                                                if ip_obj in network:
                                                    netblock.last_scanned = datetime.utcnow()
                                                    netblock.scan_count = (netblock.scan_count or 0) + 1
                                                    scanned_netblocks += 1
                                                    break
                                            except ValueError:
                                                pass
                        except ValueError:
                            pass  # Not an IP address
                
                if scanned_netblocks > 0:
                    logger.info(f"Updated {scanned_netblocks} netblocks as scanned")
            
            # Commit the scan results BEFORE any additional processing
            try:
                db.commit()
                logger.info(
                    f"Port scan {scan_id} complete: {len(result.ports_found)} ports, "
                    f"{findings_summary.get('findings_created', 0)} findings"
                )
            except Exception as commit_error:
                logger.error(f"Scan {scan_id}: Failed to commit results: {commit_error}", exc_info=True)
                db.rollback()
                raise
            
        except Exception as e:
            logger.error(f"Port scan {scan_id} failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    # Rollback any failed transaction first
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_port_verify(self, job_data: dict):
        """
        Handle port verification job - runs nmap on all unverified open ports.
        
        This is the background scan that verifies masscan-discovered ports using
        nmap to determine if they're truly open or filtered.
        """
        import subprocess
        import re as regex_module
        from app.models.port_service import PortService, PortState, Protocol
        
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config', {})
        
        # Config options
        max_ports = config.get('max_ports', 500)  # Max ports to verify per scan
        port_ids = config.get('port_ids')  # Specific port IDs to verify (from bulk verify)
        verify_filtered = config.get('verify_filtered', False)  # Also re-verify filtered ports
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection for port verification")
            self._mark_scan_failed(scan_id, "No database connection")
            return
        
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.current_step = "Gathering unverified ports"
                db.commit()
            
            # Get ports to verify
            if port_ids:
                # Specific ports requested (from bulk verify)
                ports_query = db.query(PortService).filter(PortService.id.in_(port_ids))
            else:
                # Get all unverified open ports for the organization
                ports_query = db.query(PortService).join(Asset).filter(
                    Asset.organization_id == organization_id,
                    PortService.verified == False,
                    PortService.state == PortState.OPEN
                )
                
                if verify_filtered:
                    # Also include filtered ports that haven't been verified
                    ports_query = db.query(PortService).join(Asset).filter(
                        Asset.organization_id == organization_id,
                        PortService.verified == False,
                        PortService.state.in_([PortState.OPEN, PortState.FILTERED])
                    )
            
            ports_to_verify = ports_query.limit(max_ports).all()
            
            if not ports_to_verify:
                logger.info(f"Scan {scan_id}: No unverified ports found")
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {"message": "No unverified ports to verify", "ports_verified": 0}
                    db.commit()
                return
            
            logger.info(f"Scan {scan_id}: Verifying {len(ports_to_verify)} ports with nmap")
            
            verified_count = 0
            open_count = 0
            filtered_count = 0
            closed_count = 0
            errors = []
            
            # Process ports - group by IP for efficiency
            ip_ports = {}
            for port_record in ports_to_verify:
                # Get IP address for this port
                ip = port_record.scanned_ip
                if not ip and port_record.asset:
                    if port_record.asset.ip_addresses:
                        ip = port_record.asset.ip_addresses[0]
                    elif port_record.asset.value and regex_module.match(r'^[\d.]+$', port_record.asset.value):
                        ip = port_record.asset.value
                
                if ip:
                    if ip not in ip_ports:
                        ip_ports[ip] = []
                    ip_ports[ip].append(port_record)
            
            total_ips = len(ip_ports)
            processed_ips = 0
            
            for ip, port_records in ip_ports.items():
                processed_ips += 1
                
                # Update progress
                if scan:
                    progress = int((processed_ips / total_ips) * 100)
                    scan.progress = progress
                    scan.current_step = f"Verifying {ip} ({processed_ips}/{total_ips})"
                    db.commit()
                
                # Build port list for this IP
                port_list = ",".join([str(p.port) for p in port_records])
                
                # Run nmap for this IP (batch all ports together)
                cmd = [
                    "nmap", "-Pn", "-sT", "-sV", "--version-light",
                    "-p", port_list, ip,
                    "--max-retries", "2",
                    "-T4",
                    "-oG", "-"  # Greppable output for easier parsing
                ]
                
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=120  # 2 minute timeout per IP
                    )
                    
                    output = result.stdout
                    
                    # Parse greppable output for each port
                    # Format: "Host: 1.2.3.4 (hostname)  Ports: 80/open/tcp//http//, 443/open/tcp//https//"
                    for port_record in port_records:
                        port_num = port_record.port
                        protocol = port_record.protocol.value
                        
                        # Look for port in output
                        # Pattern: "PORT/STATE/PROTOCOL//SERVICE//"
                        port_pattern = rf'{port_num}/(\w+)/{protocol}//([^/]*)//'
                        match = regex_module.search(port_pattern, output)
                        
                        if match:
                            state = match.group(1)  # open, closed, filtered
                            service = match.group(2).strip() if match.group(2) else None
                        else:
                            # Try standard output format
                            std_pattern = rf'{port_num}/{protocol}\s+(\w+)\s+(\S+)'
                            std_match = regex_module.search(std_pattern, output)
                            if std_match:
                                state = std_match.group(1)
                                service = std_match.group(2) if std_match.group(2) != "unknown" else None
                            else:
                                state = "unknown"
                                service = None
                        
                        # Update port record
                        port_record.verified = True
                        port_record.verified_at = datetime.utcnow()
                        port_record.verified_state = state
                        port_record.verification_scanner = "nmap"
                        
                        # Update service if detected
                        if service and service not in ["unknown", ""]:
                            port_record.service_name = service
                        
                        # Update port state based on nmap result
                        if state == "open":
                            port_record.state = PortState.OPEN
                            open_count += 1
                        elif state == "filtered":
                            port_record.state = PortState.FILTERED
                            filtered_count += 1
                        elif state == "closed":
                            port_record.state = PortState.CLOSED
                            closed_count += 1
                        
                        verified_count += 1
                    
                    db.commit()
                    
                except subprocess.TimeoutExpired:
                    logger.warning(f"Nmap timeout for {ip}")
                    errors.append(f"Timeout scanning {ip}")
                except Exception as e:
                    logger.error(f"Error verifying {ip}: {e}")
                    errors.append(f"Error scanning {ip}: {str(e)[:100]}")
                    db.rollback()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.results = {
                    "ports_verified": verified_count,
                    "open_confirmed": open_count,
                    "filtered_detected": filtered_count,
                    "closed_detected": closed_count,
                    "ips_scanned": total_ips,
                    "errors": errors[:10] if errors else []
                }
                if errors:
                    scan.error_message = f"{len(errors)} errors during verification"
                db.commit()
            
            logger.info(
                f"Port verification {scan_id} complete: {verified_count} ports verified "
                f"(open={open_count}, filtered={filtered_count}, closed={closed_count})"
            )
            
        except Exception as e:
            logger.error(f"Port verification {scan_id} failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_service_detect(self, job_data: dict):
        """
        Handle service detection job - runs deep nmap scans on unknown services.
        
        This scans ports where service_name is 'unknown' or NULL to identify
        what service is actually running using nmap's version detection.
        """
        import subprocess
        import re as regex_module
        from app.models.port_service import PortService, PortState, Protocol
        
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        config = job_data.get('config', {})
        
        # Config options
        max_ports = config.get('max_ports', 200)  # Max ports to scan (deep scan is slower)
        intensity = config.get('intensity', 7)  # Version detection intensity (1-9)
        include_scripts = config.get('include_scripts', True)  # Run default NSE scripts
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection for service detection")
            self._mark_scan_failed(scan_id, "No database connection")
            return
        
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.current_step = "Finding ports with unknown services"
                db.commit()
            
            # Get ports with unknown services
            from sqlalchemy import or_
            ports_to_scan = db.query(PortService).join(Asset).filter(
                Asset.organization_id == organization_id,
                PortService.state == PortState.OPEN,
                or_(
                    PortService.service_name.is_(None),
                    PortService.service_name == '',
                    PortService.service_name == 'unknown',
                    PortService.service_name == 'tcpwrapped'
                )
            ).limit(max_ports).all()
            
            if not ports_to_scan:
                logger.info(f"Scan {scan_id}: No unknown services found")
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {"message": "No unknown services to identify", "services_detected": 0}
                    db.commit()
                return
            
            logger.info(f"Scan {scan_id}: Deep scanning {len(ports_to_scan)} unknown services")
            
            detected_count = 0
            errors = []
            service_results = []
            
            # Group by IP
            ip_ports = {}
            for port_record in ports_to_scan:
                ip = port_record.scanned_ip
                if not ip and port_record.asset:
                    if port_record.asset.ip_addresses:
                        ip = port_record.asset.ip_addresses[0]
                    elif port_record.asset.value and regex_module.match(r'^[\d.]+$', port_record.asset.value):
                        ip = port_record.asset.value
                
                if ip:
                    if ip not in ip_ports:
                        ip_ports[ip] = []
                    ip_ports[ip].append(port_record)
            
            total_ips = len(ip_ports)
            processed_ips = 0
            
            for ip, port_records in ip_ports.items():
                processed_ips += 1
                
                # Update progress
                if scan:
                    progress = int((processed_ips / total_ips) * 100)
                    scan.progress = progress
                    scan.current_step = f"Deep scanning {ip} ({processed_ips}/{total_ips})"
                    db.commit()
                
                port_list = ",".join([str(p.port) for p in port_records])
                
                # Run deep nmap scan with version detection
                cmd = [
                    "nmap", "-Pn", "-sT", "-sV",
                    f"--version-intensity", str(intensity),
                    "-p", port_list, ip,
                    "-T4"
                ]
                
                # Add NSE scripts for service identification
                if include_scripts:
                    cmd.extend(["-sC"])  # Default scripts
                
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=300  # 5 minute timeout for deep scans
                    )
                    
                    output = result.stdout
                    
                    # Parse output for each port
                    for port_record in port_records:
                        port_num = port_record.port
                        protocol = port_record.protocol.value
                        
                        # Look for detailed service info
                        # Format: "443/tcp open  https   nginx 1.18.0"
                        # Or: "443/tcp open  ssl/http nginx 1.18.0"
                        pattern = rf'{port_num}/{protocol}\s+\w+\s+([^\s]+)\s*(.*)?$'
                        
                        for line in output.split('\n'):
                            match = regex_module.search(pattern, line)
                            if match:
                                service = match.group(1).strip()
                                extra = match.group(2).strip() if match.group(2) else ""
                                
                                # Clean up service name
                                if service and service not in ["unknown", ""]:
                                    # Handle ssl/http style services
                                    if '/' in service:
                                        parts = service.split('/')
                                        port_record.is_ssl = 'ssl' in parts
                                        service = parts[-1]  # Get the actual service
                                    
                                    port_record.service_name = service
                                    
                                    # Parse product and version from extra
                                    if extra:
                                        # Try to extract product and version
                                        version_match = regex_module.match(r'([^\d\s]+)\s*([\d.]+.*)?', extra)
                                        if version_match:
                                            port_record.service_product = version_match.group(1).strip()
                                            if version_match.group(2):
                                                port_record.service_version = version_match.group(2).strip()
                                        else:
                                            port_record.service_extra_info = extra
                                    
                                    detected_count += 1
                                    service_results.append({
                                        "ip": ip,
                                        "port": port_num,
                                        "service": service,
                                        "product": port_record.service_product,
                                        "version": port_record.service_version
                                    })
                                break
                    
                    db.commit()
                    
                except subprocess.TimeoutExpired:
                    logger.warning(f"Deep scan timeout for {ip}")
                    errors.append(f"Timeout scanning {ip}")
                except Exception as e:
                    logger.error(f"Error scanning {ip}: {e}")
                    errors.append(f"Error scanning {ip}: {str(e)[:100]}")
                    db.rollback()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress = 100
                scan.results = {
                    "services_detected": detected_count,
                    "ports_scanned": len(ports_to_scan),
                    "ips_scanned": total_ips,
                    "detected_services": service_results[:50],  # First 50 for display
                    "errors": errors[:10] if errors else []
                }
                if errors:
                    scan.error_message = f"{len(errors)} errors during detection"
                db.commit()
            
            logger.info(
                f"Service detection {scan_id} complete: {detected_count} services identified "
                f"from {len(ports_to_scan)} unknown ports"
            )
            
        except Exception as e:
            logger.error(f"Service detection {scan_id} failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_discovery(self, job_data: dict):
        """Handle full asset discovery job."""
        import re
        import ipaddress
        
        scan_id = job_data.get('scan_id')
        targets = job_data.get('targets', [])
        domain = job_data.get('domain')
        organization_id = job_data.get('organization_id')
        
        # Filter targets to only include valid domains (not IPs or CIDRs)
        valid_domains = []
        
        # If single domain provided, use it
        if domain and not self._is_ip_or_cidr(domain):
            valid_domains.append(domain)
        
        # If targets list provided, filter for domains only
        for target in targets:
            if target and not self._is_ip_or_cidr(target):
                # Looks like a domain
                valid_domains.append(target)
        
        # Deduplicate
        valid_domains = list(set(valid_domains))
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                db.commit()
            
            if not valid_domains:
                logger.warning(f"No valid domains found for discovery scan {scan_id}. Targets were: {targets[:5]}...")
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {
                        'message': 'No valid domains to discover (IPs/CIDRs are not valid for domain discovery)',
                        'targets_received': len(targets),
                        'valid_domains': 0
                    }
                    db.commit()
                return
            
            logger.info(f"Running discovery for {len(valid_domains)} domains: {valid_domains[:3]}...")
            
            # Run discovery for each domain
            discovery_service = self.get_discovery_service(db)
            total_assets = 0
            total_subdomains = 0
            total_technologies = 0
            
            for domain_target in valid_domains:
                try:
                    result = await discovery_service.full_discovery(
                        domain=domain_target,
                        organization_id=organization_id,
                        enable_subdomain_enum=True,
                        enable_dns_enum=True,
                        enable_http_probe=True,
                        enable_tech_detection=True
                    )
                    total_assets += result.get('assets_created', 0)
                    total_subdomains += result.get('subdomains_found', 0)
                    total_technologies += result.get('technologies_detected', 0)
                    logger.info(f"Discovery for {domain_target}: {result.get('assets_created', 0)} assets")
                except Exception as domain_error:
                    logger.error(f"Discovery failed for {domain_target}: {domain_error}")
                    # Rollback failed transaction to allow subsequent queries
                    try:
                        db.rollback()
                    except Exception:
                        pass
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.results = {
                    'assets_created': total_assets,
                    'subdomains_found': total_subdomains,
                    'technologies_detected': total_technologies,
                    'domains_processed': len(valid_domains)
                }
                db.commit()
            
            logger.info(f"Discovery complete: {total_assets} assets from {len(valid_domains)} domains")
            
        except Exception as e:
            logger.error(f"Discovery failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    # Rollback any failed transaction first
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    def _is_ip_or_cidr(self, value: str) -> bool:
        """Check if a value is an IP address or CIDR block."""
        import ipaddress
        try:
            # Try to parse as IP address
            ipaddress.ip_address(value)
            return True
        except ValueError:
            pass
        
        try:
            # Try to parse as network/CIDR
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            pass
        
        return False
    
    async def handle_subdomain_enum(self, job_data: dict):
        """Handle subdomain enumeration job."""
        scan_id = job_data.get('scan_id')
        # Support both 'domain' and 'targets' for flexibility
        domain = job_data.get('domain')
        targets = job_data.get('targets', [])
        organization_id = job_data.get('organization_id')
        
        # If no domain specified, use first target
        if not domain and targets:
            domain = targets[0] if isinstance(targets, list) else targets
        
        if not domain:
            logger.error(f"Scan {scan_id}: No domain specified for subdomain enumeration")
            return
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                db.commit()
            
            # Run subdomain enumeration
            from app.services.subdomain_service import SubdomainService
            subdomain_service = SubdomainService()
            
            # enumerate_subdomains returns list[SubdomainResult]
            results = await subdomain_service.enumerate_subdomains(domain)
            
            # Create assets for discovered subdomains
            from app.models.asset import AssetType
            assets_created = 0
            sources_used = set()
            all_subdomains = []
            
            # Results is a list of SubdomainResult objects
            for result in results:
                subdomain = result.subdomain if hasattr(result, 'subdomain') else str(result)
                source = result.source if hasattr(result, 'source') else 'unknown'
                
                all_subdomains.append(subdomain)
                sources_used.add(source)
                
                existing = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == subdomain
                ).first()
                
                if not existing:
                    asset = Asset(
                        organization_id=organization_id,
                        name=subdomain,
                        value=subdomain,
                        asset_type=AssetType.SUBDOMAIN,
                        discovery_source=source
                    )
                    db.add(asset)
                    assets_created += 1
            
            db.commit()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.results = {
                    'subdomains_found': len(all_subdomains),
                    'assets_created': assets_created,
                    'sources': list(sources_used)
                }
                db.commit()
            
            logger.info(f"Subdomain enum complete: {len(all_subdomains)} found, {assets_created} created")
            
        except Exception as e:
            logger.error(f"Subdomain enum failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    # Rollback any failed transaction first
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    db.rollback()
            raise
        finally:
            if db:
                db.close()
    
    async def handle_dns_resolution(self, job_data: dict):
        """
        Handle DNS resolution scan job.
        
        Resolves domains/subdomains to IP addresses using dnsx and optionally
        geo-enriches the resolved IPs. This is useful for:
        - Populating IP addresses for newly discovered assets
        - Getting geolocation data for the world map
        - Understanding the infrastructure behind domains
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        include_geo = config.get('include_geo', True)
        limit = config.get('limit', 1000)
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Resolving domains to IPs"
                db.commit()
            
            dns_service = DNSResolutionService(db)
            
            # If specific targets provided, resolve just those
            if targets:
                logger.info(f"Resolving {len(targets)} specified targets")
                dns_results = await dns_service.resolve_domains(targets)
                
                resolved_count = 0
                geo_enriched = 0
                
                # Update assets with resolved IPs
                for target in targets:
                    dns_result = dns_results.get(target)
                    if not dns_result or not dns_result.ip_addresses:
                        continue
                    
                    # Find the asset
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == target
                    ).first()
                    
                    if asset:
                        # Update all IPs using the helper method
                        asset.update_ip_addresses(dns_result.ip_addresses)
                        
                        # Store DNS records
                        if not asset.metadata_:
                            asset.metadata_ = {}
                        asset.metadata_['dns_records'] = {
                            'a': dns_result.a_records,
                            'aaaa': dns_result.aaaa_records,
                            'cname': dns_result.cname,
                        }
                        asset.last_seen = datetime.utcnow()
                        resolved_count += 1
                        
                        # Geo-enrich if enabled
                        if include_geo and dns_result.ip_addresses:
                            geo_service = get_geolocation_service()
                            geo_data = await geo_service.lookup_ip(dns_result.ip_addresses[0])
                            if geo_data:
                                asset.latitude = geo_data.get('latitude')
                                asset.longitude = geo_data.get('longitude')
                                asset.city = geo_data.get('city')
                                asset.country = geo_data.get('country')
                                asset.country_code = geo_data.get('country_code')
                                asset.isp = geo_data.get('isp')
                                asset.asn = geo_data.get('asn')
                                geo_enriched += 1
                
                db.commit()
                
                result_summary = {
                    'targets': len(targets),
                    'resolved': resolved_count,
                    'geo_enriched': geo_enriched
                }
            else:
                # Resolve all unresolved assets in the organization
                logger.info(f"Resolving unresolved assets for org {organization_id}")
                
                if scan:
                    scan.current_step = "Resolving all unresolved domains"
                    db.commit()
                
                result_summary = await dns_service.resolve_and_update_assets(
                    organization_id=organization_id,
                    limit=limit,
                    include_geo=include_geo
                )
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.results = result_summary
                scan.assets_discovered = result_summary.get('resolved', 0)
                db.commit()
            
            logger.info(f"DNS resolution complete: {result_summary}")
            
        except Exception as e:
            logger.error(f"DNS resolution failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_http_probe(self, job_data: dict):
        """
        Handle HTTP probing scan job.
        
        Probes domains/subdomains to check if they have live web services.
        Updates assets with:
        - is_live status
        - HTTP status code
        - Page title
        - Live URL (final URL after redirects)
        - IP address (if discovered)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        limit = config.get('limit', 1000)
        timeout = config.get('timeout', 30)
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Probing HTTP services"
                db.commit()
            
            dns_service = DNSResolutionService(db)
            
            # If specific targets provided, probe just those
            if targets:
                logger.info(f"Probing {len(targets)} specified targets")
                probe_results = await dns_service.probe_http(targets, timeout=timeout)
                
                live_count = 0
                
                # Update assets
                for target in targets:
                    result = probe_results.get(target)
                    
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == target
                    ).first()
                    
                    if asset and result and result.is_live:
                        asset.is_live = True
                        asset.http_status = result.status_code
                        asset.http_title = result.title
                        asset.live_url = result.url
                        if result.ip_address:
                            asset.add_ip_address(result.ip_address)
                        asset.last_seen = datetime.utcnow()
                        live_count += 1
                
                db.commit()
                
                result_summary = {
                    'targets': len(targets),
                    'live': live_count,
                    'not_live': len(targets) - live_count
                }
            else:
                # Probe all assets in the organization
                logger.info(f"Probing all assets for org {organization_id}")
                
                if scan:
                    scan.current_step = "Probing all web assets"
                    db.commit()
                
                result_summary = await dns_service.probe_and_update_assets(
                    organization_id=organization_id,
                    limit=limit
                )
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.results = result_summary
                scan.assets_discovered = result_summary.get('live', 0)
                db.commit()
            
            logger.info(f"HTTP probe complete: {result_summary}")
            
        except Exception as e:
            logger.error(f"HTTP probe failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_login_portal_scan(self, job_data: dict):
        """
        Handle login portal detection scan job.
        
        Detects login pages, admin panels, and authentication endpoints.
        Uses subfinder, httpx, waybackurls, and pattern matching.
        
        Flags parent domain/subdomain assets with has_login_portal=True.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        include_subdomains = config.get('include_subdomains', True)
        use_wayback = config.get('use_wayback', True)
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Detecting login portals"
                db.commit()
            
            from app.services.login_portal_service import LoginPortalService
            from urllib.parse import urlparse
            portal_service = LoginPortalService()
            
            total_portals = 0
            all_portals = []
            assets_flagged = 0
            
            # Process each target domain
            for target in targets:
                if self._is_ip_or_cidr(target):
                    continue  # Skip IPs/CIDRs
                
                logger.info(f"Scanning {target} for login portals")
                
                result = await portal_service.detect_login_portals(
                    domain=target,
                    include_subdomains=include_subdomains,
                    use_wayback=use_wayback
                )
                
                portals = result.get("portals", [])
                total_portals += len(portals)
                all_portals.extend(portals)
                
                # Group portals by their host (domain/subdomain)
                portals_by_host = {}
                for portal in portals:
                    url = portal.get("url", "")
                    try:
                        parsed = urlparse(url)
                        host = parsed.netloc.split(":")[0]  # Remove port
                        if host:
                            if host not in portals_by_host:
                                portals_by_host[host] = []
                            portals_by_host[host].append({
                                "url": url,
                                "type": portal.get("portal_type"),
                                "status": portal.get("status_code"),
                                "title": portal.get("title"),
                                "verified": portal.get("verified", False)
                            })
                    except Exception:
                        pass
                
                # Flag parent domain/subdomain assets
                for host, host_portals in portals_by_host.items():
                    # Find the asset for this host
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == host
                    ).first()
                    
                    if asset:
                        asset.has_login_portal = True
                        # Merge with existing portals
                        existing_portals = asset.login_portals or []
                        existing_urls = {p.get("url") for p in existing_portals}
                        for p in host_portals:
                            if p["url"] not in existing_urls:
                                existing_portals.append(p)
                        asset.login_portals = existing_portals
                        asset.last_seen = datetime.utcnow()
                        assets_flagged += 1
                        logger.info(f"Flagged {host} with {len(host_portals)} login portals")
                
                # Also create URL assets for discovered portals (optional - for detailed tracking)
                for portal in portals:
                    existing = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == portal.get("url")
                    ).first()
                    
                    if not existing:
                        asset = Asset(
                            organization_id=organization_id,
                            name=portal.get("url", "")[:255],
                            value=portal.get("url"),
                            asset_type=AssetType.URL,
                            root_domain=target,  # Store the domain this portal was found from
                            is_live=portal.get("verified", False),
                            has_login_portal=True,
                            discovery_source="login_portal_scan",
                            metadata_={
                                "portal_type": portal.get("portal_type"),
                                "status_code": portal.get("status_code"),
                                "title": portal.get("title"),
                                "detected_at": portal.get("detected_at"),
                                "is_login_portal": True,
                                "source_domain": target  # Also store in metadata for reference
                            }
                        )
                        db.add(asset)
                
                db.commit()
                logger.info(f"Found {len(portals)} login portals for {target}, flagged {assets_flagged} assets")
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = total_portals
                scan.results = {
                    'portals_found': total_portals,
                    'assets_flagged': assets_flagged,
                    'domains_scanned': len(targets),
                    'portals': all_portals[:100]  # Limit stored results
                }
                db.commit()
            
            logger.info(f"Login portal scan complete: {total_portals} portals found, {assets_flagged} assets flagged")
            
        except Exception as e:
            logger.error(f"Login portal scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_screenshot_scan(self, job_data: dict):
        """
        Handle screenshot capture scan job.
        
        Captures screenshots of web assets using EyeWitness.
        Screenshots are stored and linked to assets for visual monitoring.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Capturing screenshots"
                db.commit()
            
            from app.services.screenshot_service import _capture_screenshots_async
            
            # If no specific targets, get live assets from the organization
            # Use live_url when available for better screenshot accuracy
            # Include domains, subdomains, AND IP addresses
            if not targets:
                live_assets = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.is_live == True,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS])
                ).limit(config.get('max_hosts', 200)).all()
                
                # Prefer live_url (the actual responding URL) over just the domain/IP
                # This ensures we screenshot the actual endpoint (e.g., /global-protect/login.esp)
                targets = []
                for a in live_assets:
                    if a.live_url:
                        # Use the actual live URL from HTTP probe
                        targets.append(a.live_url)
                    else:
                        # Fallback to https://value
                        targets.append(f"https://{a.value}")
            
            logger.info(f"Starting screenshot capture for {len(targets)} targets")
            
            # Use the async capture function
            result = await _capture_screenshots_async(
                db,
                organization_id=organization_id,
                hosts=targets,
                max_hosts=config.get('max_hosts', 200),
                timeout=config.get('timeout', 30)
            )
            
            screenshots_captured = result.get('screenshots_captured', 0)
            screenshots_failed = result.get('screenshots_failed', 0)
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = screenshots_captured
                scan.results = {
                    'screenshots_captured': screenshots_captured,
                    'screenshots_failed': screenshots_failed,
                    'targets_processed': len(targets),
                    'assets_updated': result.get('assets_updated', 0),
                }
                db.commit()
            
            logger.info(f"Screenshot scan complete: {screenshots_captured} captured, {screenshots_failed} failed")
            
        except Exception as e:
            logger.error(f"Screenshot scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_paramspider_scan(self, job_data: dict):
        """
        Handle ParamSpider parameter discovery scan.
        
        Discovers URL parameters from web archives for vulnerability testing.
        Updates assets with discovered parameters, endpoints, and JS files.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Discovering URL parameters"
                db.commit()
            
            from app.services.paramspider_service import ParamSpiderService
            paramspider = ParamSpiderService()
            
            # If no specific targets, get domains from the organization
            if not targets:
                domain_assets = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                    Asset.is_live == True
                ).limit(config.get('max_domains', 50)).all()
                targets = [a.value for a in domain_assets]
            
            # Limit targets to prevent excessively long scans
            max_targets = config.get('max_domains', 30)
            if len(targets) > max_targets:
                logger.info(f"Limiting ParamSpider scan from {len(targets)} to {max_targets} targets")
                targets = targets[:max_targets]
            
            logger.info(f"Running ParamSpider on {len(targets)} targets (parallel)")
            
            total_urls = 0
            total_params = 0
            total_endpoints = 0
            total_js_files = 0
            assets_updated = 0
            
            # Update progress tracking
            if scan:
                scan.current_step = f"Discovering params from {len(targets)} domains (parallel)"
                db.commit()
            
            # Use parallel processing for faster completion
            results = await paramspider.scan_multiple_domains(
                domains=targets,
                max_concurrent=config.get('max_concurrent', 5),
                level=config.get('level', 'high'),
                timeout=config.get('timeout', 120),  # Reduced from 300 to 120 seconds per target
            )
            
            for result in results:
                try:
                    if result.success:
                        total_urls += len(result.urls)
                        total_params += len(result.parameters)
                        total_endpoints += len(result.endpoints)
                        total_js_files += len(result.js_files)
                        
                        # Update the asset with discovered data
                        asset = db.query(Asset).filter(
                            Asset.organization_id == organization_id,
                            Asset.value == result.domain
                        ).first()
                        
                        if asset:
                            # Merge with existing data
                            existing_endpoints = asset.endpoints or []
                            existing_params = asset.parameters or []
                            existing_js = asset.js_files or []
                            
                            asset.endpoints = list(set(existing_endpoints + result.endpoints[:500]))
                            asset.parameters = list(set(existing_params + result.parameters))
                            asset.js_files = list(set(existing_js + result.js_files[:100]))
                            asset.last_seen = datetime.utcnow()
                            assets_updated += 1
                        
                        logger.info(f"ParamSpider for {result.domain}: {len(result.parameters)} params, {len(result.endpoints)} endpoints")
                    else:
                        logger.warning(f"ParamSpider failed for {result.domain}: {result.error}")
                        
                except Exception as e:
                    logger.warning(f"ParamSpider result processing error: {e}")
                    # Rollback failed transaction to allow subsequent queries
                    try:
                        db.rollback()
                    except Exception:
                        pass
            
            db.commit()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = total_params
                scan.results = {
                    'domains_scanned': len(targets),
                    'total_urls': total_urls,
                    'total_parameters': total_params,
                    'total_endpoints': total_endpoints,
                    'total_js_files': total_js_files,
                    'assets_updated': assets_updated,
                }
                db.commit()
            
            logger.info(f"ParamSpider scan complete: {total_params} params, {total_endpoints} endpoints from {len(targets)} domains")
            
        except Exception as e:
            logger.error(f"ParamSpider scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_waybackurls_scan(self, job_data: dict):
        """
        Handle WaybackURLs historical URL discovery scan.
        
        Fetches historical URLs from Wayback Machine to find:
        - Forgotten endpoints
        - Old config files
        - Sensitive files
        - API endpoints
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Fetching historical URLs"
                db.commit()
            
            from app.services.waybackurls_service import WaybackURLsService
            wayback = WaybackURLsService(db)
            
            # If no specific targets, get domains from the organization
            if not targets:
                domain_assets = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN])
                ).limit(config.get('max_domains', 100)).all()
                targets = [a.value for a in domain_assets]
            
            logger.info(f"Running WaybackURLs on {len(targets)} targets")
            
            # Use the batch fetch
            results = await wayback.fetch_urls_batch(
                domains=targets,
                no_subs=not config.get('include_subdomains', True),
                timeout=config.get('timeout_per_domain', 120),
                max_concurrent=config.get('max_concurrent', 3)
            )
            
            total_urls = 0
            total_interesting = 0
            assets_updated = 0
            
            for result in results:
                if result.success:
                    total_urls += len(result.urls)
                    total_interesting += len(result.interesting_urls)
                    
                    # Update the asset with discovered data
                    asset = db.query(Asset).filter(
                        Asset.organization_id == organization_id,
                        Asset.value == result.domain
                    ).first()
                    
                    if asset:
                        # Store in metadata
                        if not asset.metadata_:
                            asset.metadata_ = {}
                        
                        asset.metadata_['wayback_urls_count'] = len(result.urls)
                        asset.metadata_['wayback_interesting_count'] = len(result.interesting_urls)
                        asset.metadata_['wayback_extensions'] = result.file_extensions
                        asset.metadata_['wayback_last_scan'] = datetime.utcnow().isoformat()
                        
                        # Store unique paths as endpoints
                        existing_endpoints = asset.endpoints or []
                        asset.endpoints = list(set(existing_endpoints + result.unique_paths[:500]))
                        
                        asset.last_seen = datetime.utcnow()
                        assets_updated += 1
            
            db.commit()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = total_interesting
                scan.results = {
                    'domains_scanned': len(targets),
                    'total_urls': total_urls,
                    'interesting_urls': total_interesting,
                    'assets_updated': assets_updated,
                }
                db.commit()
            
            logger.info(f"WaybackURLs scan complete: {total_urls} URLs, {total_interesting} interesting from {len(targets)} domains")
            
        except Exception as e:
            logger.error(f"WaybackURLs scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_katana_scan(self, job_data: dict):
        """
        Handle Katana deep web crawling scan.
        
        Actively crawls websites to discover:
        - All reachable URLs and endpoints
        - JavaScript files (for secret scanning)
        - URL parameters (for injection testing)
        - Form actions
        - API endpoints
        
        Results are stored directly on each asset.
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Deep crawling with Katana"
                db.commit()
            
            from app.services.katana_service import KatanaService
            katana = KatanaService()
            
            if not katana.is_available():
                raise Exception("Katana not installed. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            
            # If no specific targets, get live domains from the organization
            # Use live_url when available (from HTTP probe), otherwise fall back to domain
            if not targets:
                live_assets = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                    Asset.is_live == True
                ).limit(config.get('max_targets', 50)).all()
                # Prefer live_url (the actual responding URL) over just the domain name
                targets = [a.live_url or f"https://{a.value}" for a in live_assets]
            
            # Limit targets to prevent excessively long scans
            max_targets = config.get('max_targets', 20)  # Reduced from 50
            if len(targets) > max_targets:
                logger.info(f"Limiting Katana scan from {len(targets)} to {max_targets} targets")
                targets = targets[:max_targets]
            
            logger.info(f"Running Katana on {len(targets)} targets with depth={config.get('depth', 3)}")
            
            total_urls = 0
            total_endpoints = 0
            total_params = 0
            total_js = 0
            assets_updated = 0
            
            # Use parallel processing for faster completion
            # Default: 3 concurrent crawls, 3 minutes timeout per target
            per_target_timeout = config.get('timeout', 180)  # Reduced from 600 to 180 seconds
            max_concurrent = config.get('max_concurrent', 3)
            
            # Update progress tracking
            if scan:
                scan.current_step = f"Deep crawling {len(targets)} targets (parallel)"
                db.commit()
            
            # Use crawl_multiple for parallel processing
            results = await katana.crawl_multiple(
                targets=targets,
                max_concurrent=max_concurrent,
                depth=config.get('depth', 3),  # Reduced default depth from 5 to 3
                js_crawl=config.get('js_crawl', True),
                form_extraction=config.get('form_extraction', True),
                timeout=per_target_timeout,
                rate_limit=config.get('rate_limit', DEFAULT_NUCLEI_RATE_LIMIT),
                concurrency=config.get('concurrency', 10),
            )
            
            # Process results and update assets
            for result in results:
                try:
                    if result.success:
                        total_urls += len(result.urls)
                        total_endpoints += len(result.endpoints)
                        total_params += len(result.parameters)
                        total_js += len(result.js_files)
                        
                        # Extract target domain from result
                        target = result.target
                        if target.startswith(('http://', 'https://')):
                            from urllib.parse import urlparse
                            target = urlparse(target).netloc
                        
                        # Update the asset with discovered data
                        asset = db.query(Asset).filter(
                            Asset.organization_id == organization_id,
                            Asset.value == target
                        ).first()
                        
                        if asset:
                            # Merge with existing data (deduplicate)
                            existing_endpoints = set(asset.endpoints or [])
                            existing_params = set(asset.parameters or [])
                            existing_js = set(asset.js_files or [])
                            
                            # Add new discoveries
                            existing_endpoints.update(result.endpoints)
                            existing_params.update(result.parameters)
                            existing_js.update(result.js_files)
                            
                            # Update asset (limit to prevent huge JSON)
                            asset.endpoints = sorted(list(existing_endpoints))[:1000]
                            asset.parameters = sorted(list(existing_params))[:500]
                            asset.js_files = sorted(list(existing_js))[:500]
                            
                            # Store additional metadata
                            if not asset.metadata_:
                                asset.metadata_ = {}
                            asset.metadata_['katana_last_scan'] = datetime.utcnow().isoformat()
                            asset.metadata_['katana_urls_found'] = len(result.urls)
                            asset.metadata_['katana_api_endpoints'] = result.api_endpoints[:50]
                            
                            asset.last_seen = datetime.utcnow()
                            assets_updated += 1
                        
                        logger.info(
                            f"Katana crawl of {result.target}: {len(result.endpoints)} endpoints, "
                            f"{len(result.parameters)} params, {len(result.js_files)} JS files"
                        )
                    else:
                        logger.warning(f"Katana failed for {result.target}: {result.error}")
                        
                except Exception as e:
                    logger.warning(f"Katana result processing error: {e}")
                    # Rollback failed transaction to allow subsequent queries
                    try:
                        db.rollback()
                    except Exception:
                        pass
            
            db.commit()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.assets_discovered = total_endpoints
                scan.results = {
                    'targets_crawled': len(targets),
                    'total_urls': total_urls,
                    'total_endpoints': total_endpoints,
                    'total_parameters': total_params,
                    'total_js_files': total_js,
                    'assets_updated': assets_updated,
                }
                db.commit()
            
            logger.info(
                f"Katana scan complete: {total_endpoints} endpoints, "
                f"{total_params} params, {total_js} JS files from {len(targets)} targets"
            )
            
        except Exception as e:
            logger.error(f"Katana scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_cleanup(self, job_data: dict):
        """
        Handle system cleanup and maintenance task.
        
        Cleans up:
        - Old scan result files
        - Temporary files from scanning tools
        - Old/orphaned screenshots
        - Failed scan records
        """
        scan_id = job_data.get('scan_id')
        config = job_data.get('config', {})
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = "Running system cleanup"
                db.commit()
            
            from app.services.cleanup_service import CleanupService
            
            cleanup = CleanupService(db)
            
            # Build retention config
            retention_days = {
                'screenshots': config.get('screenshots_retention_days', 90),
                'scan_results': config.get('scan_files_retention_days', 30),
                'temp_files': config.get('temp_files_retention_days', 1),
                'failed_scans': config.get('failed_scans_retention_days', 14),
            }
            
            dry_run = config.get('dry_run', False)
            
            logger.info(f"Running cleanup with retention: {retention_days}, dry_run={dry_run}")
            
            # Run full cleanup
            stats = await cleanup.run_full_cleanup(
                retention_days=retention_days,
                dry_run=dry_run
            )
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.current_step = None
                scan.results = {
                    'files_deleted': stats.get('files_deleted', 0),
                    'bytes_freed': stats.get('bytes_freed', 0),
                    'mb_freed': round(stats.get('bytes_freed', 0) / 1024 / 1024, 2),
                    'records_cleaned': stats.get('records_cleaned', 0),
                    'errors': stats.get('errors', [])[:10],  # Limit errors in results
                    'dry_run': dry_run,
                }
                db.commit()
            
            logger.info(
                f"Cleanup complete: {stats.get('files_deleted', 0)} files deleted, "
                f"{stats.get('bytes_freed', 0) / 1024 / 1024:.2f} MB freed"
            )
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def handle_technology_scan(self, job_data: dict):
        """
        Handle technology detection scan job.
        
        Detects web technologies on domains/subdomains using:
        - Wappalyzer (local fingerprinting - fast, 150+ technologies)
        - WhatRuns API (comprehensive - CMS, JS libs, fonts, analytics, security)
        
        Results are stored:
        - In the technologies table
        - Associated with assets via asset_technologies
        - As tech:xxx labels for filtering
        
        Config options:
        - source: "wappalyzer", "whatruns", or "both" (default: "both")
        - max_hosts: Maximum hosts to scan (default: 500)
        - only_live: Only scan assets marked as is_live (default: false)
        """
        scan_id = job_data.get('scan_id')
        organization_id = job_data.get('organization_id')
        targets = job_data.get('targets', [])
        config = job_data.get('config', {})
        
        source = config.get('source', 'both')  # wappalyzer, whatruns, or both
        max_hosts = config.get('max_hosts', 500)
        only_live = config.get('only_live', False)
        
        db = self.get_db_session()
        if not db:
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                scan.current_step = f"Detecting technologies using {source}"
                db.commit()
            
            from app.services.technology_scan_service import run_technology_scan_for_hosts
            
            # If no specific targets, get domains/subdomains/IPs from the organization
            # Include IP addresses that have live_url (detected via HTTP probe)
            if not targets:
                query = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS])
                )
                
                if only_live:
                    query = query.filter(Asset.is_live == True)
                else:
                    # For IP addresses, only include if they have a live_url (HTTP responds)
                    # This prevents scanning IPs that don't have web services
                    from sqlalchemy import or_
                    query = query.filter(
                        or_(
                            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
                            Asset.live_url.isnot(None)  # IP assets must have live_url
                        )
                    )
                
                assets = query.limit(max_hosts).all()
                targets = [a.value for a in assets]
            
            if not targets:
                logger.warning(f"No targets found for technology scan {scan_id}")
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.results = {
                        'message': 'No domains/subdomains/IPs to scan',
                        'targets': 0
                    }
                    db.commit()
                return
            
            logger.info(f"Starting technology scan for {len(targets)} targets with source={source}")
            
            # Close db before running the scan (it creates its own session)
            db.close()
            db = None
            
            # Run technology scan
            result = run_technology_scan_for_hosts(
                organization_id=organization_id,
                hosts=targets,
                max_hosts=max_hosts,
                source=source
            )
            
            # Reopen db for final update
            db = self.get_db_session()
            
            # Update scan record
            if db:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    scan.current_step = None
                    scan.technologies_found = result.get('technologies_found', 0)
                    scan.assets_discovered = result.get('hosts_scanned', 0)
                    scan.results = {
                        'total_hosts': result.get('total_hosts', 0),
                        'hosts_scanned': result.get('hosts_scanned', 0),
                        'technologies_found': result.get('technologies_found', 0),
                        'source': source,
                    }
                    db.commit()
            
            logger.info(
                f"Technology scan complete: {result.get('technologies_found', 0)} technologies "
                f"on {result.get('hosts_scanned', 0)}/{result.get('total_hosts', 0)} hosts"
            )
            
        except Exception as e:
            logger.error(f"Technology scan failed: {e}", exc_info=True)
            if db and scan_id:
                try:
                    db.rollback()
                    scan = db.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error_message = str(e)[:500]
                        scan.completed_at = datetime.utcnow()
                        db.commit()
                except Exception as db_error:
                    logger.error(f"Failed to update scan {scan_id} status: {db_error}")
                    try:
                        db.rollback()
                    except Exception:
                        pass
            raise
        finally:
            if db:
                db.close()
    
    async def _process_with_semaphore(self, message: dict):
        """Process a message with semaphore limiting."""
        scan_id = None
        try:
            body = json.loads(message.get('Body', '{}'))
            scan_id = body.get('scan_id')

            # Note: scan_id is already added to active_scans in the main loop
            # to prevent race conditions during polling

            async with self.scan_semaphore:
                await self.process_message(message)

        except Exception as e:
            logger.error(f"Error processing scan {scan_id}: {e}", exc_info=True)
        finally:
            # Remove from active scans when complete
            if scan_id:
                active_scans.discard(scan_id)
                logger.info(f"Scan {scan_id} removed from active scans")
    
    async def run(self):
        """
        Main worker loop with concurrent scan processing.
        
        Features:
        - Runs up to MAX_CONCURRENT_SCANS in parallel
        - Prioritizes ad-hoc scans over scheduled scans
        - Graceful shutdown with active scan tracking
        - Periodic recovery of stale RUNNING scans
        """
        logger.info(f"Starting scanner worker (max_concurrent={MAX_CONCURRENT_SCANS})...")
        
        pending_tasks = set()
        last_stale_check = datetime.utcnow()
        STALE_CHECK_INTERVAL = 300  # Check for stale scans every 5 minutes
        
        # Initial stale scan recovery on startup
        try:
            recovered = await self.recover_stale_scans()
            if recovered > 0:
                logger.info(f"Startup: recovered {recovered} stale scans")
        except Exception as e:
            logger.error(f"Error during startup stale scan recovery: {e}")
        
        while not shutdown_requested:
            try:
                # Periodic stale scan recovery
                if (datetime.utcnow() - last_stale_check).total_seconds() > STALE_CHECK_INTERVAL:
                    try:
                        recovered = await self.recover_stale_scans()
                        if recovered > 0:
                            logger.info(f"Periodic recovery: recovered {recovered} stale scans")
                    except Exception as e:
                        logger.error(f"Error during periodic stale scan recovery: {e}")
                    last_stale_check = datetime.utcnow()
                
                messages = await self.poll_for_jobs()
                
                # Create tasks for each message
                for message in messages:
                    if shutdown_requested:
                        break
                    
                    # Add scan to active_scans BEFORE creating task to prevent race condition
                    try:
                        body = json.loads(message.get('Body', '{}'))
                        scan_id = body.get('scan_id')
                        if scan_id:
                            active_scans.add(scan_id)
                            logger.info(f"Starting processing for scan {scan_id}")
                    except Exception:
                        pass
                    
                    # Create task for concurrent processing
                    task = asyncio.create_task(self._process_with_semaphore(message))
                    pending_tasks.add(task)
                    task.add_done_callback(pending_tasks.discard)
                
                # Brief pause to let async tasks start processing
                if messages:
                    await asyncio.sleep(0.5)
                
                # Clean up completed tasks
                done_tasks = [t for t in pending_tasks if t.done()]
                for task in done_tasks:
                    pending_tasks.discard(task)
                    
            except Exception as e:
                logger.error(f"Error in worker loop: {e}", exc_info=True)
                await asyncio.sleep(5)  # Back off on error
        
        # Wait for active scans to complete on shutdown
        if pending_tasks:
            logger.info(f"Waiting for {len(pending_tasks)} active scans to complete...")
            await asyncio.gather(*pending_tasks, return_exceptions=True)
        
        logger.info("Scanner worker shutting down...")


async def main():
    """Main entry point."""
    # Register signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    worker = ScannerWorker()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())













