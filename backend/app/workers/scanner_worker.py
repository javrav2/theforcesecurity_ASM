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
from app.models.asset import Asset
from app.services.nuclei_service import NucleiService
from app.services.nuclei_findings_service import NucleiFindingsService
from app.services.port_scanner_service import PortScannerService, ScannerType
from app.services.port_findings_service import PortFindingsService
from app.services.discovery_service import DiscoveryService
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

# Global shutdown flag
shutdown_requested = False


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
    Scanner worker that processes scan jobs from SQS.
    
    Job Types:
    - NUCLEI_SCAN: Run Nuclei vulnerability scan
    - PORT_SCAN: Run port scan (naabu/nmap/masscan)
    - DISCOVERY: Full asset discovery
    - SUBDOMAIN_ENUM: Subdomain enumeration
    """
    
    def __init__(self):
        """Initialize the scanner worker."""
        # Database connection
        if DATABASE_URL:
            self.engine = create_engine(DATABASE_URL)
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
        
        logger.info("Scanner worker initialized")
    
    def get_discovery_service(self, db):
        """Get or create discovery service with db session."""
        return DiscoveryService(db)
    
    def get_db_session(self):
        """Get a database session."""
        if self.SessionLocal:
            return self.SessionLocal()
        return None
    
    async def poll_for_jobs(self):
        """Poll for scan jobs from SQS or database."""
        # If SQS is configured, use it
        if self.sqs and self.queue_url:
            try:
                response = self.sqs.receive_message(
                    QueueUrl=self.queue_url,
                    MaxNumberOfMessages=1,
                    WaitTimeSeconds=POLL_INTERVAL,
                    VisibilityTimeout=VISIBILITY_TIMEOUT,
                    MessageAttributeNames=['All']
                )
                return response.get('Messages', [])
            except ClientError as e:
                logger.error(f"Error polling SQS: {e}")
                return []
        
        # Otherwise, poll database for pending scans
        return await self.poll_database_for_jobs()
    
    async def poll_database_for_jobs(self):
        """Poll database for pending scans (local development mode)."""
        db = self.get_db_session()
        if not db:
            return []
        
        try:
            # Find pending scans
            pending_scan = db.query(Scan).filter(
                Scan.status == ScanStatus.PENDING
            ).order_by(Scan.created_at.asc()).first()
            
            if not pending_scan:
                await asyncio.sleep(POLL_INTERVAL)
                return []
            
            # Convert to message format
            job_type_map = {
                ScanType.VULNERABILITY: 'NUCLEI_SCAN',
                ScanType.PORT_SCAN: 'PORT_SCAN',
                ScanType.DISCOVERY: 'DISCOVERY',
                ScanType.SUBDOMAIN_ENUM: 'SUBDOMAIN_ENUM',
            }
            
            job_type = job_type_map.get(pending_scan.scan_type, 'NUCLEI_SCAN')
            config = pending_scan.config or {}
            
            # Build job data with config values extracted
            job_data = {
                'job_type': job_type,
                'scan_id': pending_scan.id,
                'organization_id': pending_scan.organization_id,
                'targets': pending_scan.targets or [],
                'config': config,
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
            
            logger.info(f"Found pending scan {pending_scan.id} ({pending_scan.scan_type.value})")
            return [message]
            
        except Exception as e:
            logger.error(f"Error polling database: {e}")
            return []
        finally:
            db.close()
    
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
            
            # Route to appropriate handler
            if job_type == 'NUCLEI_SCAN':
                await self.handle_nuclei_scan(body)
            elif job_type == 'PORT_SCAN':
                await self.handle_port_scan(body)
            elif job_type == 'DISCOVERY':
                await self.handle_discovery(body)
            elif job_type == 'SUBDOMAIN_ENUM':
                await self.handle_subdomain_enum(body)
            else:
                logger.warning(f"Unknown job type: {job_type}")
            
            # Delete message from SQS queue (only if not a DB message)
            if not is_db_message and self.sqs and self.queue_url:
                self.sqs.delete_message(
                    QueueUrl=self.queue_url,
                    ReceiptHandle=receipt_handle
                )
            
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
            logger.error("No database connection")
            return
        
        try:
            # Update scan status
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.RUNNING
                scan.started_at = datetime.utcnow()
                db.commit()
            
            # Run Nuclei scan
            logger.info(f"Starting Nuclei scan on {len(targets)} targets with severity: {severity}")
            logger.debug(f"Nuclei targets: {targets[:5]}{'...' if len(targets) > 5 else ''}")
            
            result = await self.nuclei_service.scan_targets(
                targets=targets,
                severity=severity,
                tags=tags if tags else None,
                exclude_tags=exclude_tags if exclude_tags else None
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
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.vulnerabilities_found = import_summary['findings_created']
                scan.results = {
                    'summary': result.summary,
                    'import_summary': import_summary,
                    'targets_original': result.targets_original,
                    'targets_expanded': result.targets_expanded,
                    'targets_scanned': result.targets_scanned,
                    'live_hosts': len(unique_hosts),
                    'findings_count': import_summary['findings_created'],
                }
                db.commit()
            
            logger.info(
                f"Nuclei scan complete: {import_summary['findings_created']} findings, "
                f"{len(import_summary.get('cves_found', []))} CVEs, {len(unique_hosts)} live hosts"
            )
            
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}", exc_info=True)
            if db and scan_id:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    scan.completed_at = datetime.utcnow()
                    db.commit()
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
        rate = config.get('rate', 500)  # Lower rate for reliability
        timeout = config.get('timeout', 30)  # Longer timeout
        retries = config.get('retries', 2)  # Retry on failure
        chunk_size = config.get('chunk_size', 64)  # Chunk large scans
        
        # IMPORTANT: Set default ports if not specified (don't scan all 65535!)
        # This prevents accidental 33+ minute scans
        if not ports or ports == "-":
            # Default to top 100 common ports for reasonable scan time
            ports = config.get('ports') or "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1723,3306,3389,5432,5900,8080,8443"
            logger.info(f"No ports specified, defaulting to top common ports")
        
        # Log scan estimate
        from app.services.port_scanner_service import PortScannerService
        scanner_svc = PortScannerService()
        num_ports = scanner_svc._count_ports(ports) if hasattr(scanner_svc, '_count_ports') else 0
        num_hosts = scanner_svc._estimate_hosts(targets) if hasattr(scanner_svc, '_estimate_hosts') else len(targets)
        logger.info(f"Port scan: {num_hosts} hosts × {num_ports} ports = ~{num_hosts * num_ports:,} probes")
        
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
            
            # Map scanner type
            scanner_type_map = {
                'naabu': ScannerType.NAABU,
                'masscan': ScannerType.MASSCAN,
                'nmap': ScannerType.NMAP
            }
            selected_scanner = scanner_type_map.get(scanner, ScannerType.NAABU)
            
            # Run port scan with reliability options
            scan_kwargs = {
                "targets": targets, 
                "ports": ports,
                "rate": rate,
                "timeout": timeout,
            }
            
            # Add scanner-specific options
            if selected_scanner == ScannerType.NAABU:
                scan_kwargs["retries"] = retries
                scan_kwargs["chunk_size"] = chunk_size
            elif selected_scanner == ScannerType.NMAP and service_detection:
                scan_kwargs["service_detection"] = service_detection
            
            logger.info(f"Starting port scan with rate={rate}, timeout={timeout}, retries={retries}")
            
            result = await self.port_scanner_service.scan(
                scanner=selected_scanner,
                **scan_kwargs
            )
            
            # Import results
            import_summary = self.port_scanner_service.import_results_to_assets(
                db=db,
                scan_result=result,
                organization_id=organization_id,
                create_assets=True
            )
            
            # Generate findings from port scan results
            findings_service = PortFindingsService()
            findings_summary = findings_service.create_findings_from_scan(
                db=db,
                organization_id=organization_id,
                scan_id=scan_id
            )
            
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
                db.commit()
            
            logger.info(
                f"Port scan complete: {len(result.ports_found)} ports, "
                f"{findings_summary.get('findings_created', 0)} findings"
            )
            
        except Exception as e:
            logger.error(f"Port scan failed: {e}", exc_info=True)
            if db and scan_id:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    scan.completed_at = datetime.utcnow()
                    db.commit()
            raise
        finally:
            if db:
                db.close()
    
    async def handle_discovery(self, job_data: dict):
        """Handle full asset discovery job."""
        scan_id = job_data.get('scan_id')
        domain = job_data.get('domain')
        organization_id = job_data.get('organization_id')
        
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
            
            # Run discovery
            discovery_service = self.get_discovery_service(db)
            result = await discovery_service.full_discovery(
                domain=domain,
                organization_id=organization_id,
                enable_subdomain_enum=True,
                enable_dns_enum=True,
                enable_http_probe=True,
                enable_tech_detection=True
            )
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.results = {
                    'assets_created': result.get('assets_created', 0),
                    'subdomains_found': result.get('subdomains_found', 0),
                    'technologies_detected': result.get('technologies_detected', 0)
                }
                db.commit()
            
            logger.info(f"Discovery complete: {result.get('assets_created', 0)} assets")
            
        except Exception as e:
            logger.error(f"Discovery failed: {e}", exc_info=True)
            if db and scan_id:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    scan.completed_at = datetime.utcnow()
                    db.commit()
            raise
        finally:
            if db:
                db.close()
    
    async def handle_subdomain_enum(self, job_data: dict):
        """Handle subdomain enumeration job."""
        scan_id = job_data.get('scan_id')
        domain = job_data.get('domain')
        organization_id = job_data.get('organization_id')
        
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
            
            result = await subdomain_service.enumerate_subdomains(domain)
            
            # Create assets for discovered subdomains
            from app.models.asset import AssetType
            assets_created = 0
            
            for subdomain in result.subdomains:
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
                        discovery_source="subfinder"
                    )
                    db.add(asset)
                    assets_created += 1
            
            db.commit()
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.results = {
                    'subdomains_found': len(result.subdomains),
                    'assets_created': assets_created,
                    'sources': result.sources
                }
                db.commit()
            
            logger.info(f"Subdomain enum complete: {len(result.subdomains)} found, {assets_created} created")
            
        except Exception as e:
            logger.error(f"Subdomain enum failed: {e}", exc_info=True)
            if db and scan_id:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    scan.completed_at = datetime.utcnow()
                    db.commit()
            raise
        finally:
            if db:
                db.close()
    
    async def run(self):
        """Main worker loop."""
        logger.info("Starting scanner worker...")
        
        while not shutdown_requested:
            try:
                messages = await self.poll_for_jobs()
                
                for message in messages:
                    if shutdown_requested:
                        break
                    await self.process_message(message)
                    
            except Exception as e:
                logger.error(f"Error in worker loop: {e}", exc_info=True)
                await asyncio.sleep(5)  # Back off on error
        
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













