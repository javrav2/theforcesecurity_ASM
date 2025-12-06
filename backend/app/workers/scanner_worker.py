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
        
        # Initialize services
        self.nuclei_service = NucleiService()
        self.port_scanner_service = PortScannerService()
        self.discovery_service = DiscoveryService()
        
        logger.info("Scanner worker initialized")
    
    def get_db_session(self):
        """Get a database session."""
        if self.SessionLocal:
            return self.SessionLocal()
        return None
    
    async def poll_for_jobs(self):
        """Poll SQS for scan jobs."""
        if not self.sqs or not self.queue_url:
            logger.error("SQS not configured")
            return []
        
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
    
    async def process_message(self, message: dict):
        """Process a single SQS message."""
        message_id = message.get('MessageId')
        receipt_handle = message.get('ReceiptHandle')
        
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
            
            # Delete message from queue
            self.sqs.delete_message(
                QueueUrl=self.queue_url,
                ReceiptHandle=receipt_handle
            )
            
            logger.info(f"Job {message_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Error processing message {message_id}: {e}", exc_info=True)
            # Message will return to queue after visibility timeout
    
    async def handle_nuclei_scan(self, job_data: dict):
        """Handle Nuclei vulnerability scan job."""
        scan_id = job_data.get('scan_id')
        targets = job_data.get('targets', [])
        organization_id = job_data.get('organization_id')
        severity = job_data.get('severity', ['critical', 'high'])
        tags = job_data.get('tags', [])
        exclude_tags = job_data.get('exclude_tags', [])
        
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
            result = await self.nuclei_service.scan_targets(
                targets=targets,
                severity=severity,
                tags=tags if tags else None,
                exclude_tags=exclude_tags if exclude_tags else None
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
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.vulnerabilities_found = import_summary['findings_created']
                scan.results = {
                    'summary': result.summary,
                    'import_summary': import_summary
                }
                db.commit()
            
            logger.info(
                f"Nuclei scan complete: {import_summary['findings_created']} findings, "
                f"{len(import_summary.get('cves_found', []))} CVEs"
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
            scanner_type = scanner_type_map.get(scanner, ScannerType.NAABU)
            
            # Run port scan
            result = await self.port_scanner_service.run_scan(
                scanner_type=scanner_type,
                targets=targets,
                ports=ports,
                service_detection=service_detection
            )
            
            # Import results
            import_summary = self.port_scanner_service.import_results_to_assets(
                db=db,
                scan_result=result,
                organization_id=organization_id,
                create_assets=True
            )
            
            # Generate findings
            findings_service = PortFindingsService(db)
            findings_summary = await findings_service.generate_findings_for_organization(organization_id)
            
            # Update scan record
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.results = {
                    'ports_found': result.ports_found,
                    'import_summary': import_summary,
                    'findings_summary': findings_summary
                }
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
            result = await self.discovery_service.full_discovery(
                domain=domain,
                organization_id=organization_id,
                db=db,
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



