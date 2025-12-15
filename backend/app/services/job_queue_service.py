"""
Job Queue Service for AWS SQS integration.

Provides methods to submit scan jobs to SQS for async processing by scanner workers.
Falls back to synchronous execution if SQS is not configured.
"""

import json
import logging
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


class JobType(str, Enum):
    """Types of scan jobs."""
    NUCLEI_SCAN = "NUCLEI_SCAN"
    PORT_SCAN = "PORT_SCAN"
    DISCOVERY = "DISCOVERY"
    SUBDOMAIN_ENUM = "SUBDOMAIN_ENUM"
    TECHNOLOGY_SCAN = "TECHNOLOGY_SCAN"
    WEB_CRAWL = "WEB_CRAWL"


class JobPriority(str, Enum):
    """Job priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class JobQueueService:
    """
    Service for managing scan job queues.
    
    Uses AWS SQS for distributed job processing in production,
    or falls back to synchronous execution for local development.
    """
    
    def __init__(self):
        """Initialize the job queue service."""
        self.queue_url = os.getenv("SQS_QUEUE_URL")
        self.aws_region = os.getenv("AWS_REGION", "us-east-1")
        self.sqs = None
        
        if self.queue_url:
            try:
                self.sqs = boto3.client('sqs', region_name=self.aws_region)
                logger.info(f"SQS client initialized for queue: {self.queue_url}")
            except NoCredentialsError:
                logger.warning("AWS credentials not found, SQS disabled")
        else:
            logger.info("SQS_QUEUE_URL not set, running in synchronous mode")
    
    @property
    def is_async_enabled(self) -> bool:
        """Check if async job processing is enabled."""
        return self.sqs is not None and self.queue_url is not None
    
    def submit_job(
        self,
        job_type: JobType,
        scan_id: int,
        organization_id: int,
        priority: JobPriority = JobPriority.NORMAL,
        **job_params
    ) -> Dict[str, Any]:
        """
        Submit a scan job to the queue.
        
        Args:
            job_type: Type of scan to perform
            scan_id: Database scan record ID
            organization_id: Organization ID
            priority: Job priority
            **job_params: Additional job parameters
            
        Returns:
            Dict with job submission result
        """
        job_data = {
            "job_type": job_type.value,
            "scan_id": scan_id,
            "organization_id": organization_id,
            "priority": priority.value,
            "submitted_at": datetime.utcnow().isoformat(),
            **job_params
        }
        
        if not self.is_async_enabled:
            logger.warning(f"SQS not enabled, job {scan_id} will need synchronous execution")
            return {
                "success": False,
                "message": "Async processing not available",
                "job_data": job_data,
                "async": False
            }
        
        try:
            # Set delay based on priority
            delay_seconds = {
                JobPriority.CRITICAL: 0,
                JobPriority.HIGH: 0,
                JobPriority.NORMAL: 0,
                JobPriority.LOW: 60
            }.get(priority, 0)
            
            response = self.sqs.send_message(
                QueueUrl=self.queue_url,
                MessageBody=json.dumps(job_data),
                DelaySeconds=delay_seconds,
                MessageAttributes={
                    'JobType': {
                        'DataType': 'String',
                        'StringValue': job_type.value
                    },
                    'Priority': {
                        'DataType': 'String',
                        'StringValue': priority.value
                    },
                    'OrganizationId': {
                        'DataType': 'Number',
                        'StringValue': str(organization_id)
                    }
                }
            )
            
            logger.info(f"Job submitted: {response['MessageId']} (type={job_type.value}, scan_id={scan_id})")
            
            return {
                "success": True,
                "message_id": response['MessageId'],
                "scan_id": scan_id,
                "job_type": job_type.value,
                "async": True
            }
            
        except ClientError as e:
            logger.error(f"Failed to submit job: {e}")
            return {
                "success": False,
                "error": str(e),
                "job_data": job_data,
                "async": False
            }
    
    def submit_nuclei_scan(
        self,
        scan_id: int,
        organization_id: int,
        targets: List[str],
        severity: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        exclude_tags: Optional[List[str]] = None,
        profile_id: Optional[int] = None,
        priority: JobPriority = JobPriority.NORMAL
    ) -> Dict[str, Any]:
        """Submit a Nuclei vulnerability scan job."""
        return self.submit_job(
            job_type=JobType.NUCLEI_SCAN,
            scan_id=scan_id,
            organization_id=organization_id,
            priority=priority,
            targets=targets,
            severity=severity or ["critical", "high"],
            tags=tags or [],
            exclude_tags=exclude_tags or [],
            profile_id=profile_id
        )
    
    def submit_port_scan(
        self,
        scan_id: int,
        organization_id: int,
        targets: List[str],
        scanner: str = "naabu",
        ports: Optional[str] = None,
        service_detection: bool = True,
        priority: JobPriority = JobPriority.NORMAL
    ) -> Dict[str, Any]:
        """Submit a port scan job."""
        return self.submit_job(
            job_type=JobType.PORT_SCAN,
            scan_id=scan_id,
            organization_id=organization_id,
            priority=priority,
            targets=targets,
            scanner=scanner,
            ports=ports,
            service_detection=service_detection
        )
    
    def submit_discovery(
        self,
        scan_id: int,
        organization_id: int,
        domain: str,
        enable_subdomain_enum: bool = True,
        enable_dns_enum: bool = True,
        enable_http_probe: bool = True,
        enable_tech_detection: bool = True,
        priority: JobPriority = JobPriority.NORMAL
    ) -> Dict[str, Any]:
        """Submit a full discovery job."""
        return self.submit_job(
            job_type=JobType.DISCOVERY,
            scan_id=scan_id,
            organization_id=organization_id,
            priority=priority,
            domain=domain,
            enable_subdomain_enum=enable_subdomain_enum,
            enable_dns_enum=enable_dns_enum,
            enable_http_probe=enable_http_probe,
            enable_tech_detection=enable_tech_detection
        )
    
    def submit_subdomain_enum(
        self,
        scan_id: int,
        organization_id: int,
        domain: str,
        recursive: bool = False,
        priority: JobPriority = JobPriority.NORMAL
    ) -> Dict[str, Any]:
        """Submit a subdomain enumeration job."""
        return self.submit_job(
            job_type=JobType.SUBDOMAIN_ENUM,
            scan_id=scan_id,
            organization_id=organization_id,
            priority=priority,
            domain=domain,
            recursive=recursive
        )
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        if not self.is_async_enabled:
            return {
                "enabled": False,
                "message": "SQS not configured"
            }
        
        try:
            response = self.sqs.get_queue_attributes(
                QueueUrl=self.queue_url,
                AttributeNames=[
                    'ApproximateNumberOfMessages',
                    'ApproximateNumberOfMessagesNotVisible',
                    'ApproximateNumberOfMessagesDelayed'
                ]
            )
            
            attrs = response.get('Attributes', {})
            
            return {
                "enabled": True,
                "queue_url": self.queue_url,
                "messages_available": int(attrs.get('ApproximateNumberOfMessages', 0)),
                "messages_in_flight": int(attrs.get('ApproximateNumberOfMessagesNotVisible', 0)),
                "messages_delayed": int(attrs.get('ApproximateNumberOfMessagesDelayed', 0))
            }
            
        except ClientError as e:
            logger.error(f"Failed to get queue stats: {e}")
            return {
                "enabled": True,
                "error": str(e)
            }


# Global instance
job_queue = JobQueueService()













