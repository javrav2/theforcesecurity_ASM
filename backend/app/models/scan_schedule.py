"""Scan Schedule model for continuous monitoring."""

import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class ScheduleFrequency(str, enum.Enum):
    """Frequency for scheduled scans."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


class ScanSchedule(Base):
    """Model for scheduling automated scans."""
    
    __tablename__ = "scan_schedules"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    # Organization
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False, index=True)
    organization = relationship("Organization", backref="scan_schedules")
    
    # Scan configuration
    scan_type = Column(String(50), nullable=False)  # nuclei, port_scan, discovery, masscan
    targets = Column(JSON, default=list)  # Static list of targets
    label_ids = Column(JSON, default=list)  # Labels to use for dynamic targeting
    match_all_labels = Column(Boolean, default=False)
    config = Column(JSON, default=dict)  # Additional scan configuration
    
    # Schedule settings
    frequency = Column(Enum(ScheduleFrequency), default=ScheduleFrequency.DAILY)
    cron_expression = Column(String(100), nullable=True)  # For custom schedules
    run_at_hour = Column(Integer, default=2)  # Hour of day (0-23) for daily/weekly/monthly
    run_on_day = Column(Integer, nullable=True)  # Day of week (0-6) for weekly, day of month (1-31) for monthly
    timezone = Column(String(50), default="UTC")
    
    # State
    is_enabled = Column(Boolean, default=True, index=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    last_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    run_count = Column(Integer, default=0)
    
    # Error tracking
    consecutive_failures = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    
    # Notifications
    notify_on_completion = Column(Boolean, default=False)
    notify_on_findings = Column(Boolean, default=True)
    notification_emails = Column(JSON, default=list)
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by = Column(String(100), nullable=True)
    
    def __repr__(self):
        return f"<ScanSchedule(id={self.id}, name='{self.name}', freq={self.frequency.value})>"
    
    def calculate_next_run(self):
        """Calculate the next run time based on frequency."""
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        
        if self.frequency == ScheduleFrequency.HOURLY:
            next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        elif self.frequency == ScheduleFrequency.DAILY:
            next_run = now.replace(hour=self.run_at_hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
        elif self.frequency == ScheduleFrequency.WEEKLY:
            # Find next occurrence of the target day
            days_ahead = (self.run_on_day or 0) - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            next_run = now.replace(hour=self.run_at_hour, minute=0, second=0, microsecond=0) + timedelta(days=days_ahead)
        elif self.frequency == ScheduleFrequency.MONTHLY:
            # Next month on the specified day
            next_run = now.replace(day=min(self.run_on_day or 1, 28), hour=self.run_at_hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                if now.month == 12:
                    next_run = next_run.replace(year=now.year + 1, month=1)
                else:
                    next_run = next_run.replace(month=now.month + 1)
        else:
            # Custom - calculate from cron
            next_run = now + timedelta(hours=1)  # Fallback
        
        return next_run


# Critical ports that should be monitored for exposure
CRITICAL_PORTS = {
    # Remote Access - High value targets
    "remote_access": [22, 23, 3389, 5900, 5901, 5902, 5903, 512, 513, 514],
    # Databases - Data exposure risk
    "databases": [3306, 5432, 1433, 1434, 1521, 27017, 27018, 6379, 9200, 9300, 5984, 11211],
    # File Sharing - Ransomware vectors
    "file_sharing": [21, 69, 445, 139, 2049],
    # Container/Orchestration - Host takeover
    "container": [2375, 2376, 6443, 10250],
    # Management
    "management": [161, 162, 389, 636, 88],
    # Email
    "email": [25, 110, 143],
    # Web (for service detection)
    "web": [80, 443, 8080, 8000, 8443, 8888, 3000],
}

# Flatten all critical ports for quick scanning
ALL_CRITICAL_PORTS = sorted(set(
    port for ports in CRITICAL_PORTS.values() for port in ports
))


# Tool-specific scan types for continuous monitoring
CONTINUOUS_SCAN_TYPES = {
    "critical_ports": {
        "name": "Critical Port Monitoring",
        "description": "Monitor for exposed critical ports (databases, remote access, file sharing, containers) using high-speed masscan. Generates security findings for exposed services.",
        "default_config": {
            "ports": ",".join(str(p) for p in ALL_CRITICAL_PORTS),
            "scanner": "masscan",  # Masscan is faster for CIDR blocks
            "rate": 10000,  # 10k packets/sec - fast but safe for most networks
            "service_detection": True,
            "generate_findings": True,
            "alert_on_new": True,
        }
    },
    "masscan": {
        "name": "Masscan Port Scan",
        "description": "High-speed port scanning using masscan",
        "default_config": {
            "rate": 1000,  # packets per second
            "ports": "1-65535",
            "timeout": 5,
        }
    },
    "nuclei": {
        "name": "Nuclei Vulnerability Scan",
        "description": "Template-based vulnerability scanning",
        "default_config": {
            "severity": ["critical", "high", "medium"],
            "rate_limit": 150,
            "timeout": 10,
        }
    },
    "port_scan": {
        "name": "Port Service Scan",
        "description": "Detailed port and service enumeration",
        "default_config": {
            "ports": "top1000",
            "version_detection": True,
        }
    },
    "discovery": {
        "name": "Asset Discovery",
        "description": "Subdomain and asset discovery",
        "default_config": {
            "passive": True,
            "active": False,
            "dns_bruteforce": False,
        }
    },
    "screenshot": {
        "name": "Web Screenshot",
        "description": "Capture screenshots of web assets",
        "default_config": {
            "timeout": 30,
            "viewport_width": 1920,
            "viewport_height": 1080,
        }
    },
    "technology": {
        "name": "Technology Detection",
        "description": "Detect web technologies and frameworks",
        "default_config": {}
    },
}




