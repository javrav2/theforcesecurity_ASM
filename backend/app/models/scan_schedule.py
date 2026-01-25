"""Scan Schedule model for continuous monitoring."""

import enum
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Enum, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship

from app.db.database import Base


class ScheduleFrequency(str, enum.Enum):
    """Frequency for scheduled scans."""
    EVERY_15_MINUTES = "every_15_minutes"
    EVERY_30_MINUTES = "every_30_minutes"
    HOURLY = "hourly"
    EVERY_2_HOURS = "every_2_hours"
    EVERY_4_HOURS = "every_4_hours"
    EVERY_6_HOURS = "every_6_hours"
    EVERY_12_HOURS = "every_12_hours"
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
        
        if self.frequency == ScheduleFrequency.EVERY_15_MINUTES:
            # Next 15-minute mark
            minutes = (now.minute // 15 + 1) * 15
            if minutes >= 60:
                next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
            else:
                next_run = now.replace(minute=minutes, second=0, microsecond=0)
        elif self.frequency == ScheduleFrequency.EVERY_30_MINUTES:
            # Next 30-minute mark
            if now.minute < 30:
                next_run = now.replace(minute=30, second=0, microsecond=0)
            else:
                next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        elif self.frequency == ScheduleFrequency.HOURLY:
            next_run = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        elif self.frequency == ScheduleFrequency.EVERY_2_HOURS:
            next_hour = ((now.hour // 2) + 1) * 2
            if next_hour >= 24:
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            else:
                next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
        elif self.frequency == ScheduleFrequency.EVERY_4_HOURS:
            next_hour = ((now.hour // 4) + 1) * 4
            if next_hour >= 24:
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            else:
                next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
        elif self.frequency == ScheduleFrequency.EVERY_6_HOURS:
            next_hour = ((now.hour // 6) + 1) * 6
            if next_hour >= 24:
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
            else:
                next_run = now.replace(hour=next_hour, minute=0, second=0, microsecond=0)
        elif self.frequency == ScheduleFrequency.EVERY_12_HOURS:
            if now.hour < 12:
                next_run = now.replace(hour=12, minute=0, second=0, microsecond=0)
            else:
                next_run = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
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
        "name": "Nuclei Vulnerability Scan (All Severities)",
        "description": "Full template-based vulnerability scanning - all severity levels. Can take a long time for large targets.",
        "default_config": {
            "severity": ["critical", "high", "medium", "low", "info"],
            "rate_limit": 150,
            "timeout": 10,
        }
    },
    "nuclei_critical": {
        "name": "Nuclei - Critical Only",
        "description": "Fast scan for critical vulnerabilities only. Runs quickly, catches the most severe issues.",
        "default_config": {
            "severity": ["critical"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "daily",
    },
    "nuclei_high": {
        "name": "Nuclei - High Severity",
        "description": "Scan for high severity vulnerabilities. Runs faster than full scan.",
        "default_config": {
            "severity": ["high"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "daily",
    },
    "nuclei_critical_high": {
        "name": "Nuclei - Critical & High",
        "description": "Scan for critical and high severity vulnerabilities. Best balance of speed and coverage.",
        "default_config": {
            "severity": ["critical", "high"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "daily",
    },
    "nuclei_medium": {
        "name": "Nuclei - Medium Severity",
        "description": "Scan for medium severity vulnerabilities.",
        "default_config": {
            "severity": ["medium"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "weekly",
    },
    "nuclei_low_info": {
        "name": "Nuclei - Low & Info",
        "description": "Scan for low severity and informational findings. Slowest but most comprehensive.",
        "default_config": {
            "severity": ["low", "info"],
            "rate_limit": 150,
            "timeout": 10,
        },
        "recommended_frequency": "weekly",
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
        "name": "Web Screenshot Capture",
        "description": "Capture screenshots of web assets for visual monitoring and change detection. Run daily to track website changes.",
        "default_config": {
            "timeout": 30,
            "viewport_width": 1920,
            "viewport_height": 1080,
            "threads": 5,
        },
        "recommended_frequency": "daily",
    },
    "subdomain_enum": {
        "name": "Subdomain Enumeration",
        "description": "Discover new subdomains using Subfinder. Run daily to find newly created subdomains and expand attack surface visibility.",
        "default_config": {
            "sources": ["all"],
            "recursive": False,
            "timeout": 300,
        },
        "recommended_frequency": "daily",
    },
    "technology": {
        "name": "Technology Detection",
        "description": "Detect web technologies and frameworks using Wappalyzer fingerprinting",
        "default_config": {}
    },
    "http_probe": {
        "name": "HTTP Probe",
        "description": "Check which assets are live and responding to HTTP requests. Updates is_live status and discovers web services.",
        "default_config": {
            "timeout": 30,
            "follow_redirects": True,
        },
        "recommended_frequency": "daily",
    },
    "dns_resolution": {
        "name": "DNS Resolution",
        "description": "Resolve domains to IP addresses and enrich with geolocation data. Detects infrastructure changes.",
        "default_config": {
            "include_geo": True,
            "limit": 1000,
        },
        "recommended_frequency": "daily",
    },
    "login_portal": {
        "name": "Login Portal Detection",
        "description": "Detect login pages, admin panels, and authentication endpoints using waybackurls and pattern matching",
        "default_config": {
            "include_subdomains": True,
            "use_wayback": True,
        }
    },
    "full_discovery": {
        "name": "Full Asset Discovery",
        "description": "Complete discovery including subdomains, DNS, HTTP probing, and technology detection",
        "default_config": {
            "passive": True,
            "active": True,
            "dns_bruteforce": False,
        }
    },
    "paramspider": {
        "name": "Parameter Discovery (ParamSpider)",
        "description": "Discover URL parameters from web archives for vulnerability testing. Finds XSS, SQLi, and other injection points.",
        "default_config": {
            "level": "high",
            "timeout": 300,
            "exclude_extensions": ["css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2"],
        },
        "recommended_frequency": "weekly",
    },
    "waybackurls": {
        "name": "Historical URL Discovery (WaybackURLs)",
        "description": "Fetch historical URLs from Wayback Machine to find forgotten endpoints, old configs, and sensitive files.",
        "default_config": {
            "include_subdomains": True,
            "timeout_per_domain": 120,
            "max_concurrent": 3,
        },
        "recommended_frequency": "weekly",
    },
    "katana": {
        "name": "Deep Web Crawling (Katana)",
        "description": "Active deep crawling with JS parsing. Discovers endpoints, parameters, JS files, and forms. Stores all findings on assets.",
        "default_config": {
            "depth": 5,
            "js_crawl": True,
            "form_extraction": True,
            "rate_limit": 150,
            "concurrency": 10,
            "timeout": 600,
        },
        "recommended_frequency": "weekly",
    },
    "cleanup": {
        "name": "System Cleanup",
        "description": "Clean up old scan files, temporary files, and orphaned data. Frees disk space and maintains system health.",
        "default_config": {
            "screenshots_retention_days": 90,
            "scan_files_retention_days": 30,
            "temp_files_retention_days": 1,
            "failed_scans_retention_days": 14,
            "dry_run": False,
        },
        "recommended_frequency": "weekly",
    },
}




