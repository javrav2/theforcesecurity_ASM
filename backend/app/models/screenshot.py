"""
Screenshot model for storing website screenshots from EyeWitness.

Tracks screenshot history for each asset to monitor visual changes over time.
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean, JSON, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

from app.db.database import Base


class ScreenshotStatus(enum.Enum):
    """Status of a screenshot capture attempt."""
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    ERROR = "error"


class Screenshot(Base):
    """
    Model for storing screenshots of web assets.
    
    Each asset can have multiple screenshots over time, allowing
    for visual change tracking and historical comparison.
    """
    __tablename__ = "screenshots"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Relationship to asset
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    asset = relationship("Asset", back_populates="screenshots")
    
    # Screenshot data
    url = Column(String(2048), nullable=False)  # The exact URL that was screenshotted
    
    # File storage (relative path from screenshots directory)
    file_path = Column(String(512), nullable=True)  # Path to screenshot image
    thumbnail_path = Column(String(512), nullable=True)  # Path to thumbnail
    source_path = Column(String(512), nullable=True)  # Path to HTML source
    
    # Screenshot metadata
    status = Column(SQLEnum(ScreenshotStatus), default=ScreenshotStatus.PENDING)
    error_message = Column(Text, nullable=True)
    
    # Response information captured by EyeWitness
    http_status = Column(Integer, nullable=True)
    page_title = Column(String(512), nullable=True)
    server_header = Column(String(256), nullable=True)
    
    # Headers captured
    response_headers = Column(JSON, nullable=True)
    
    # Default credentials detection (EyeWitness feature)
    default_creds_detected = Column(Boolean, default=False)
    default_creds_info = Column(JSON, nullable=True)
    
    # Category assigned by EyeWitness
    category = Column(String(64), nullable=True)  # e.g., "CMS", "Network Devices", "High Value"
    
    # Image dimensions
    width = Column(Integer, nullable=True)
    height = Column(Integer, nullable=True)
    file_size = Column(Integer, nullable=True)  # bytes
    
    # Hash for change detection
    image_hash = Column(String(64), nullable=True)  # perceptual hash for similarity
    content_hash = Column(String(64), nullable=True)  # hash of page content
    
    # Change detection
    has_changed = Column(Boolean, default=False)  # Changed from previous screenshot
    change_percentage = Column(Integer, nullable=True)  # % difference from previous
    previous_screenshot_id = Column(Integer, ForeignKey("screenshots.id"), nullable=True)
    
    # Timestamps
    captured_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Scan reference
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    
    def __repr__(self):
        return f"<Screenshot {self.id} for asset {self.asset_id} at {self.captured_at}>"
    
    @property
    def is_successful(self) -> bool:
        """Check if screenshot was captured successfully."""
        return self.status == ScreenshotStatus.SUCCESS and self.file_path is not None


class ScreenshotSchedule(Base):
    """
    Schedule configuration for automatic screenshot captures.
    """
    __tablename__ = "screenshot_schedules"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Organization this schedule belongs to
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    organization = relationship("Organization")
    
    # Schedule settings
    name = Column(String(128), nullable=False)
    description = Column(Text, nullable=True)
    
    # Frequency
    frequency = Column(String(32), default="daily")  # daily, weekly, monthly, custom
    cron_expression = Column(String(64), nullable=True)  # For custom schedules
    
    # Options
    is_active = Column(Boolean, default=True)
    
    # Asset filtering
    asset_types = Column(JSON, default=list)  # Which asset types to screenshot
    include_tags = Column(JSON, default=list)  # Only assets with these tags
    exclude_tags = Column(JSON, default=list)  # Skip assets with these tags
    
    # EyeWitness options
    timeout = Column(Integer, default=30)  # Seconds
    threads = Column(Integer, default=5)
    delay = Column(Integer, default=0)  # Delay between requests
    jitter = Column(Integer, default=0)  # Random jitter
    
    # Timestamps
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Stats
    total_runs = Column(Integer, default=0)
    successful_captures = Column(Integer, default=0)
    failed_captures = Column(Integer, default=0)












