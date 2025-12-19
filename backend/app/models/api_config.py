"""
API Configuration model for storing external service API keys.

Stores encrypted API keys for various external discovery services:
- WhoisXML API
- Whoxy
- VirusTotal
- AlienVault OTX
- And more
"""

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Boolean, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from cryptography.fernet import Fernet
import os
import base64

from app.db.database import Base


def get_encryption_key():
    """Get encryption key from environment, using SECRET_KEY as fallback."""
    # Try dedicated encryption key first
    key = os.environ.get("API_KEY_ENCRYPTION_KEY")
    if not key:
        # Fall back to SECRET_KEY which is always set in docker-compose
        key = os.environ.get("SECRET_KEY", "your-super-secret-key-change-in-production")
    return key


def get_cipher():
    """Get Fernet cipher for encryption/decryption."""
    key = get_encryption_key()
    key = key.encode() if isinstance(key, str) else key
    # Ensure key is valid Fernet key (32 url-safe base64-encoded bytes)
    if len(key) != 44:
        # Generate a deterministic key from the provided key
        import hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(key).digest())
    return Fernet(key)


class APIConfig(Base):
    """
    Model for storing API configurations and keys for external services.
    
    API keys are encrypted at rest for security.
    """
    __tablename__ = "api_configs"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Organization this config belongs to
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    organization = relationship("Organization")
    
    # Service identification
    service_name = Column(String(64), nullable=False, index=True)
    # Service names: whoisxml, whoxy, virustotal, otx, shodan, censys, securitytrails, etc.
    
    # Encrypted API key
    api_key_encrypted = Column(Text, nullable=True)
    
    # Optional additional credentials
    api_user = Column(String(256), nullable=True)  # For services requiring username
    api_secret_encrypted = Column(Text, nullable=True)  # For services with separate secret
    
    # Service-specific configuration
    config = Column(JSON, default=dict)
    # Examples:
    # - whoxy: {"registration_emails": ["admin@company.com"]}
    # - whoisxml: {"organization_names": ["Company Inc"]}
    # - virustotal: {"daily_quota_percent": 70}
    
    # Status
    is_active = Column(Boolean, default=True)
    is_valid = Column(Boolean, default=True)  # Set to False if key fails validation
    
    # Usage tracking
    last_used = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)
    last_error = Column(Text, nullable=True)
    
    # Rate limiting
    rate_limit_per_second = Column(Integer, nullable=True)
    rate_limit_per_day = Column(Integer, nullable=True)
    daily_usage = Column(Integer, default=0)
    daily_usage_reset = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def set_api_key(self, key: str):
        """Encrypt and store API key."""
        if key:
            cipher = get_cipher()
            self.api_key_encrypted = cipher.encrypt(key.encode()).decode()
    
    def get_api_key(self) -> str:
        """Decrypt and return API key."""
        if self.api_key_encrypted:
            cipher = get_cipher()
            return cipher.decrypt(self.api_key_encrypted.encode()).decode()
        return None
    
    def set_api_secret(self, secret: str):
        """Encrypt and store API secret."""
        if secret:
            cipher = get_cipher()
            self.api_secret_encrypted = cipher.encrypt(secret.encode()).decode()
    
    def get_api_secret(self) -> str:
        """Decrypt and return API secret."""
        if self.api_secret_encrypted:
            cipher = get_cipher()
            return cipher.decrypt(self.api_secret_encrypted.encode()).decode()
        return None
    
    def increment_usage(self):
        """Increment usage counter."""
        self.usage_count += 1
        self.daily_usage += 1
        self.last_used = datetime.utcnow()
    
    def reset_daily_usage(self):
        """Reset daily usage counter."""
        self.daily_usage = 0
        self.daily_usage_reset = datetime.utcnow()
    
    def __repr__(self):
        return f"<APIConfig {self.service_name} for org {self.organization_id}>"


# Service name constants
class ExternalService:
    """Constants for external service names."""
    WHOISXML = "whoisxml"
    WHOXY = "whoxy"
    VIRUSTOTAL = "virustotal"
    OTX = "otx"
    SHODAN = "shodan"
    CENSYS = "censys"
    SECURITYTRAILS = "securitytrails"
    BINARYEDGE = "binaryedge"
    PASSIVETOTAL = "passivetotal"
    
    # Free services (no API key required)
    WAYBACK = "wayback"
    RAPIDDNS = "rapiddns"
    CRTSH = "crtsh"
    COMMONCRAWL = "commoncrawl"
    M365 = "m365"


# Default rate limits for services
DEFAULT_RATE_LIMITS = {
    ExternalService.WHOISXML: {"per_second": 2, "per_day": 1000},
    ExternalService.WHOXY: {"per_second": 2, "per_day": 500},
    ExternalService.VIRUSTOTAL: {"per_second": 4, "per_day": 500},
    ExternalService.OTX: {"per_second": 2, "per_day": 10000},
    ExternalService.SHODAN: {"per_second": 1, "per_day": None},
    ExternalService.CENSYS: {"per_second": 0.4, "per_day": 250},
    ExternalService.SECURITYTRAILS: {"per_second": 2, "per_day": 50},
    ExternalService.WAYBACK: {"per_second": 1, "per_day": None},
    ExternalService.RAPIDDNS: {"per_second": 1, "per_day": None},
    ExternalService.M365: {"per_second": 1, "per_day": None},
}













