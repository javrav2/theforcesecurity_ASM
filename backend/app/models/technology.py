"""Technology model for tracking detected technologies via Wappalyzer."""

from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Table, ForeignKey
from sqlalchemy.orm import relationship

from app.db.database import Base


# Association table for many-to-many relationship between assets and technologies
asset_technologies = Table(
    "asset_technologies",
    Base.metadata,
    Column("asset_id", Integer, ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
    Column("technology_id", Integer, ForeignKey("technologies.id", ondelete="CASCADE"), primary_key=True),
    Column("confidence", Integer, default=100),  # Detection confidence 0-100
    Column("version", String(50), nullable=True),  # Detected version
    Column("detected_at", DateTime, default=datetime.utcnow),
)


class Technology(Base):
    """Technology model for Wappalyzer-detected technologies."""
    
    __tablename__ = "technologies"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Technology identification (from Wappalyzer)
    name = Column(String(255), unique=True, index=True, nullable=False)
    slug = Column(String(255), unique=True, index=True, nullable=False)  # URL-safe name
    
    # Wappalyzer categories
    categories = Column(JSON, default=list)  # List of category names
    
    # Technology details
    description = Column(Text, nullable=True)
    website = Column(String(500), nullable=True)
    icon = Column(String(255), nullable=True)
    
    # CPE (Common Platform Enumeration) for vulnerability mapping
    cpe = Column(String(255), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assets = relationship(
        "Asset",
        secondary=asset_technologies,
        back_populates="technologies"
    )
    
    def __repr__(self):
        return f"<Technology {self.name}>"


# Wappalyzer category mappings
WAPPALYZER_CATEGORIES = {
    1: "CMS",
    2: "Message boards",
    3: "Database managers",
    4: "Documentation",
    5: "Widgets",
    6: "Ecommerce",
    7: "Photo galleries",
    8: "Wikis",
    9: "Hosting panels",
    10: "Analytics",
    11: "Blogs",
    12: "JavaScript frameworks",
    13: "Issue trackers",
    14: "Video players",
    15: "Comment systems",
    16: "Security",
    17: "Font scripts",
    18: "Web frameworks",
    19: "Miscellaneous",
    20: "Editors",
    21: "LMS",
    22: "Web servers",
    23: "Caching",
    24: "Rich text editors",
    25: "JavaScript graphics",
    26: "Mobile frameworks",
    27: "Programming languages",
    28: "Operating systems",
    29: "Search engines",
    30: "Web mail",
    31: "CDN",
    32: "Marketing automation",
    33: "Web server extensions",
    34: "Databases",
    35: "Maps",
    36: "Advertising",
    37: "Network devices",
    38: "Media servers",
    39: "Webcams",
    41: "Payment processors",
    42: "Tag managers",
    44: "CI",
    45: "Control systems",
    46: "Remote access",
    47: "Dev tools",
    48: "Network storage",
    49: "Feed readers",
    50: "Document management",
    51: "Page builders",
    52: "Live chat",
    53: "CRM",
    54: "SEO",
    55: "Accounting",
    56: "Cryptominers",
    57: "Static site generator",
    58: "User onboarding",
    59: "JavaScript libraries",
    60: "Containers",
    61: "SaaS",
    62: "PaaS",
    63: "IaaS",
    64: "Reverse proxies",
    65: "Load balancers",
    66: "UI frameworks",
    67: "Cookie compliance",
    68: "Accessibility",
    69: "Social login",
    70: "SSL/TLS certificate authorities",
    71: "Affiliate programs",
    72: "Appointment scheduling",
    73: "Surveys",
    74: "A/B testing",
    75: "Email",
    76: "Personalisation",
    77: "Retargeting",
    78: "RUM",
    79: "Geolocation",
    80: "WordPress themes",
    81: "Shopify themes",
    82: "Drupal themes",
    83: "Browser fingerprinting",
    84: "Loyalty & rewards",
    85: "Feature management",
    86: "Segmentation",
    87: "WordPress plugins",
    88: "Hosting",
    89: "Translation",
    90: "Reviews",
    91: "Buy now pay later",
    92: "Performance",
    93: "Reservations & delivery",
    94: "Referral marketing",
    95: "Digital asset management",
    96: "Content curation",
    97: "Customer data platform",
    98: "Cart abandonment",
    99: "Shipping carriers",
    100: "Shopify apps",
    101: "Recruitment & staffing",
    102: "Returns",
    103: "Livestreaming",
    104: "Ticket & event management",
    105: "Authentication",
    106: "Security",
    107: "Form builders",
}
