"""
ASM Data Source Field Mappings

Each data source (scanner/tool) maps its native output fields to our unified schema.
This ensures:
1. All sources produce the same structure (even if some fields are null)
2. Easy to add new data sources
3. Clear field mapping documentation
4. Normalization consistency

Inspired by H-ISAC and ASM Recon data standards.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Type
from enum import Enum
from pydantic import BaseModel, Field
from dataclasses import dataclass, field as dataclass_field


# =============================================================================
# Data Source Registry
# =============================================================================

class DataSourceType(str, Enum):
    """All supported data sources/tools."""
    # Port Scanners
    NAABU = "naabu"
    MASSCAN = "masscan"
    NMAP = "nmap"
    
    # Vulnerability Scanners
    NUCLEI = "nuclei"
    
    # Discovery Tools
    SUBFINDER = "subfinder"
    HTTPX = "httpx"
    DNSX = "dnsx"
    KATANA = "katana"
    
    # External APIs
    CRTSH = "crtsh"
    SECURITYTRAILS = "securitytrails"
    SHODAN = "shodan"
    CENSYS = "censys"
    VIRUSTOTAL = "virustotal"
    WHOXY = "whoxy"
    WHOISXML = "whoisxml"
    BINARYEDGE = "binaryedge"
    HUNTER = "hunter"
    ZOOMEYE = "zoomeye"
    FULLHUNT = "fullhunt"
    NETLAS = "netlas"
    LEAKIX = "leakix"
    CRIMINALIP = "criminalip"
    
    # Archive/Historical
    COMMONCRAWL = "commoncrawl"
    WAYBACKMACHINE = "waybackmachine"
    
    # Screenshot Tools
    EYEWITNESS = "eyewitness"
    GOWITNESS = "gowitness"
    
    # Technology Detection
    WAPPALYZER = "wappalyzer"
    WEBANALYZE = "webanalyze"
    
    # Custom/Manual
    MANUAL = "manual"
    IMPORT = "import"


class FindingCategory(str, Enum):
    """Categories of findings."""
    PORT = "port"
    VULNERABILITY = "vulnerability"
    SUBDOMAIN = "subdomain"
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    CIDR_RANGE = "cidr_range"
    ASN = "asn"
    URL = "url"
    TECHNOLOGY = "technology"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    SCREENSHOT = "screenshot"
    WAYBACK_URL = "wayback_url"
    EMAIL = "email"
    WHOIS = "whois"


class SeverityLevel(str, Enum):
    """Severity levels (CVSS aligned)."""
    CRITICAL = "critical"  # 9.0 - 10.0
    HIGH = "high"          # 7.0 - 8.9
    MEDIUM = "medium"      # 4.0 - 6.9
    LOW = "low"            # 0.1 - 3.9
    INFO = "info"          # 0.0
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Confidence in the finding accuracy."""
    CONFIRMED = "confirmed"  # 100% verified
    HIGH = "high"            # 80-99%
    MEDIUM = "medium"        # 50-79%
    LOW = "low"              # <50%


class PortState(str, Enum):
    """Port states."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class Protocol(str, Enum):
    """Network protocols."""
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


# =============================================================================
# Master Data Model - All Fields
# =============================================================================

class ASMDataModel(BaseModel):
    """
    Master data model containing ALL possible fields from ALL data sources.
    
    Every finding from any source is normalized to this schema.
    Fields not applicable to a source will be None/empty.
    
    This enables:
    - Consistent handling across all tools
    - Easy field mapping and normalization
    - Future field additions without breaking changes
    - Cross-source correlation and deduplication
    """
    
    # =========================================================================
    # Identification & Metadata
    # =========================================================================
    id: Optional[str] = Field(None, description="Unique finding ID")
    source: DataSourceType = Field(..., description="Tool/API that discovered this")
    category: FindingCategory = Field(..., description="Type of finding")
    
    # Timestamps
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When discovered")
    first_seen: Optional[datetime] = Field(None, description="First time seen")
    last_seen: Optional[datetime] = Field(None, description="Last time seen")
    
    # Organization context
    organization_id: Optional[int] = Field(None, description="Associated organization")
    asset_id: Optional[int] = Field(None, description="Associated asset ID")
    scan_id: Optional[int] = Field(None, description="Associated scan ID")
    
    # =========================================================================
    # Target Information
    # =========================================================================
    target: str = Field(..., description="Original scan target")
    
    # Network identifiers
    hostname: Optional[str] = Field(None, description="Resolved hostname/FQDN")
    ip_address: Optional[str] = Field(None, description="IPv4/IPv6 address")
    ip_addresses: List[str] = Field(default_factory=list, description="All resolved IPs")
    cidr: Optional[str] = Field(None, description="CIDR range")
    asn: Optional[str] = Field(None, description="Autonomous System Number")
    asn_name: Optional[str] = Field(None, description="AS organization name")
    
    # URL components
    url: Optional[str] = Field(None, description="Full URL")
    scheme: Optional[str] = Field(None, description="URL scheme (http/https)")
    path: Optional[str] = Field(None, description="URL path")
    query: Optional[str] = Field(None, description="URL query string")
    
    # Port information
    port: Optional[int] = Field(None, description="Port number")
    protocol: Optional[Protocol] = Field(None, description="Protocol (tcp/udp)")
    port_state: Optional[PortState] = Field(None, description="Port state")
    
    # =========================================================================
    # Finding Details
    # =========================================================================
    title: Optional[str] = Field(None, description="Human-readable title")
    description: Optional[str] = Field(None, description="Detailed description")
    severity: SeverityLevel = Field(default=SeverityLevel.INFO, description="Severity level")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH, description="Confidence level")
    
    # Risk assessment
    is_risky: bool = Field(default=False, description="Is this considered risky")
    risk_reason: Optional[str] = Field(None, description="Reason for risk classification")
    risk_score: Optional[float] = Field(None, ge=0, le=100, description="Custom risk score 0-100")
    
    # =========================================================================
    # Service/Application Details
    # =========================================================================
    service_name: Optional[str] = Field(None, description="Service name (ssh, http, etc)")
    service_product: Optional[str] = Field(None, description="Product name (Apache, nginx)")
    service_version: Optional[str] = Field(None, description="Product version")
    service_extra_info: Optional[str] = Field(None, description="Additional service info")
    banner: Optional[str] = Field(None, description="Service banner/response")
    cpe: Optional[str] = Field(None, description="Common Platform Enumeration")
    
    # =========================================================================
    # Web/HTTP Details
    # =========================================================================
    http_status_code: Optional[int] = Field(None, description="HTTP status code")
    http_title: Optional[str] = Field(None, description="HTML page title")
    http_server: Optional[str] = Field(None, description="Server header value")
    http_content_type: Optional[str] = Field(None, description="Content-Type header")
    http_content_length: Optional[int] = Field(None, description="Content-Length")
    http_response_time_ms: Optional[float] = Field(None, description="Response time in ms")
    http_body_hash: Optional[str] = Field(None, description="SHA256 hash of body")
    http_headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers")
    http_cookies: List[str] = Field(default_factory=list, description="Cookies found")
    
    # =========================================================================
    # TLS/SSL Details
    # =========================================================================
    tls_enabled: Optional[bool] = Field(None, description="TLS/SSL enabled")
    tls_version: Optional[str] = Field(None, description="TLS version")
    tls_cipher: Optional[str] = Field(None, description="TLS cipher suite")
    tls_issuer: Optional[str] = Field(None, description="Certificate issuer")
    tls_subject: Optional[str] = Field(None, description="Certificate subject")
    tls_san: List[str] = Field(default_factory=list, description="Subject Alternative Names")
    tls_not_before: Optional[datetime] = Field(None, description="Cert valid from")
    tls_not_after: Optional[datetime] = Field(None, description="Cert valid until")
    tls_serial: Optional[str] = Field(None, description="Certificate serial")
    tls_fingerprint_sha256: Optional[str] = Field(None, description="Cert SHA256 fingerprint")
    
    # =========================================================================
    # DNS Details
    # =========================================================================
    dns_record_type: Optional[str] = Field(None, description="DNS record type (A, AAAA, MX, etc)")
    dns_record_value: Optional[str] = Field(None, description="DNS record value")
    dns_ttl: Optional[int] = Field(None, description="DNS TTL")
    cname: Optional[str] = Field(None, description="CNAME record")
    mx_records: List[str] = Field(default_factory=list, description="MX records")
    ns_records: List[str] = Field(default_factory=list, description="NS records")
    txt_records: List[str] = Field(default_factory=list, description="TXT records")
    
    # =========================================================================
    # Vulnerability Details
    # =========================================================================
    vuln_id: Optional[str] = Field(None, description="Vulnerability ID")
    template_id: Optional[str] = Field(None, description="Scanner template ID")
    template_name: Optional[str] = Field(None, description="Template name")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    cwe_id: Optional[str] = Field(None, description="CWE identifier")
    cvss_score: Optional[float] = Field(None, ge=0, le=10, description="CVSS score")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector string")
    epss_score: Optional[float] = Field(None, description="EPSS probability score")
    exploit_available: Optional[bool] = Field(None, description="Known exploit exists")
    patch_available: Optional[bool] = Field(None, description="Patch available")
    matched_at: Optional[str] = Field(None, description="Where vulnerability matched")
    matcher_name: Optional[str] = Field(None, description="Matcher that triggered")
    extracted_results: List[str] = Field(default_factory=list, description="Extracted data")
    curl_command: Optional[str] = Field(None, description="Reproduction curl command")
    proof: Optional[str] = Field(None, description="Proof of vulnerability")
    
    # =========================================================================
    # Technology Details
    # =========================================================================
    technologies: List[str] = Field(default_factory=list, description="Detected technologies")
    technology_details: List[Dict[str, Any]] = Field(default_factory=list, description="Tech with versions/categories")
    frameworks: List[str] = Field(default_factory=list, description="Detected frameworks")
    cms: Optional[str] = Field(None, description="Content Management System")
    language: Optional[str] = Field(None, description="Programming language")
    
    # =========================================================================
    # CDN/WAF/Hosting
    # =========================================================================
    cdn_name: Optional[str] = Field(None, description="CDN provider")
    cdn_detected: Optional[bool] = Field(None, description="CDN detected")
    waf_name: Optional[str] = Field(None, description="WAF detected")
    waf_detected: Optional[bool] = Field(None, description="WAF detected")
    cloud_provider: Optional[str] = Field(None, description="Cloud provider")
    hosting_provider: Optional[str] = Field(None, description="Hosting provider")
    
    # =========================================================================
    # Geolocation
    # =========================================================================
    country_code: Optional[str] = Field(None, description="ISO country code")
    country_name: Optional[str] = Field(None, description="Country name")
    city: Optional[str] = Field(None, description="City")
    region: Optional[str] = Field(None, description="Region/state")
    latitude: Optional[float] = Field(None, description="Latitude")
    longitude: Optional[float] = Field(None, description="Longitude")
    
    # =========================================================================
    # WHOIS Details
    # =========================================================================
    whois_registrar: Optional[str] = Field(None, description="Domain registrar")
    whois_registrant: Optional[str] = Field(None, description="Registrant name/org")
    whois_created_date: Optional[datetime] = Field(None, description="Domain created date")
    whois_updated_date: Optional[datetime] = Field(None, description="Domain updated date")
    whois_expiry_date: Optional[datetime] = Field(None, description="Domain expiry date")
    whois_nameservers: List[str] = Field(default_factory=list, description="Nameservers")
    
    # =========================================================================
    # Screenshot Details
    # =========================================================================
    screenshot_path: Optional[str] = Field(None, description="Screenshot file path")
    screenshot_url: Optional[str] = Field(None, description="Screenshot URL/S3 path")
    screenshot_hash: Optional[str] = Field(None, description="Screenshot hash")
    
    # =========================================================================
    # Email Details
    # =========================================================================
    email: Optional[str] = Field(None, description="Email address")
    email_verified: Optional[bool] = Field(None, description="Email verified")
    email_type: Optional[str] = Field(None, description="personal/generic/role")
    
    # =========================================================================
    # Historical/Archive Details
    # =========================================================================
    archive_url: Optional[str] = Field(None, description="Archive.org URL")
    archive_timestamp: Optional[datetime] = Field(None, description="Archive snapshot date")
    commoncrawl_index: Optional[str] = Field(None, description="CommonCrawl index")
    
    # =========================================================================
    # Classification & Tags
    # =========================================================================
    tags: List[str] = Field(default_factory=list, description="Tags/labels")
    labels: List[str] = Field(default_factory=list, description="Custom labels")
    categories: List[str] = Field(default_factory=list, description="Finding categories")
    
    # =========================================================================
    # References & Evidence
    # =========================================================================
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    evidence: Optional[str] = Field(None, description="Evidence/proof text")
    notes: Optional[str] = Field(None, description="Analyst notes")
    
    # =========================================================================
    # Raw Data (for debugging/analysis)
    # =========================================================================
    raw_output: Optional[str] = Field(None, description="Raw tool output")
    raw_json: Optional[Dict[str, Any]] = Field(None, description="Original JSON response")
    
    class Config:
        use_enum_values = True


# =============================================================================
# Source-Specific Field Mappings
# =============================================================================

@dataclass
class FieldMapping:
    """Maps a source field to the unified model field."""
    source_field: str
    model_field: str
    transform: Optional[str] = None  # Optional transformation (e.g., "lowercase", "parse_date")


@dataclass
class DataSourceMapping:
    """
    Complete field mapping for a data source.
    
    Defines how each tool's output maps to ASMDataModel fields.
    """
    source: DataSourceType
    category: FindingCategory
    description: str
    output_format: str  # json, xml, csv, text
    field_mappings: List[FieldMapping] = dataclass_field(default_factory=list)
    default_values: Dict[str, Any] = dataclass_field(default_factory=dict)


# =============================================================================
# Field Mapping Definitions for Each Tool
# =============================================================================

NAABU_MAPPING = DataSourceMapping(
    source=DataSourceType.NAABU,
    category=FindingCategory.PORT,
    description="Fast port scanner from ProjectDiscovery",
    output_format="json",
    field_mappings=[
        FieldMapping("host", "hostname"),
        FieldMapping("ip", "ip_address"),
        FieldMapping("port", "port"),
        FieldMapping("protocol", "protocol"),
        FieldMapping("timestamp", "timestamp", "parse_date"),
    ],
    default_values={
        "port_state": PortState.OPEN,
        "protocol": Protocol.TCP,
        "confidence": ConfidenceLevel.HIGH,
    }
)

MASSCAN_MAPPING = DataSourceMapping(
    source=DataSourceType.MASSCAN,
    category=FindingCategory.PORT,
    description="High-speed port scanner",
    output_format="json",
    field_mappings=[
        FieldMapping("ip", "ip_address"),
        FieldMapping("ports[].port", "port"),
        FieldMapping("ports[].proto", "protocol"),
        FieldMapping("ports[].status", "port_state"),
        FieldMapping("ports[].service.name", "service_name"),
        FieldMapping("ports[].service.banner", "banner"),
        FieldMapping("timestamp", "timestamp", "unix_to_datetime"),
    ],
    default_values={
        "confidence": ConfidenceLevel.HIGH,
    }
)

NMAP_MAPPING = DataSourceMapping(
    source=DataSourceType.NMAP,
    category=FindingCategory.PORT,
    description="Network mapper with service detection",
    output_format="xml",
    field_mappings=[
        FieldMapping("host/address/@addr", "ip_address"),
        FieldMapping("host/hostnames/hostname/@name", "hostname"),
        FieldMapping("host/ports/port/@portid", "port"),
        FieldMapping("host/ports/port/@protocol", "protocol"),
        FieldMapping("host/ports/port/state/@state", "port_state"),
        FieldMapping("host/ports/port/state/@reason", "risk_reason"),
        FieldMapping("host/ports/port/service/@name", "service_name"),
        FieldMapping("host/ports/port/service/@product", "service_product"),
        FieldMapping("host/ports/port/service/@version", "service_version"),
        FieldMapping("host/ports/port/service/@extrainfo", "service_extra_info"),
        FieldMapping("host/ports/port/script/@output", "banner"),
        FieldMapping("host/ports/port/service/cpe", "cpe"),
    ],
    default_values={
        "confidence": ConfidenceLevel.CONFIRMED,
    }
)

NUCLEI_MAPPING = DataSourceMapping(
    source=DataSourceType.NUCLEI,
    category=FindingCategory.VULNERABILITY,
    description="Vulnerability scanner with YAML templates",
    output_format="json",
    field_mappings=[
        FieldMapping("host", "hostname"),
        FieldMapping("ip", "ip_address"),
        FieldMapping("matched-at", "matched_at"),
        FieldMapping("template-id", "template_id"),
        FieldMapping("info.name", "template_name"),
        FieldMapping("info.severity", "severity"),
        FieldMapping("info.description", "description"),
        FieldMapping("info.tags", "tags", "split_comma"),
        FieldMapping("info.reference", "references"),
        FieldMapping("info.classification.cve-id", "cve_id", "first_item"),
        FieldMapping("info.classification.cwe-id", "cwe_id", "first_item"),
        FieldMapping("info.classification.cvss-score", "cvss_score", "to_float"),
        FieldMapping("info.classification.cvss-metrics", "cvss_vector"),
        FieldMapping("matcher-name", "matcher_name"),
        FieldMapping("extracted-results", "extracted_results"),
        FieldMapping("curl-command", "curl_command"),
        FieldMapping("timestamp", "timestamp", "parse_iso"),
    ],
    default_values={
        "confidence": ConfidenceLevel.CONFIRMED,
    }
)

HTTPX_MAPPING = DataSourceMapping(
    source=DataSourceType.HTTPX,
    category=FindingCategory.URL,
    description="HTTP probe with technology detection",
    output_format="json",
    field_mappings=[
        FieldMapping("url", "url"),
        FieldMapping("host", "hostname"),
        FieldMapping("input", "target"),
        FieldMapping("status_code", "http_status_code"),
        FieldMapping("status-code", "http_status_code"),
        FieldMapping("title", "http_title"),
        FieldMapping("webserver", "http_server"),
        FieldMapping("content_type", "http_content_type"),
        FieldMapping("content-type", "http_content_type"),
        FieldMapping("content_length", "http_content_length"),
        FieldMapping("content-length", "http_content_length"),
        FieldMapping("a", "ip_addresses", "array"),
        FieldMapping("cname", "cname", "first_item"),
        FieldMapping("tech", "technologies"),
        FieldMapping("cdn_name", "cdn_name"),
        FieldMapping("cdn-name", "cdn_name"),
        FieldMapping("cdn", "cdn_detected", "to_bool"),
        FieldMapping("waf", "waf_name"),
        FieldMapping("tls.version", "tls_version"),
        FieldMapping("tls.cipher", "tls_cipher"),
        FieldMapping("time", "http_response_time_ms", "parse_duration"),
        FieldMapping("body_sha256", "http_body_hash"),
        FieldMapping("body-sha256", "http_body_hash"),
    ],
    default_values={
        "tls_enabled": True,  # Will be overridden based on scheme
        "confidence": ConfidenceLevel.HIGH,
    }
)

SUBFINDER_MAPPING = DataSourceMapping(
    source=DataSourceType.SUBFINDER,
    category=FindingCategory.SUBDOMAIN,
    description="Subdomain enumeration tool",
    output_format="json",
    field_mappings=[
        FieldMapping("host", "hostname"),
        FieldMapping("source", "notes"),
        FieldMapping("input", "target"),
    ],
    default_values={
        "severity": SeverityLevel.INFO,
        "confidence": ConfidenceLevel.HIGH,
    }
)

DNSX_MAPPING = DataSourceMapping(
    source=DataSourceType.DNSX,
    category=FindingCategory.DNS_RECORD,
    description="DNS query tool",
    output_format="json",
    field_mappings=[
        FieldMapping("host", "hostname"),
        FieldMapping("a", "ip_addresses"),
        FieldMapping("aaaa", "ip_addresses"),
        FieldMapping("cname", "cname"),
        FieldMapping("mx", "mx_records"),
        FieldMapping("ns", "ns_records"),
        FieldMapping("txt", "txt_records"),
        FieldMapping("resolver", "notes"),
    ],
    default_values={
        "severity": SeverityLevel.INFO,
        "confidence": ConfidenceLevel.CONFIRMED,
    }
)

CRTSH_MAPPING = DataSourceMapping(
    source=DataSourceType.CRTSH,
    category=FindingCategory.CERTIFICATE,
    description="Certificate Transparency logs (crt.sh)",
    output_format="json",
    field_mappings=[
        FieldMapping("common_name", "hostname"),
        FieldMapping("name_value", "tls_san", "split_newline"),
        FieldMapping("issuer_name", "tls_issuer"),
        FieldMapping("not_before", "tls_not_before", "parse_date"),
        FieldMapping("not_after", "tls_not_after", "parse_date"),
        FieldMapping("serial_number", "tls_serial"),
    ],
    default_values={
        "severity": SeverityLevel.INFO,
        "confidence": ConfidenceLevel.CONFIRMED,
    }
)

SHODAN_MAPPING = DataSourceMapping(
    source=DataSourceType.SHODAN,
    category=FindingCategory.PORT,
    description="Shodan internet search engine",
    output_format="json",
    field_mappings=[
        FieldMapping("ip_str", "ip_address"),
        FieldMapping("hostnames", "hostname", "first_item"),
        FieldMapping("port", "port"),
        FieldMapping("transport", "protocol"),
        FieldMapping("product", "service_product"),
        FieldMapping("version", "service_version"),
        FieldMapping("data", "banner"),
        FieldMapping("org", "asn_name"),
        FieldMapping("asn", "asn"),
        FieldMapping("isp", "hosting_provider"),
        FieldMapping("os", "service_extra_info"),
        FieldMapping("country_code", "country_code"),
        FieldMapping("country_name", "country_name"),
        FieldMapping("city", "city"),
        FieldMapping("latitude", "latitude"),
        FieldMapping("longitude", "longitude"),
        FieldMapping("vulns", "tags"),
        FieldMapping("ssl.cert.issuer.CN", "tls_issuer"),
        FieldMapping("ssl.cert.subject.CN", "tls_subject"),
        FieldMapping("ssl.cert.fingerprint.sha256", "tls_fingerprint_sha256"),
        FieldMapping("ssl.versions", "tls_version", "first_item"),
    ],
    default_values={
        "port_state": PortState.OPEN,
        "confidence": ConfidenceLevel.HIGH,
    }
)

CENSYS_MAPPING = DataSourceMapping(
    source=DataSourceType.CENSYS,
    category=FindingCategory.PORT,
    description="Censys internet search",
    output_format="json",
    field_mappings=[
        FieldMapping("ip", "ip_address"),
        FieldMapping("services[].port", "port"),
        FieldMapping("services[].transport_protocol", "protocol"),
        FieldMapping("services[].service_name", "service_name"),
        FieldMapping("services[].banner", "banner"),
        FieldMapping("services[].software[].product", "service_product"),
        FieldMapping("services[].software[].version", "service_version"),
        FieldMapping("autonomous_system.asn", "asn"),
        FieldMapping("autonomous_system.name", "asn_name"),
        FieldMapping("location.country", "country_name"),
        FieldMapping("location.city", "city"),
        FieldMapping("location.coordinates.latitude", "latitude"),
        FieldMapping("location.coordinates.longitude", "longitude"),
    ],
    default_values={
        "port_state": PortState.OPEN,
        "confidence": ConfidenceLevel.HIGH,
    }
)

VIRUSTOTAL_MAPPING = DataSourceMapping(
    source=DataSourceType.VIRUSTOTAL,
    category=FindingCategory.DOMAIN,
    description="VirusTotal domain/IP intelligence",
    output_format="json",
    field_mappings=[
        FieldMapping("id", "hostname"),
        FieldMapping("attributes.last_dns_records", "dns_record_value"),
        FieldMapping("attributes.registrar", "whois_registrar"),
        FieldMapping("attributes.creation_date", "whois_created_date", "unix_to_datetime"),
        FieldMapping("attributes.last_update_date", "whois_updated_date", "unix_to_datetime"),
        FieldMapping("attributes.categories", "categories"),
        FieldMapping("attributes.tags", "tags"),
        FieldMapping("attributes.popularity_ranks", "notes"),
    ],
    default_values={
        "severity": SeverityLevel.INFO,
        "confidence": ConfidenceLevel.HIGH,
    }
)

WAPPALYZER_MAPPING = DataSourceMapping(
    source=DataSourceType.WAPPALYZER,
    category=FindingCategory.TECHNOLOGY,
    description="Technology detection",
    output_format="json",
    field_mappings=[
        FieldMapping("url", "url"),
        FieldMapping("technologies[].name", "technologies"),
        FieldMapping("technologies[].categories[].name", "categories"),
        FieldMapping("technologies[].version", "technology_details"),
    ],
    default_values={
        "severity": SeverityLevel.INFO,
        "confidence": ConfidenceLevel.HIGH,
    }
)

EYEWITNESS_MAPPING = DataSourceMapping(
    source=DataSourceType.EYEWITNESS,
    category=FindingCategory.SCREENSHOT,
    description="Screenshot capture tool",
    output_format="json",
    field_mappings=[
        FieldMapping("url", "url"),
        FieldMapping("screenshot_path", "screenshot_path"),
        FieldMapping("title", "http_title"),
        FieldMapping("server", "http_server"),
        FieldMapping("status_code", "http_status_code"),
    ],
    default_values={
        "severity": SeverityLevel.INFO,
        "confidence": ConfidenceLevel.CONFIRMED,
    }
)

WAYBACKMACHINE_MAPPING = DataSourceMapping(
    source=DataSourceType.WAYBACKMACHINE,
    category=FindingCategory.WAYBACK_URL,
    description="Internet Archive Wayback Machine",
    output_format="text",
    field_mappings=[
        FieldMapping("url", "archive_url"),
        FieldMapping("original", "url"),
        FieldMapping("timestamp", "archive_timestamp", "wayback_date"),
    ],
    default_values={
        "severity": SeverityLevel.INFO,
        "confidence": ConfidenceLevel.CONFIRMED,
    }
)

COMMONCRAWL_MAPPING = DataSourceMapping(
    source=DataSourceType.COMMONCRAWL,
    category=FindingCategory.SUBDOMAIN,
    description="CommonCrawl web archive index",
    output_format="json",
    field_mappings=[
        FieldMapping("url", "url"),
        FieldMapping("subdomain", "hostname"),
        FieldMapping("crawl_index", "commoncrawl_index"),
        FieldMapping("timestamp", "archive_timestamp", "parse_date"),
    ],
    default_values={
        "severity": SeverityLevel.INFO,
        "confidence": ConfidenceLevel.MEDIUM,
    }
)


# =============================================================================
# Registry of All Mappings
# =============================================================================

DATA_SOURCE_MAPPINGS: Dict[DataSourceType, DataSourceMapping] = {
    DataSourceType.NAABU: NAABU_MAPPING,
    DataSourceType.MASSCAN: MASSCAN_MAPPING,
    DataSourceType.NMAP: NMAP_MAPPING,
    DataSourceType.NUCLEI: NUCLEI_MAPPING,
    DataSourceType.HTTPX: HTTPX_MAPPING,
    DataSourceType.SUBFINDER: SUBFINDER_MAPPING,
    DataSourceType.DNSX: DNSX_MAPPING,
    DataSourceType.CRTSH: CRTSH_MAPPING,
    DataSourceType.SHODAN: SHODAN_MAPPING,
    DataSourceType.CENSYS: CENSYS_MAPPING,
    DataSourceType.VIRUSTOTAL: VIRUSTOTAL_MAPPING,
    DataSourceType.WAPPALYZER: WAPPALYZER_MAPPING,
    DataSourceType.EYEWITNESS: EYEWITNESS_MAPPING,
    DataSourceType.WAYBACKMACHINE: WAYBACKMACHINE_MAPPING,
    DataSourceType.COMMONCRAWL: COMMONCRAWL_MAPPING,
}


def get_source_mapping(source: DataSourceType) -> Optional[DataSourceMapping]:
    """Get the field mapping for a data source."""
    return DATA_SOURCE_MAPPINGS.get(source)


def list_all_model_fields() -> List[str]:
    """List all fields in ASMDataModel."""
    return list(ASMDataModel.model_fields.keys())


def get_fields_for_source(source: DataSourceType) -> List[str]:
    """Get the model fields that a source populates."""
    mapping = get_source_mapping(source)
    if not mapping:
        return []
    return [fm.model_field for fm in mapping.field_mappings]


def get_unmapped_fields_for_source(source: DataSourceType) -> List[str]:
    """Get model fields that a source does NOT populate."""
    all_fields = set(list_all_model_fields())
    mapped_fields = set(get_fields_for_source(source))
    return sorted(all_fields - mapped_fields)

