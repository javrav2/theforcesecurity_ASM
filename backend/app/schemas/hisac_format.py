"""
H-ISAC Compatible Output Format

Based on the H-ISAC reconnaissance scripts output pattern:
- get_whoxy, get_massdns, get_masscan, etc.

All tools output a consistent JSON structure:
{
    "ip_or_fqdn": "<target>",
    "port": <port_number>,
    "protocol": "<protocol_or_type>",
    "data": [<tool_specific_data>]
}

This module provides:
1. The H-ISAC output schema
2. Converters from our ASMDataModel to H-ISAC format
3. Converters from H-ISAC format to ASMDataModel
"""

from datetime import datetime
from typing import Optional, List, Dict, Any, Union
from enum import Enum
from pydantic import BaseModel, Field
from dataclasses import dataclass


# =============================================================================
# H-ISAC Protocol Types (based on script outputs)
# =============================================================================

class HISACProtocol(str, Enum):
    """Protocol types used in H-ISAC scripts."""
    # Port scanning
    TCP = "tcp"
    UDP = "udp"
    
    # DNS
    DNS = "dns"
    
    # WHOIS/Domain
    WHOIS = "whois"
    
    # HTTP/Web
    HTTP = "http"
    HTTPS = "https"
    
    # Discovery
    SUBDOMAIN = "subdomain"
    CERTIFICATE = "certificate"
    
    # Intelligence
    THREAT_INTEL = "threat_intel"
    ASN = "asn"
    
    # Archive
    WAYBACK = "wayback"
    COMMONCRAWL = "commoncrawl"
    
    # Microsoft 365
    M365 = "m365"
    
    # Generic
    INFO = "info"


# =============================================================================
# H-ISAC Core Output Schema
# =============================================================================

class HISACResult(BaseModel):
    """
    H-ISAC compatible scan result format.
    
    This is the standard output format used by H-ISAC reconnaissance scripts.
    All tools normalize their output to this structure.
    """
    ip_or_fqdn: str = Field(..., description="IP address or fully qualified domain name")
    port: int = Field(default=0, description="Port number (0 for non-port findings)")
    protocol: str = Field(..., description="Protocol or finding type (tcp, dns, whois, etc.)")
    data: List[Dict[str, Any]] = Field(default_factory=list, description="Tool-specific data array")
    
    # Extended fields (not in original H-ISAC but useful)
    source: Optional[str] = Field(None, description="Tool/script that generated this result")
    timestamp: Optional[datetime] = Field(None, description="When the result was generated")
    organization_id: Optional[int] = Field(None, description="Associated organization")
    
    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "ip_or_fqdn": "1.2.3.4",
                    "port": 443,
                    "protocol": "tcp",
                    "data": [{"status": "open", "banner": "HTTP/1.1 200 OK"}]
                },
                {
                    "ip_or_fqdn": "example.com",
                    "port": 0,
                    "protocol": "dns",
                    "data": [{"type": "A", "data": "1.2.3.4"}, {"type": "CNAME", "data": "cdn.example.com"}]
                },
                {
                    "ip_or_fqdn": "example.com",
                    "port": 0,
                    "protocol": "whois",
                    "data": [{"registrar": "GoDaddy", "create_date": "2020-01-01"}]
                }
            ]
        }


class HISACBatchResult(BaseModel):
    """
    Container for multiple H-ISAC results from a scan.
    """
    results: List[HISACResult] = Field(default_factory=list)
    source: str = Field(..., description="Tool/script that generated these results")
    target: Optional[str] = Field(None, description="Original scan target")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    duration_seconds: Optional[float] = Field(None)
    errors: List[str] = Field(default_factory=list)
    
    # Statistics
    total_count: int = Field(default=0)
    by_protocol: Dict[str, int] = Field(default_factory=dict)
    
    def add_result(self, result: HISACResult):
        """Add a result and update stats."""
        self.results.append(result)
        self.total_count = len(self.results)
        self.by_protocol[result.protocol] = self.by_protocol.get(result.protocol, 0) + 1


# =============================================================================
# Tool-Specific Data Schemas (for the 'data' array)
# =============================================================================

class MasscanPortData(BaseModel):
    """Data structure for masscan port results."""
    status: str = "open"
    reason: Optional[str] = None
    reason_ttl: Optional[int] = None
    banner: Optional[str] = None
    service: Optional[str] = None


class MassDNSData(BaseModel):
    """Data structure for massdns DNS results."""
    type: str  # A, AAAA, CNAME, MX, etc.
    data: str  # IP address or hostname


class WhoxyData(BaseModel):
    """Data structure for whoxy WHOIS results."""
    registrar: Optional[str] = None
    registrant_name: Optional[str] = None
    registrant_email: Optional[str] = None
    create_date: Optional[str] = None
    update_date: Optional[str] = None
    expiry_date: Optional[str] = None
    nameservers: Optional[List[str]] = None


class WhoisXMLData(BaseModel):
    """Data structure for WhoisXML IP/CIDR results."""
    cidr: Optional[str] = None
    first_ip: Optional[str] = None
    last_ip: Optional[str] = None
    org_name: Optional[str] = None
    org_email: Optional[str] = None


class OTXData(BaseModel):
    """Data structure for AlienVault OTX results."""
    hostname: str
    record_type: Optional[str] = None
    indicator_type: Optional[str] = None


class VirusTotalData(BaseModel):
    """Data structure for VirusTotal results."""
    subdomain: str
    last_resolved: Optional[str] = None
    positives: Optional[int] = None


class WaybackData(BaseModel):
    """Data structure for Wayback Machine results."""
    url: str
    timestamp: Optional[str] = None
    status_code: Optional[int] = None


class CommonCrawlData(BaseModel):
    """Data structure for CommonCrawl results."""
    url: str
    crawl_index: Optional[str] = None
    mime_type: Optional[str] = None


class M365Data(BaseModel):
    """Data structure for Microsoft 365 domain enumeration."""
    domain: str
    tenant_name: Optional[str] = None
    mdi_instance: Optional[bool] = None


class ASNData(BaseModel):
    """Data structure for ASN lookup results."""
    asn: str
    org_name: Optional[str] = None
    cidr: Optional[str] = None


class CertificateData(BaseModel):
    """Data structure for certificate transparency results."""
    common_name: Optional[str] = None
    issuer: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    san: Optional[List[str]] = None


# =============================================================================
# Conversion Functions: ASMDataModel <-> H-ISAC Format
# =============================================================================

def asm_to_hisac(asm_finding) -> HISACResult:
    """
    Convert ASMDataModel finding to H-ISAC format.
    
    Maps our rich data model to the simple H-ISAC structure.
    """
    from app.schemas.data_sources import ASMDataModel, FindingCategory
    
    # Determine ip_or_fqdn (prefer hostname, fall back to IP)
    ip_or_fqdn = asm_finding.hostname or asm_finding.ip_address or asm_finding.target or ""
    
    # Determine port
    port = asm_finding.port or 0
    
    # Map category to protocol
    protocol_map = {
        FindingCategory.PORT: asm_finding.protocol.value if asm_finding.protocol else "tcp",
        FindingCategory.VULNERABILITY: "vuln",
        FindingCategory.SUBDOMAIN: "subdomain",
        FindingCategory.DOMAIN: "whois",
        FindingCategory.IP_ADDRESS: "ip",
        FindingCategory.CIDR_RANGE: "cidr",
        FindingCategory.ASN: "asn",
        FindingCategory.URL: "http",
        FindingCategory.TECHNOLOGY: "tech",
        FindingCategory.CERTIFICATE: "certificate",
        FindingCategory.DNS_RECORD: "dns",
        FindingCategory.SCREENSHOT: "screenshot",
        FindingCategory.WAYBACK_URL: "wayback",
        FindingCategory.EMAIL: "email",
        FindingCategory.WHOIS: "whois",
    }
    protocol = protocol_map.get(asm_finding.category, "info")
    
    # Build data array based on category
    data = []
    
    if asm_finding.category == FindingCategory.PORT:
        data.append({
            "status": asm_finding.port_state.value if asm_finding.port_state else "open",
            "service": asm_finding.service_name,
            "product": asm_finding.service_product,
            "version": asm_finding.service_version,
            "banner": asm_finding.banner,
        })
    
    elif asm_finding.category == FindingCategory.DNS_RECORD:
        if asm_finding.ip_addresses:
            for ip in asm_finding.ip_addresses:
                data.append({"type": "A", "data": ip})
        if asm_finding.cname:
            data.append({"type": "CNAME", "data": asm_finding.cname})
        if asm_finding.mx_records:
            for mx in asm_finding.mx_records:
                data.append({"type": "MX", "data": mx})
        if asm_finding.ns_records:
            for ns in asm_finding.ns_records:
                data.append({"type": "NS", "data": ns})
        if asm_finding.txt_records:
            for txt in asm_finding.txt_records:
                data.append({"type": "TXT", "data": txt})
    
    elif asm_finding.category == FindingCategory.VULNERABILITY:
        data.append({
            "template_id": asm_finding.template_id,
            "template_name": asm_finding.template_name,
            "severity": asm_finding.severity.value if asm_finding.severity else "info",
            "cve_id": asm_finding.cve_id,
            "cvss_score": asm_finding.cvss_score,
            "description": asm_finding.description,
            "matched_at": asm_finding.matched_at,
        })
    
    elif asm_finding.category in [FindingCategory.DOMAIN, FindingCategory.WHOIS]:
        data.append({
            "registrar": asm_finding.whois_registrar,
            "registrant": asm_finding.whois_registrant,
            "create_date": asm_finding.whois_created_date.isoformat() if asm_finding.whois_created_date else None,
            "expiry_date": asm_finding.whois_expiry_date.isoformat() if asm_finding.whois_expiry_date else None,
            "nameservers": asm_finding.whois_nameservers,
        })
    
    elif asm_finding.category == FindingCategory.CERTIFICATE:
        data.append({
            "issuer": asm_finding.tls_issuer,
            "subject": asm_finding.tls_subject,
            "san": asm_finding.tls_san,
            "not_before": asm_finding.tls_not_before.isoformat() if asm_finding.tls_not_before else None,
            "not_after": asm_finding.tls_not_after.isoformat() if asm_finding.tls_not_after else None,
        })
    
    elif asm_finding.category == FindingCategory.TECHNOLOGY:
        for tech in asm_finding.technologies:
            data.append({"name": tech})
    
    elif asm_finding.category == FindingCategory.URL:
        data.append({
            "url": asm_finding.url,
            "status_code": asm_finding.http_status_code,
            "title": asm_finding.http_title,
            "server": asm_finding.http_server,
            "technologies": asm_finding.technologies,
        })
    
    elif asm_finding.category == FindingCategory.WAYBACK_URL:
        data.append({
            "url": asm_finding.url,
            "archive_url": asm_finding.archive_url,
            "timestamp": asm_finding.archive_timestamp.isoformat() if asm_finding.archive_timestamp else None,
        })
    
    else:
        # Generic data - include raw_json if available
        if asm_finding.raw_json:
            data.append(asm_finding.raw_json)
        else:
            data.append({
                "title": asm_finding.title,
                "description": asm_finding.description,
            })
    
    # Remove None values from data dicts
    data = [{k: v for k, v in d.items() if v is not None} for d in data]
    
    return HISACResult(
        ip_or_fqdn=ip_or_fqdn,
        port=port,
        protocol=protocol,
        data=data,
        source=asm_finding.source.value if hasattr(asm_finding.source, 'value') else str(asm_finding.source),
        timestamp=asm_finding.timestamp,
        organization_id=asm_finding.organization_id,
    )


def hisac_to_asm(hisac_result: HISACResult, source_hint: Optional[str] = None):
    """
    Convert H-ISAC format to ASMDataModel.
    
    Maps the simple H-ISAC structure to our rich data model.
    """
    from app.schemas.data_sources import (
        ASMDataModel, DataSourceType, FindingCategory,
        SeverityLevel, ConfidenceLevel, PortState, Protocol
    )
    
    # Determine source
    source = DataSourceType.MANUAL
    if source_hint:
        try:
            source = DataSourceType(source_hint.lower())
        except ValueError:
            pass
    elif hisac_result.source:
        try:
            source = DataSourceType(hisac_result.source.lower())
        except ValueError:
            pass
    
    # Map protocol to category
    protocol_category_map = {
        "tcp": FindingCategory.PORT,
        "udp": FindingCategory.PORT,
        "dns": FindingCategory.DNS_RECORD,
        "whois": FindingCategory.WHOIS,
        "subdomain": FindingCategory.SUBDOMAIN,
        "certificate": FindingCategory.CERTIFICATE,
        "http": FindingCategory.URL,
        "https": FindingCategory.URL,
        "vuln": FindingCategory.VULNERABILITY,
        "tech": FindingCategory.TECHNOLOGY,
        "wayback": FindingCategory.WAYBACK_URL,
        "commoncrawl": FindingCategory.SUBDOMAIN,
        "asn": FindingCategory.ASN,
        "m365": FindingCategory.DOMAIN,
        "threat_intel": FindingCategory.DOMAIN,
    }
    category = protocol_category_map.get(hisac_result.protocol.lower(), FindingCategory.DOMAIN)
    
    # Determine if ip_or_fqdn is an IP or hostname
    import re
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    is_ip = bool(re.match(ip_pattern, hisac_result.ip_or_fqdn))
    
    hostname = None if is_ip else hisac_result.ip_or_fqdn
    ip_address = hisac_result.ip_or_fqdn if is_ip else None
    
    # Start building the ASM model
    asm_data = {
        "source": source,
        "category": category,
        "target": hisac_result.ip_or_fqdn,
        "hostname": hostname,
        "ip_address": ip_address,
        "port": hisac_result.port if hisac_result.port > 0 else None,
        "timestamp": hisac_result.timestamp or datetime.utcnow(),
        "organization_id": hisac_result.organization_id,
        "raw_json": {"hisac_data": hisac_result.data},
    }
    
    # Set protocol for port findings
    if category == FindingCategory.PORT:
        if hisac_result.protocol.lower() in ["tcp", "udp"]:
            asm_data["protocol"] = Protocol(hisac_result.protocol.lower())
    
    # Extract data based on category
    if hisac_result.data:
        first_data = hisac_result.data[0] if hisac_result.data else {}
        
        if category == FindingCategory.PORT:
            asm_data["port_state"] = PortState(first_data.get("status", "open").lower()) if first_data.get("status") else PortState.OPEN
            asm_data["service_name"] = first_data.get("service")
            asm_data["service_product"] = first_data.get("product")
            asm_data["service_version"] = first_data.get("version")
            asm_data["banner"] = first_data.get("banner")
        
        elif category == FindingCategory.DNS_RECORD:
            ip_addresses = []
            for d in hisac_result.data:
                if d.get("type") == "A":
                    ip_addresses.append(d.get("data"))
                elif d.get("type") == "CNAME":
                    asm_data["cname"] = d.get("data")
                elif d.get("type") == "MX":
                    if "mx_records" not in asm_data:
                        asm_data["mx_records"] = []
                    asm_data["mx_records"].append(d.get("data"))
                elif d.get("type") == "NS":
                    if "ns_records" not in asm_data:
                        asm_data["ns_records"] = []
                    asm_data["ns_records"].append(d.get("data"))
                elif d.get("type") == "TXT":
                    if "txt_records" not in asm_data:
                        asm_data["txt_records"] = []
                    asm_data["txt_records"].append(d.get("data"))
            if ip_addresses:
                asm_data["ip_addresses"] = ip_addresses
                asm_data["ip_address"] = ip_addresses[0]
        
        elif category == FindingCategory.WHOIS:
            asm_data["whois_registrar"] = first_data.get("registrar")
            asm_data["whois_registrant"] = first_data.get("registrant") or first_data.get("registrant_name")
            # Parse dates if they're strings
            for date_field, asm_field in [("create_date", "whois_created_date"), ("expiry_date", "whois_expiry_date")]:
                if first_data.get(date_field):
                    try:
                        asm_data[asm_field] = datetime.fromisoformat(first_data[date_field])
                    except:
                        pass
            if first_data.get("nameservers"):
                asm_data["whois_nameservers"] = first_data["nameservers"]
        
        elif category == FindingCategory.VULNERABILITY:
            asm_data["template_id"] = first_data.get("template_id")
            asm_data["template_name"] = first_data.get("template_name")
            asm_data["cve_id"] = first_data.get("cve_id")
            asm_data["cvss_score"] = first_data.get("cvss_score")
            asm_data["description"] = first_data.get("description")
            asm_data["matched_at"] = first_data.get("matched_at")
            severity_str = first_data.get("severity", "info").lower()
            severity_map = {"critical": SeverityLevel.CRITICAL, "high": SeverityLevel.HIGH, "medium": SeverityLevel.MEDIUM, "low": SeverityLevel.LOW}
            asm_data["severity"] = severity_map.get(severity_str, SeverityLevel.INFO)
        
        elif category == FindingCategory.URL:
            asm_data["url"] = first_data.get("url") or hisac_result.ip_or_fqdn
            asm_data["http_status_code"] = first_data.get("status_code")
            asm_data["http_title"] = first_data.get("title")
            asm_data["http_server"] = first_data.get("server")
            if first_data.get("technologies"):
                asm_data["technologies"] = first_data["technologies"]
        
        elif category == FindingCategory.TECHNOLOGY:
            asm_data["technologies"] = [d.get("name") for d in hisac_result.data if d.get("name")]
    
    # Generate title
    if category == FindingCategory.PORT:
        asm_data["title"] = f"Port {asm_data.get('port', 0)}/{hisac_result.protocol} Open"
    elif category == FindingCategory.SUBDOMAIN:
        asm_data["title"] = f"Subdomain: {asm_data.get('hostname', '')}"
    elif category == FindingCategory.DNS_RECORD:
        asm_data["title"] = f"DNS: {asm_data.get('hostname', '')}"
    else:
        asm_data["title"] = f"{category.value.title()}: {hisac_result.ip_or_fqdn}"
    
    return ASMDataModel(**{k: v for k, v in asm_data.items() if v is not None})


def batch_asm_to_hisac(asm_findings: List, source: str = "asm") -> HISACBatchResult:
    """Convert multiple ASMDataModel findings to H-ISAC batch format."""
    batch = HISACBatchResult(source=source, timestamp=datetime.utcnow())
    
    for finding in asm_findings:
        hisac_result = asm_to_hisac(finding)
        batch.add_result(hisac_result)
    
    return batch


def batch_hisac_to_asm(hisac_batch: HISACBatchResult):
    """Convert H-ISAC batch to list of ASMDataModel findings."""
    findings = []
    for result in hisac_batch.results:
        asm_finding = hisac_to_asm(result, source_hint=hisac_batch.source)
        findings.append(asm_finding)
    return findings


# =============================================================================
# H-ISAC Script Output Parsers
# =============================================================================

def parse_hisac_jsonl(jsonl_content: str, source: Optional[str] = None) -> List[HISACResult]:
    """
    Parse H-ISAC JSON Lines output (one JSON object per line).
    
    This is the format output by the H-ISAC scripts like get_masscan, get_massdns, etc.
    """
    import json
    
    results = []
    for line in jsonl_content.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            result = HISACResult(
                ip_or_fqdn=data.get("ip_or_fqdn", ""),
                port=data.get("port", 0),
                protocol=data.get("protocol", "info"),
                data=data.get("data", []),
                source=source,
            )
            results.append(result)
        except Exception:
            continue
    
    return results


def parse_masscan_hisac(output: str) -> List[HISACResult]:
    """Parse masscan output in H-ISAC format (from get_masscan script)."""
    return parse_hisac_jsonl(output, source="masscan")


def parse_massdns_hisac(output: str) -> List[HISACResult]:
    """Parse massdns output in H-ISAC format (from get_massdns script)."""
    return parse_hisac_jsonl(output, source="massdns")


def parse_whoxy_hisac(output: str) -> List[HISACResult]:
    """Parse whoxy output in H-ISAC format (from get_whoxy script)."""
    return parse_hisac_jsonl(output, source="whoxy")

