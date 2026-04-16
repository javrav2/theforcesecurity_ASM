"""Normalized finding model (matches platform ingest / Aegis Vanguard bridge shape)."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """A single finding for ingest or DB import."""

    type: str
    source: str
    target: str
    host: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    url: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    severity: str = "info"
    confidence: str = "high"
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    template_id: Optional[str] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    service_product: Optional[str] = None
    banner: Optional[str] = None
    technologies: List[str] = field(default_factory=list)
    state: Optional[str] = None
    is_risky: bool = False
    risk_reason: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None
    takeover_status: Optional[str] = None
    takeover_service: Optional[str] = None
    cname_target: Optional[str] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cert_score: Optional[str] = None
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    ca_type: Optional[str] = None
    cert_expiry_days: Optional[int] = None
    security_headers: Optional[Dict[str, Any]] = None
    cors_policy: Optional[Dict[str, Any]] = None
    mail_records: Optional[Dict[str, Any]] = None
    mail_provider: Optional[str] = None
    email_risk_score: Optional[int] = None
    vendor_name: Optional[str] = None
    vendor_category: Optional[str] = None
    vendor_detection_source: Optional[str] = None

    def to_dict(self) -> dict:
        d = {k: v for k, v in asdict(self).items() if v is not None}
        d["timestamp"] = datetime.now(timezone.utc).isoformat()
        return d
