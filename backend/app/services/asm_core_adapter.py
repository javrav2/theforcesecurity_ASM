"""Import asm_scanner_core Finding objects via the same path as agent ingest."""

import logging
from typing import List, Optional

from sqlalchemy.orm import Session

from app.schemas.ingestion import AgentType, IngestionBatchRequest
from app.schemas.unified_results import ConfidenceLevel, ResultType, Severity, UnifiedFinding
from app.services.ingestion_service import process_ingestion_batch

logger = logging.getLogger(__name__)

try:
    from asm_scanner_core.findings import Finding as CoreFinding
except ImportError:
    CoreFinding = None  # type: ignore

_TYPE_MAP = {
    "port": ResultType.PORT,
    "vulnerability": ResultType.VULNERABILITY,
    "subdomain": ResultType.SUBDOMAIN,
    "domain": ResultType.DOMAIN,
    "ip_address": ResultType.IP_ADDRESS,
    "ip_range": ResultType.IP_RANGE,
    "url": ResultType.URL,
    "technology": ResultType.TECHNOLOGY,
    "certificate": ResultType.CERTIFICATE,
    "dns_record": ResultType.DNS_RECORD,
    "screenshot": ResultType.SCREENSHOT,
    "wayback_url": ResultType.WAYBACK_URL,
    "takeover": ResultType.TAKEOVER,
    "tls_analysis": ResultType.TLS_ANALYSIS,
    "security_header": ResultType.SECURITY_HEADER,
    "mail_infrastructure": ResultType.MAIL_INFRASTRUCTURE,
    "third_party_vendor": ResultType.THIRD_PARTY_VENDOR,
}

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.UNKNOWN,
}

_CONF_MAP = {
    "confirmed": ConfidenceLevel.CONFIRMED,
    "high": ConfidenceLevel.HIGH,
    "medium": ConfidenceLevel.MEDIUM,
    "low": ConfidenceLevel.LOW,
}


def core_finding_to_unified(f: "CoreFinding") -> UnifiedFinding:
    """Map shared-package Finding to platform UnifiedFinding."""
    d = f.to_dict()
    d.pop("timestamp", None)
    raw_type = (d.pop("type", None) or "vulnerability").lower()
    d["type"] = _TYPE_MAP.get(raw_type, ResultType.VULNERABILITY)
    sev = (d.get("severity") or "info")
    if isinstance(sev, str):
        d["severity"] = _SEVERITY_MAP.get(sev.lower(), Severity.INFO)
    conf = d.get("confidence")
    if isinstance(conf, str):
        d["confidence"] = _CONF_MAP.get(conf.lower(), ConfidenceLevel.HIGH)
    return UnifiedFinding.model_validate(d)


def ingest_core_findings(
    db: Session,
    organization_id: int,
    findings: List["CoreFinding"],
    *,
    scan_id: Optional[int] = None,
    agent_id: str = "asm-scanner-core",
) -> Optional[dict]:
    """Persist core findings using ingestion pipeline (same as external agents)."""
    if CoreFinding is None:
        logger.warning("asm_scanner_core not installed; skip ingest")
        return None
    if not findings:
        return {"skipped": True, "count": 0}

    unified: List[UnifiedFinding] = []
    for f in findings:
        u = core_finding_to_unified(f)
        if scan_id is not None:
            u.scan_id = scan_id
        unified.append(u)

    req = IngestionBatchRequest(
        agent_id=agent_id,
        agent_type=AgentType.EXTERNAL_SCANNER,
        scan_context=f"asm_scanner_core:{scan_id or 'adhoc'}",
        findings=unified,
    )
    resp = process_ingestion_batch(db, req, organization_id)
    return {
        "created": resp.created,
        "updated": resp.updated,
        "duplicates": resp.duplicates,
        "errors": resp.errors,
        "total": resp.total_submitted,
    }
