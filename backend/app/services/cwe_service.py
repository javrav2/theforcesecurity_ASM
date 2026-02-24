"""
CWE (Common Weakness Enumeration) service.

Fetches and caches CWE data from MITRE (https://cwe.mitre.org/data/downloads.html)
to provide weakness names, descriptions, and potential mitigations for remediation guidance.
Uses the official CWE XML download (cwec_latest.xml.zip) when available, with a
fallback list of common CWEs for offline or first-use scenarios.
"""

import io
import logging
import re
import zipfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx
from lxml import etree

logger = logging.getLogger(__name__)

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_VIEW_URL = "https://cwe.mitre.org/data/definitions/{id}.html"


@dataclass
class CWEMitigation:
    """Single potential mitigation from CWE."""
    description: str
    phase: Optional[str] = None
    strategy: Optional[str] = None
    effectiveness: Optional[str] = None


@dataclass
class CWEInfo:
    """CWE entry with name, description, and mitigations."""
    id: str
    name: str
    description: Optional[str] = None
    mitigations: List[CWEMitigation] = field(default_factory=list)
    url: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "mitigations": [
                {
                    "description": m.description,
                    "phase": m.phase,
                    "strategy": m.strategy,
                    "effectiveness": m.effectiveness,
                }
                for m in self.mitigations
            ],
            "url": self.url,
        }


# Fallback: common CWEs with short descriptions and mitigations when XML is unavailable
CWE_FALLBACK: Dict[str, CWEInfo] = {
    "CWE-79": CWEInfo(
        id="CWE-79",
        name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        description="The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page.",
        mitigations=[
            CWEMitigation(description="Use a vetted library or framework that escapes output by default.", phase="Implementation", effectiveness="High"),
            CWEMitigation(description="Use Content Security Policy (CSP) and other defense-in-depth controls.", phase="Architecture and Design", effectiveness="Defense in Depth"),
        ],
        url="https://cwe.mitre.org/data/definitions/79.html",
    ),
    "CWE-89": CWEInfo(
        id="CWE-89",
        name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        description="The software constructs all or part of an SQL command using externally-influenced input, leading to execution of unintended commands.",
        mitigations=[
            CWEMitigation(description="Use parameterized queries or prepared statements.", phase="Implementation", effectiveness="High"),
            CWEMitigation(description="Use ORM frameworks that avoid raw SQL.", phase="Architecture and Design", effectiveness="High"),
        ],
        url="https://cwe.mitre.org/data/definitions/89.html",
    ),
    "CWE-22": CWEInfo(
        id="CWE-22",
        name="Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        description="The software uses external input to construct a pathname that is intended to identify a file or directory, but does not properly neutralize special elements.",
        mitigations=[
            CWEMitigation(description="Use a safe path resolution API and avoid user-controlled paths.", phase="Implementation", effectiveness="High"),
            CWEMitigation(description="Use an allowlist of permitted path basenames.", phase="Implementation", effectiveness="Moderate"),
        ],
        url="https://cwe.mitre.org/data/definitions/22.html",
    ),
    "CWE-284": CWEInfo(
        id="CWE-284",
        name="Improper Access Control",
        description="The software does not restrict or incorrectly restricts access to a resource from an unauthorized actor.",
        mitigations=[
            CWEMitigation(description="Apply principle of least privilege and enforce access checks.", phase="Architecture and Design", effectiveness="High"),
            CWEMitigation(description="Do not expose management interfaces to the internet.", phase="Deployment", effectiveness="High"),
        ],
        url="https://cwe.mitre.org/data/definitions/284.html",
    ),
    "CWE-319": CWEInfo(
        id="CWE-319",
        name="Cleartext Transmission of Sensitive Information",
        description="The software transmits sensitive or security-critical data in cleartext.",
        mitigations=[
            CWEMitigation(description="Use TLS or equivalent for all sensitive communications.", phase="Implementation", effectiveness="High"),
            CWEMitigation(description="Redirect HTTP to HTTPS and enforce HSTS.", phase="Configuration", effectiveness="High"),
        ],
        url="https://cwe.mitre.org/data/definitions/319.html",
    ),
    "CWE-306": CWEInfo(
        id="CWE-306",
        name="Missing Authentication for Critical Function",
        description="The software does not perform any authentication for functionality that requires a user identity.",
        mitigations=[
            CWEMitigation(description="Require authentication for all critical functions.", phase="Architecture and Design", effectiveness="High"),
            CWEMitigation(description="Restrict network access to management interfaces.", phase="Deployment", effectiveness="Defense in Depth"),
        ],
        url="https://cwe.mitre.org/data/definitions/306.html",
    ),
    "CWE-918": CWEInfo(
        id="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        description="The web server receives a URL or similar request from an upstream component and retrieves the contents of this URL, but it does not sufficiently ensure that the request is being sent to the expected destination.",
        mitigations=[
            CWEMitigation(description="Use an allowlist of permitted destinations and block private IP ranges.", phase="Implementation", effectiveness="High"),
            CWEMitigation(description="Segment the network so the server cannot reach internal services.", phase="Architecture and Design", effectiveness="Defense in Depth"),
        ],
        url="https://cwe.mitre.org/data/definitions/918.html",
    ),
    "CWE-200": CWEInfo(
        id="CWE-200",
        name="Exposure of Sensitive Information to an Unauthorized Actor",
        description="The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.",
        mitigations=[
            CWEMitigation(description="Do not expose debug or internal data in production.", phase="Implementation", effectiveness="High"),
            CWEMitigation(description="Restrict access to config files and backups.", phase="Configuration", effectiveness="High"),
        ],
        url="https://cwe.mitre.org/data/definitions/200.html",
    ),
    "CWE-798": CWEInfo(
        id="CWE-798",
        name="Use of Hard-coded Credentials",
        description="The software contains hard-coded credentials, such as a password or cryptographic key.",
        mitigations=[
            CWEMitigation(description="Use a secrets manager or environment variables.", phase="Implementation", effectiveness="High"),
            CWEMitigation(description="Change default credentials before deployment.", phase="Configuration", effectiveness="High"),
        ],
        url="https://cwe.mitre.org/data/definitions/798.html",
    ),
    "CWE-78": CWEInfo(
        id="CWE-78",
        name="Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        description="The software constructs all or part of an OS command using externally-influenced input.",
        mitigations=[
            CWEMitigation(description="Use APIs that avoid shell invocation (e.g. exec without shell).", phase="Implementation", effectiveness="High"),
            CWEMitigation(description="Use an allowlist for permitted values.", phase="Implementation", effectiveness="Moderate"),
        ],
        url="https://cwe.mitre.org/data/definitions/78.html",
    ),
}


def _normalize_cwe_id(raw: Optional[str]) -> Optional[str]:
    """Normalize to CWE-NNN format."""
    if not raw or not isinstance(raw, str):
        return None
    raw = raw.strip().upper().replace("_", "-")
    if not raw.startswith("CWE-"):
        match = re.search(r"(\d+)", raw)
        if match:
            return f"CWE-{match.group(1)}"
        return f"CWE-{raw}" if raw.isdigit() else None
    return raw


def _text(el: Optional[etree._Element]) -> str:
    if el is None:
        return ""
    return (el.text or "").strip() + "".join(
        (e.tail or "").strip() for e in el
    ).strip()


def _parse_mitigation(mit_el: etree._Element) -> CWEMitigation:
    desc_el = mit_el.find(".//{*}Description") or mit_el.find("Description")
    phase_el = mit_el.find(".//{*}Phase") or mit_el.find("Phase")
    strat_el = mit_el.find(".//{*}Strategy") or mit_el.find("Strategy")
    eff_el = mit_el.find(".//{*}Effectiveness") or mit_el.find("Effectiveness")
    return CWEMitigation(
        description=_text(desc_el) or "No description",
        phase=_text(phase_el) or None,
        strategy=_text(strat_el) or None,
        effectiveness=_text(eff_el) or None,
    )


def _parse_weakness(weak_el: etree._Element) -> Optional[CWEInfo]:
    id_attr = weak_el.get("ID")
    if not id_attr:
        return None
    cwe_id = f"CWE-{id_attr}"
    name = weak_el.get("Name") or ""

    desc_el = weak_el.find(".//{*}Description") or weak_el.find("Description")
    if desc_el is not None:
        desc_text = _text(desc_el)
    else:
        sum_el = weak_el.find(".//{*}Summary") or weak_el.find("Summary")
        desc_text = _text(sum_el) if sum_el is not None else ""

    mitigations: List[CWEMitigation] = []
    pm_el = weak_el.find(".//{*}Potential_Mitigations") or weak_el.find("Potential_Mitigations")
    if pm_el is not None:
        for mit_el in pm_el.findall(".//{*}Mitigation") or pm_el.findall("Mitigation"):
            mitigations.append(_parse_mitigation(mit_el))

    return CWEInfo(
        id=cwe_id,
        name=name,
        description=desc_text or None,
        mitigations=mitigations,
        url=CWE_VIEW_URL.format(id=id_attr),
    )


def _load_from_xml_stream(stream: io.BytesIO) -> Dict[str, CWEInfo]:
    """Parse CWE XML (from zip or raw). Returns dict CWE_ID -> CWEInfo."""
    result: Dict[str, CWEInfo] = {}
    try:
        tree = etree.parse(stream)
        root = tree.getroot()
        # CWE XML may use default namespace; find Weakness by local name
        weak_elements = root.xpath("//*[local-name()='Weakness']")
        if not weak_elements:
            weak_elements = root.findall(".//Weakness")

        for w in weak_elements:
            info = _parse_weakness(w)
            if info and info.id:
                result[info.id] = info

        logger.info("CWE service: loaded %d entries from XML", len(result))
    except Exception as e:
        logger.warning("CWE XML parse failed: %s", e)
    return result


class CWEService:
    """Service for CWE data with lazy load from MITRE and in-memory cache."""

    _cache: Dict[str, CWEInfo] = {}
    _loaded: bool = False

    @classmethod
    def _ensure_loaded(cls) -> None:
        if cls._loaded:
            return
        cls._loaded = True
        try:
            with httpx.Client(timeout=30.0) as client:
                r = client.get(CWE_XML_URL)
                r.raise_for_status()
                with zipfile.ZipFile(io.BytesIO(r.content), "r") as zf:
                    names = zf.namelist()
                    xml_name = next((n for n in names if n.endswith(".xml")), names[0] if names else None)
                    if xml_name:
                        with zf.open(xml_name) as f:
                            cls._cache = _load_from_xml_stream(io.BytesIO(f.read()))
        except Exception as e:
            logger.warning("CWE download/parse failed, using fallback: %s", e)
            cls._cache = dict(CWE_FALLBACK)
        if not cls._cache:
            cls._cache = dict(CWE_FALLBACK)

    @classmethod
    def get(cls, cwe_id: Optional[str]) -> Optional[CWEInfo]:
        """Return CWE info for the given ID (e.g. CWE-79 or 79)."""
        normalized = _normalize_cwe_id(cwe_id)
        if not normalized:
            return None
        cls._ensure_loaded()
        return cls._cache.get(normalized) or cls._cache.get(normalized.upper())

    @classmethod
    def get_dict(cls, cwe_id: Optional[str]) -> Optional[dict]:
        """Return CWE info as a dict for API responses."""
        info = cls.get(cwe_id)
        return info.to_dict() if info else None

    @classmethod
    def refresh(cls) -> bool:
        """Force reload from MITRE. Returns True if successful."""
        cls._loaded = False
        cls._cache = {}
        cls._ensure_loaded()
        return len(cls._cache) > 0


def get_cwe_service() -> CWEService:
    return CWEService
