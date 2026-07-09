"""
Threat Intelligence — Emerging Vulnerabilities Feed

Surfaces recently-added VulnCheck KEV entries enriched with:
  - Detection coverage (Nuclei templates, PoC availability, remote exploitability)
  - Active exploitation signals (ransomware, threat actors, KEV sources)
  - Oracle OPES analysis when available

Data sources:
  - VulnCheck API          /v3/index/vulncheck-kev          (requires VULNCHECK_API_TOKEN)
  - ProjectDiscovery PDCP  /v1/vulnerability                 (requires PDCP_API_KEY; optional)
  - Our own DB             any existing Oracle enrichment for the CVE
"""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_active_user
from app.models.api_config import ExternalService, resolve_api_key

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

_HTTP_TIMEOUT = 20.0


def _get_vulncheck_token(db: Session, org_id: int | None = None) -> str:
    return resolve_api_key(db, ExternalService.VULNCHECK, org_id) or ""


def _get_pdcp_key(db: Session, org_id: int | None = None) -> str:
    return resolve_api_key(db, ExternalService.PDCP, org_id) or ""


# ── VulnCheck KEV ─────────────────────────────────────────────────────────────

async def _fetch_vulncheck_kev(client: httpx.AsyncClient, days: int, token: str) -> list[dict]:
    """Fetch VulnCheck KEV entries, paginating until the cutoff date is passed.

    Uses cursor-based pagination so the full KEV dataset is available for
    longer time windows. Stops fetching as soon as every entry on the current
    page pre-dates the cutoff (VulnCheck sorts descending by dateAdded).
    """
    if not token:
        return []

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": "aegis-oracle/1.0",
    }
    # days=0 means "all time" — fetch everything
    cutoff = (
        datetime.now(timezone.utc) - timedelta(days=days)
        if days > 0
        else datetime.min.replace(tzinfo=timezone.utc)
    )

    all_entries: list[dict] = []
    cursor: str | None = None
    page_limit = 500  # max VulnCheck allows per page
    max_pages = 10    # safety cap (~5 000 entries)

    for _ in range(max_pages):
        params: dict = {"sort": "dateAdded", "order": "desc", "limit": page_limit}
        if cursor:
            params["cursor"] = cursor

        try:
            resp = await client.get(
                "https://api.vulncheck.com/v3/index/vulncheck-kev",
                headers=headers,
                params=params,
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            payload = resp.json()
        except Exception:
            break

        entries = payload.get("data", []) or []
        if not entries:
            break

        page_done = False
        for entry in entries:
            date_str = entry.get("dateAdded") or entry.get("date_added") or ""
            cves = entry.get("cve", []) or []
            if not cves:
                continue

            try:
                added = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if added < cutoff:
                    page_done = True
                    break
            except ValueError:
                pass

            all_entries.append({
                "cve_id": cves[0] if cves else "",
                "all_cves": cves,
                "date_added": date_str,
                "vendor_project": entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "vulnerability_name": entry.get("vulnerabilityName", ""),
                "short_description": entry.get("shortDescription", ""),
                "known_ransomware_use": entry.get("knownRansomwareUse", "Unknown"),
                "kev_sources": ["vulncheck_kev"],
            })

        if page_done:
            break

        # Follow cursor for next page
        cursor = payload.get("_next") or payload.get("cursor") or payload.get("meta", {}).get("next_cursor")
        if not cursor:
            break

    return all_entries


# ── ProjectDiscovery PDCP (vulnx backend) ────────────────────────────────────

async def _fetch_pdcp_cve(client: httpx.AsyncClient, cve_id: str, pdcp_key: str) -> dict:
    """
    Fetch per-CVE enrichment from ProjectDiscovery Cloud Platform.
    Returns the raw PDCP payload for the CVE, or {} on failure.

    Key fields returned by PDCP that we surface:
      is_template  — Nuclei template exists (detection possible)
      is_poc       — Public proof-of-concept available
      is_remote    — Remotely exploitable
      cvss_score   — CVSS base score
      severity     — critical / high / medium / low
      epss_score   — EPSS probability (informational)
      tags         — vulnerability tags (rce, sqli, xss, etc.)
    """
    if not pdcp_key:
        return {}
    try:
        resp = await client.get(
            f"https://api.projectdiscovery.io/v1/vulnerability/{cve_id}",
            headers={
                "X-Api-Key": pdcp_key,
                "Accept": "application/json",
                "User-Agent": "aegis-oracle/1.0",
            },
            timeout=_HTTP_TIMEOUT,
        )
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return resp.json() or {}
    except Exception:
        return {}


async def _fetch_pdcp_batch(
    client: httpx.AsyncClient, cve_ids: list[str], pdcp_key: str
) -> dict[str, dict]:
    """Fetch PDCP enrichment for a batch of CVEs concurrently."""
    if not pdcp_key or not cve_ids:
        return {}
    tasks = {cve_id: _fetch_pdcp_cve(client, cve_id, pdcp_key) for cve_id in cve_ids}
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    return {
        cve_id: (r if isinstance(r, dict) else {})
        for cve_id, r in zip(tasks.keys(), results)
    }


# ── OTX pulse count ───────────────────────────────────────────────────────────

async def _fetch_otx_pulse_count(client: httpx.AsyncClient, cve_id: str) -> int:
    """Quick OTX pulse count — free, no API key needed."""
    try:
        resp = await client.get(
            f"https://otx.alienvault.com/api/v1/indicator/cve/{cve_id}/general",
            headers={"User-Agent": "aegis-oracle/1.0", "Accept": "application/json"},
            timeout=10.0,
        )
        if resp.status_code != 200:
            return 0
        return resp.json().get("pulse_info", {}).get("count", 0)
    except Exception:
        return 0


async def _fetch_otx_batch(
    client: httpx.AsyncClient, cve_ids: list[str]
) -> dict[str, int]:
    """OTX pulse counts for a batch, concurrently."""
    results = await asyncio.gather(
        *[_fetch_otx_pulse_count(client, cid) for cid in cve_ids],
        return_exceptions=True,
    )
    return {
        cid: (r if isinstance(r, int) else 0)
        for cid, r in zip(cve_ids, results)
    }


# ── DB: Oracle analysis ───────────────────────────────────────────────────────

def _get_oracle_analysis_for_cves(db: Session, cve_ids: list[str]) -> dict[str, dict]:
    """
    Look up any existing Oracle enrichment results for these CVE IDs.
    Returns a map of cve_id → {opes_score, opes_category, delphi_priority, ...}
    """
    if not cve_ids:
        return {}
    try:
        from app.main import Vulnerability  # local import to avoid circular deps

        rows = (
            db.query(
                Vulnerability.cve_id,
                Vulnerability.opes_score,
                Vulnerability.opes_category,
                Vulnerability.delphi_priority,
                Vulnerability.severity,
                Vulnerability.cvss_score,
            )
            .filter(Vulnerability.cve_id.in_(cve_ids))
            .all()
        )
        result: dict[str, dict] = {}
        for row in rows:
            if row.cve_id and row.cve_id not in result:
                result[row.cve_id] = {
                    "opes_score": row.opes_score,
                    "opes_category": row.opes_category,
                    "delphi_priority": row.delphi_priority,
                    "severity": row.severity,
                    "cvss_score": row.cvss_score,
                }
        return result
    except Exception:
        return {}


# ── Synthesis ─────────────────────────────────────────────────────────────────

def _detection_tier(pdcp: dict) -> str:
    """
    Map PDCP flags to a human-readable detection tier.
    The user wants to know: 'can we detect this?'
    """
    is_template = pdcp.get("is_template") or pdcp.get("nuclei_templates")
    is_poc = pdcp.get("is_poc")
    is_remote = pdcp.get("is_remote")

    if is_template:
        return "nuclei_template"   # can auto-detect with Nuclei
    if is_poc:
        return "poc_available"     # PoC exists, can verify manually
    if is_remote:
        return "remote_no_template"  # remotely exploitable, no auto-detection
    return "no_detection"


def _severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _build_entry(
    kev: dict,
    pdcp: dict,
    otx_count: int,
    oracle: dict,
) -> dict:
    cve_id = kev["cve_id"]
    cvss = pdcp.get("cvss_score") or pdcp.get("cvss") or oracle.get("cvss_score")
    severity = (
        pdcp.get("severity")
        or oracle.get("severity")
        or _severity_from_cvss(cvss)
    )
    tags = pdcp.get("tags") or []
    affected = pdcp.get("affected_products") or []

    return {
        "cve_id": cve_id,
        "date_added_kev": kev.get("date_added", ""),
        "vendor_project": kev.get("vendor_project", ""),
        "product": kev.get("product", ""),
        "vulnerability_name": kev.get("vulnerability_name", "") or pdcp.get("name", ""),
        "short_description": kev.get("short_description", "") or pdcp.get("description", ""),
        "known_ransomware_use": kev.get("known_ransomware_use", "Unknown"),
        "kev_sources": kev.get("kev_sources", ["vulncheck_kev"]),

        # Severity / scoring
        "severity": severity,
        "cvss_score": cvss,
        "epss_score": pdcp.get("epss_score"),

        # Detection coverage — the 'can we find this?' answer
        "is_template": bool(pdcp.get("is_template") or pdcp.get("nuclei_templates")),
        "is_poc": bool(pdcp.get("is_poc")),
        "is_remote": bool(pdcp.get("is_remote")),
        "detection_tier": _detection_tier(pdcp),
        "template_count": pdcp.get("template_count") or (1 if pdcp.get("is_template") else 0),

        # Attacker community interest
        "otx_pulse_count": otx_count,
        "otx_active_campaign": otx_count >= 20,

        # Tags / context
        "tags": tags[:10] if tags else [],
        "affected_products": [
            {"vendor": p.get("vendor", ""), "product": p.get("product", "")}
            for p in (affected[:5] if affected else [])
        ],

        # Oracle analysis (if this CVE has been scored already)
        "oracle_analyzed": bool(oracle),
        "opes_score": oracle.get("opes_score"),
        "opes_category": oracle.get("opes_category"),
        "delphi_priority": oracle.get("delphi_priority"),
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/emerging")
async def get_emerging_vulnerabilities(
    days: int = Query(30, ge=0, le=3650, description="KEV entries added in the last N days; 0 = all time"),
    severity: Optional[str] = Query(None, description="Filter by severity (critical,high,medium,low)"),
    detection: Optional[str] = Query(None, description="Filter: nuclei_template | poc_available | remote_no_template | no_detection"),
    limit: int = Query(500, ge=1, le=5000),
    organization_id: Optional[int] = Query(None, description="Org whose stored API keys to use; omit to use any available key"),
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_active_user),
):
    """
    Returns recently-added VulnCheck KEV entries enriched with detection
    coverage from ProjectDiscovery PDCP, OTX pulse counts, and any existing
    Oracle OPES analysis.

    API keys are resolved in order:
      1. Organisation-scoped DB record (Settings → API Keys)
      2. Environment variable fallback (VULNCHECK_API_TOKEN / PDCP_API_KEY)

    Detection tiers (most to least detectable):
      nuclei_template      — Nuclei template exists; auto-detection possible
      poc_available        — Public PoC; manual verification possible
      remote_no_template   — Remotely exploitable but no auto-detection tooling
      no_detection         — No known public detection method
    """
    # Resolve API keys: DB first, env fallback
    vulncheck_token = _get_vulncheck_token(db, organization_id)
    pdcp_key = _get_pdcp_key(db, organization_id)

    async with httpx.AsyncClient() as client:
        kev_entries = await _fetch_vulncheck_kev(client, days, vulncheck_token)

        if not kev_entries:
            return {
                "total": 0,
                "days": days,
                "entries": [],
                "summary": {
                    "total": 0,
                    "with_nuclei_template": 0,
                    "with_poc": 0,
                    "remote_exploitable": 0,
                    "ransomware_associated": 0,
                    "otx_active_campaigns": 0,
                    "oracle_analyzed": 0,
                    "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "vulncheck_configured": bool(vulncheck_token),
                    "pdcp_configured": bool(pdcp_key),
                },
            }

        cve_ids = [e["cve_id"] for e in kev_entries if e["cve_id"]][:limit]

        # Concurrent enrichment: PDCP + OTX in parallel batches
        pdcp_map, otx_map = await asyncio.gather(
            _fetch_pdcp_batch(client, cve_ids, pdcp_key),
            _fetch_otx_batch(client, cve_ids),
        )

    # Oracle DB lookup (sync, local DB — no HTTP)
    oracle_map = _get_oracle_analysis_for_cves(db, cve_ids)

    entries = []
    for kev in kev_entries:
        cve_id = kev.get("cve_id", "")
        if not cve_id or cve_id not in cve_ids:
            continue
        entry = _build_entry(
            kev=kev,
            pdcp=pdcp_map.get(cve_id, {}),
            otx_count=otx_map.get(cve_id, 0),
            oracle=oracle_map.get(cve_id, {}),
        )
        entries.append(entry)

    # Apply filters
    if severity:
        allowed = {s.strip().lower() for s in severity.split(",")}
        entries = [e for e in entries if e.get("severity", "").lower() in allowed]
    if detection:
        allowed_tiers = {d.strip() for d in detection.split(",")}
        entries = [e for e in entries if e.get("detection_tier") in allowed_tiers]

    # Summary stats
    total = len(entries)
    summary = {
        "total": total,
        "with_nuclei_template": sum(1 for e in entries if e["is_template"]),
        "with_poc": sum(1 for e in entries if e["is_poc"]),
        "remote_exploitable": sum(1 for e in entries if e["is_remote"]),
        "ransomware_associated": sum(
            1 for e in entries if e.get("known_ransomware_use", "Unknown") == "Known"
        ),
        "otx_active_campaigns": sum(1 for e in entries if e.get("otx_active_campaign")),
        "oracle_analyzed": sum(1 for e in entries if e.get("oracle_analyzed")),
        "by_severity": {
            "critical": sum(1 for e in entries if e.get("severity") == "critical"),
            "high": sum(1 for e in entries if e.get("severity") == "high"),
            "medium": sum(1 for e in entries if e.get("severity") == "medium"),
            "low": sum(1 for e in entries if e.get("severity") == "low"),
        },
        "vulncheck_configured": bool(vulncheck_token),
        "pdcp_configured": bool(pdcp_key),
    }

    return {
        "total": total,
        "days": days,
        "entries": entries,
        "summary": summary,
    }


@router.get("/cve/{cve_id}")
async def get_cve_detail(
    cve_id: str,
    organization_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_active_user),
):
    """
    Full enrichment for a single CVE: PDCP data + OTX + VulnCheck exploit
    intelligence + any Oracle analysis on record.
    """
    cve_id = cve_id.upper().strip()
    pdcp_key = _get_pdcp_key(db, organization_id)
    async with httpx.AsyncClient() as client:
        pdcp, otx_count = await asyncio.gather(
            _fetch_pdcp_cve(client, cve_id, pdcp_key),
            _fetch_otx_pulse_count(client, cve_id),
        )

    oracle = _get_oracle_analysis_for_cves(db, [cve_id]).get(cve_id, {})

    return {
        "cve_id": cve_id,
        "pdcp": pdcp,
        "otx_pulse_count": otx_count,
        "otx_active_campaign": otx_count >= 20,
        "detection_tier": _detection_tier(pdcp),
        "is_template": bool(pdcp.get("is_template")),
        "is_poc": bool(pdcp.get("is_poc")),
        "is_remote": bool(pdcp.get("is_remote")),
        "oracle": oracle,
    }


@router.get("/stats")
async def get_threat_intel_stats(
    organization_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    _current_user=Depends(get_current_active_user),
):
    """Quick health-check showing which data sources are configured."""
    vulncheck_token = _get_vulncheck_token(db, organization_id)
    pdcp_key = _get_pdcp_key(db, organization_id)
    return {
        "sources": {
            "vulncheck_kev": {
                "configured": bool(vulncheck_token),
                "description": "VulnCheck KEV — recently added exploited vulnerabilities",
                "key_source": "db" if resolve_api_key(db, ExternalService.VULNCHECK, organization_id) else "env",
            },
            "pdcp_vulnx": {
                "configured": bool(pdcp_key),
                "description": "ProjectDiscovery PDCP — Nuclei template & PoC availability",
                "key_source": "db" if resolve_api_key(db, ExternalService.PDCP, organization_id) else "env",
            },
            "otx": {
                "configured": True,
                "description": "AlienVault OTX — free, no API key needed",
                "key_source": "none_required",
            },
        }
    }
