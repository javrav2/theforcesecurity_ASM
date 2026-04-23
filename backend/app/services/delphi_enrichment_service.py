"""
Delphi - CISA KEV + FIRST EPSS Enrichment Service.

Delphi was the ancient Greek oracle — the place you went to ask "which of
these threats should I actually worry about?" This service answers the same
question for vulnerabilities.

It enriches every CVE finding in the platform with two authoritative signals
that prioritise vulnerabilities far better than CVSS alone:

  1. **CISA KEV** (Known Exploited Vulnerabilities Catalog) — a curated list
     published by CISA of CVEs that are confirmed to be exploited in the
     wild right now. Inclusion in KEV is the single strongest signal that a
     vulnerability is not theoretical.

  2. **FIRST EPSS** (Exploit Prediction Scoring System) — a probabilistic
     model published daily by FIRST.org that scores every public CVE with
     the probability (0.0–1.0) that it will be exploited in the next 30
     days, plus a percentile rank within the whole CVE universe.

Together they turn a 100,000-CVE haystack into a short list of "exploit now"
and "exploit soon" findings.

Data sources:
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    https://epss.cyentia.com/epss_scores-current.csv.gz

Both feeds are downloaded on demand into a small on-disk cache and re-fetched
after `DELPHI_REFRESH_HOURS`. No API keys required; both are public.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import os
import threading
import time
import urllib.request
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)

# Public, no-auth endpoints
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# EPSS percentile thresholds used to bucket findings for humans.
# These ranges come directly from the EPSS "interpretation" guidance on first.org.
EPSS_BUCKETS: List[Tuple[float, str]] = [
    (0.95, "imminent"),    # top 5%  — act now
    (0.80, "high"),        # top 20% — prioritise
    (0.50, "elevated"),    # top half
    (0.20, "moderate"),
    (0.0, "low"),
]


def _epss_bucket(percentile: float) -> str:
    for threshold, label in EPSS_BUCKETS:
        if percentile >= threshold:
            return label
    return "low"


def _cache_dir() -> str:
    path = os.environ.get("DELPHI_CACHE_DIR") or "/tmp/delphi_cache"
    os.makedirs(path, exist_ok=True)
    return path


def _http_get(url: str, *, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "theforce-asm-delphi/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - static public URLs
        return resp.read()


class DelphiEnrichmentService:
    """
    CISA KEV + EPSS enrichment. Lazy-loaded on first call and refreshed when
    the on-disk cache is older than DELPHI_REFRESH_HOURS.
    """

    def __init__(self) -> None:
        self.enabled: bool = getattr(settings, "DELPHI_ENRICHMENT_ENABLED", True)
        self.refresh_hours: int = int(getattr(settings, "DELPHI_REFRESH_HOURS", 24))
        self._kev: Dict[str, Dict[str, Any]] = {}
        self._kev_meta: Dict[str, Any] = {}
        self._epss: Dict[str, Dict[str, float]] = {}
        self._epss_date: Optional[str] = None
        self._last_load_ts: float = 0.0
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Cache / loading
    # ------------------------------------------------------------------

    def _kev_cache_path(self) -> str:
        return os.path.join(_cache_dir(), "cisa_kev.json")

    def _epss_cache_path(self) -> str:
        return os.path.join(_cache_dir(), "epss_scores_current.csv")

    def _cache_fresh(self, path: str) -> bool:
        if not os.path.exists(path):
            return False
        age_hours = (time.time() - os.path.getmtime(path)) / 3600.0
        return age_hours < self.refresh_hours

    def _fetch_kev(self, force: bool = False) -> None:
        path = self._kev_cache_path()
        if not force and self._cache_fresh(path):
            return
        try:
            raw = _http_get(KEV_URL, timeout=60)
            with open(path, "wb") as fh:
                fh.write(raw)
            logger.info("Delphi: refreshed CISA KEV cache (%d bytes)", len(raw))
        except Exception as exc:
            logger.warning("Delphi: KEV fetch failed (%s); using stale cache if present", exc)

    def _fetch_epss(self, force: bool = False) -> None:
        path = self._epss_cache_path()
        if not force and self._cache_fresh(path):
            return
        try:
            raw = _http_get(EPSS_URL, timeout=120)
            # EPSS is gzipped CSV
            try:
                decompressed = gzip.decompress(raw)
            except OSError:
                # Served as plain CSV
                decompressed = raw
            with open(path, "wb") as fh:
                fh.write(decompressed)
            logger.info("Delphi: refreshed EPSS cache (%d bytes decompressed)", len(decompressed))
        except Exception as exc:
            logger.warning("Delphi: EPSS fetch failed (%s); using stale cache if present", exc)

    def _load_kev(self) -> None:
        path = self._kev_cache_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            vulns = data.get("vulnerabilities") or []
            mapped: Dict[str, Dict[str, Any]] = {}
            for entry in vulns:
                cve = (entry.get("cveID") or "").strip().upper()
                if not cve:
                    continue
                mapped[cve] = {
                    "cve_id": cve,
                    "vendor_project": entry.get("vendorProject"),
                    "product": entry.get("product"),
                    "vulnerability_name": entry.get("vulnerabilityName"),
                    "date_added": entry.get("dateAdded"),
                    "short_description": entry.get("shortDescription"),
                    "required_action": entry.get("requiredAction"),
                    "due_date": entry.get("dueDate"),
                    "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
                    "notes": entry.get("notes"),
                    "cwes": entry.get("cwes"),
                }
            self._kev = mapped
            self._kev_meta = {
                "catalog_version": data.get("catalogVersion"),
                "date_released": data.get("dateReleased"),
                "count": data.get("count") or len(mapped),
            }
            logger.info("Delphi: loaded %d KEV entries", len(mapped))
        except Exception as exc:
            logger.error("Delphi: KEV parse failed: %s", exc)

    def _load_epss(self) -> None:
        path = self._epss_cache_path()
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                # EPSS file begins with a comment line: "#model_version:...,score_date:..."
                text = fh.read()
            lines = text.splitlines()
            # Extract date from header if present
            self._epss_date = None
            data_start = 0
            for i, line in enumerate(lines):
                if line.startswith("#"):
                    if "score_date:" in line:
                        self._epss_date = line.split("score_date:", 1)[1].split(",")[0].strip()
                    data_start = i + 1
                else:
                    data_start = i
                    break

            reader = csv.DictReader(lines[data_start:])
            mapped: Dict[str, Dict[str, float]] = {}
            for row in reader:
                cve = (row.get("cve") or "").strip().upper()
                if not cve:
                    continue
                try:
                    score = float(row.get("epss") or 0.0)
                    percentile = float(row.get("percentile") or 0.0)
                except ValueError:
                    continue
                mapped[cve] = {"score": score, "percentile": percentile}
            self._epss = mapped
            logger.info("Delphi: loaded %d EPSS entries (date=%s)", len(mapped), self._epss_date)
        except Exception as exc:
            logger.error("Delphi: EPSS parse failed: %s", exc)

    def ensure_loaded(self, force_refresh: bool = False) -> None:
        """Lazy-load or refresh both feeds. Safe to call on every enrich()."""
        with self._lock:
            already_loaded = bool(self._kev) and bool(self._epss)
            if already_loaded and not force_refresh:
                age = time.time() - self._last_load_ts
                if age < self.refresh_hours * 3600:
                    return
            self._fetch_kev(force=force_refresh)
            self._fetch_epss(force=force_refresh)
            self._load_kev()
            self._load_epss()
            self._last_load_ts = time.time()

    # ------------------------------------------------------------------
    # Public lookup / enrichment API
    # ------------------------------------------------------------------

    def _normalize_cve(self, cve_id: str) -> str:
        if not cve_id:
            return ""
        s = cve_id.strip().upper()
        if not s.startswith("CVE-"):
            s = f"CVE-{s}"
        return s

    def lookup(self, cve_id: str) -> Dict[str, Any]:
        """
        Look up KEV + EPSS signals for a single CVE.

        Returns a dict with keys:
            cve_id, kev (obj|None), epss {score, percentile, bucket}|None,
            priority (one of: critical, high, medium, low, none),
            priority_reason (human string explaining the priority choice)
        """
        cve = self._normalize_cve(cve_id)
        if not self.enabled or not cve:
            return {"cve_id": cve, "enriched": False, "reason": "disabled_or_empty"}

        self.ensure_loaded()

        kev_entry = self._kev.get(cve)
        epss_entry = self._epss.get(cve)

        epss_out = None
        if epss_entry:
            epss_out = {
                "score": round(epss_entry["score"], 6),
                "percentile": round(epss_entry["percentile"], 6),
                "bucket": _epss_bucket(epss_entry["percentile"]),
                "date": self._epss_date,
            }

        priority, reason = self._derive_priority(kev_entry, epss_entry)

        return {
            "cve_id": cve,
            "enriched": bool(kev_entry or epss_entry),
            "kev": kev_entry,
            "epss": epss_out,
            "priority": priority,
            "priority_reason": reason,
        }

    def _derive_priority(
        self, kev: Optional[Dict[str, Any]], epss: Optional[Dict[str, float]]
    ) -> Tuple[str, str]:
        """
        Collapse KEV + EPSS into a single prioritised bucket.

        critical   → on CISA KEV (actively exploited)
        high       → EPSS percentile ≥ 0.95 (top 5%)
        medium     → EPSS percentile ≥ 0.80 (top 20%) or known ransomware CVE
        low        → EPSS percentile ≥ 0.20
        none       → everything else (no exploit signal)
        """
        if kev:
            ransom = (kev.get("known_ransomware_use") or "").strip().lower()
            base = "critical"
            if ransom in ("known", "yes", "true"):
                return base, "On CISA KEV with known ransomware campaign use"
            return base, "On CISA KEV (actively exploited)"

        if epss:
            p = float(epss.get("percentile") or 0)
            s = float(epss.get("score") or 0)
            if p >= 0.95:
                return "high", f"Top 5% EPSS (percentile={p:.2%}, score={s:.3f})"
            if p >= 0.80:
                return "medium", f"Top 20% EPSS (percentile={p:.2%}, score={s:.3f})"
            if p >= 0.20:
                return "low", f"Moderate EPSS (percentile={p:.2%}, score={s:.3f})"
            return "none", f"Low EPSS (percentile={p:.2%}, score={s:.3f})"

        return "none", "No KEV or EPSS signal"

    def enrich_vulnerability(self, vulnerability) -> Dict[str, Any]:
        """
        Enrich a Vulnerability ORM object in-place on its metadata_.

        Returns the lookup dict (regardless of whether it was persisted).
        """
        cve = getattr(vulnerability, "cve_id", None)
        if not cve:
            return {"enriched": False, "reason": "no_cve_id"}

        lookup = self.lookup(cve)
        if not lookup.get("enriched"):
            return lookup

        meta = dict(vulnerability.metadata_ or {})
        meta["delphi"] = {
            "kev": lookup.get("kev"),
            "epss": lookup.get("epss"),
            "priority": lookup.get("priority"),
            "priority_reason": lookup.get("priority_reason"),
            "enriched_at": datetime.utcnow().isoformat(),
        }
        vulnerability.metadata_ = meta

        # Append a discovery tag for filtering in the findings UI.
        tags = list(vulnerability.tags or [])
        if lookup.get("kev") and "cisa-kev" not in tags:
            tags.append("cisa-kev")
            if (lookup.get("kev") or {}).get("known_ransomware_use", "").lower() in ("known", "yes"):
                if "ransomware" not in tags:
                    tags.append("ransomware")
        if lookup.get("epss"):
            bucket_tag = f"epss-{lookup['epss']['bucket']}"
            if bucket_tag not in tags:
                tags.append(bucket_tag)
        priority_tag = f"delphi-priority-{lookup.get('priority', 'none')}"
        if priority_tag not in tags and lookup.get("priority") not in ("none", None):
            tags.append(priority_tag)
        vulnerability.tags = tags

        return lookup

    def enrich_and_update(self, vulnerability_id: int) -> Dict[str, Any]:
        """Load a vulnerability, enrich it, persist, and return the lookup."""
        from app.db.database import SessionLocal
        from app.models.vulnerability import Vulnerability

        db = SessionLocal()
        try:
            vuln = db.query(Vulnerability).filter(Vulnerability.id == vulnerability_id).first()
            if not vuln:
                return {"error": "Vulnerability not found"}
            result = self.enrich_vulnerability(vuln)
            db.commit()
            return result
        except Exception as exc:
            logger.error("Delphi enrich_and_update failed: %s", exc)
            db.rollback()
            return {"error": str(exc)}
        finally:
            db.close()

    def batch_enrich(self, organization_id: int, *, limit: Optional[int] = None) -> Dict[str, Any]:
        """Enrich every CVE-bearing vulnerability for an organization."""
        from app.db.database import SessionLocal
        from app.models.asset import Asset
        from app.models.vulnerability import Vulnerability

        db = SessionLocal()
        try:
            q = (
                db.query(Vulnerability)
                .join(Asset, Vulnerability.asset_id == Asset.id)
                .filter(Asset.organization_id == organization_id)
                .filter(Vulnerability.cve_id.isnot(None))
            )
            if limit:
                q = q.limit(limit)
            vulns = q.all()

            kev_hits = 0
            epss_hits = 0
            no_signal = 0
            errors = 0

            for vuln in vulns:
                try:
                    out = self.enrich_vulnerability(vuln)
                    if out.get("kev"):
                        kev_hits += 1
                    if out.get("epss"):
                        epss_hits += 1
                    if not out.get("enriched"):
                        no_signal += 1
                except Exception as exc:
                    errors += 1
                    logger.debug("Delphi enrich failed on vuln %s: %s", vuln.id, exc)

            db.commit()
            return {
                "total": len(vulns),
                "kev_hits": kev_hits,
                "epss_hits": epss_hits,
                "no_signal": no_signal,
                "errors": errors,
            }
        except Exception as exc:
            logger.error("Delphi batch_enrich failed: %s", exc)
            db.rollback()
            return {"error": str(exc)}
        finally:
            db.close()

    def stats(self) -> Dict[str, Any]:
        """Return catalog stats for /delphi/status."""
        self.ensure_loaded()
        return {
            "enabled": self.enabled,
            "kev_entries": len(self._kev),
            "epss_entries": len(self._epss),
            "epss_score_date": self._epss_date,
            "kev_catalog_version": self._kev_meta.get("catalog_version"),
            "kev_date_released": self._kev_meta.get("date_released"),
            "refresh_hours": self.refresh_hours,
            "last_loaded": datetime.utcfromtimestamp(self._last_load_ts).isoformat() if self._last_load_ts else None,
        }

    def refresh(self) -> Dict[str, Any]:
        """Force a cache refresh of both feeds."""
        self.ensure_loaded(force_refresh=True)
        return self.stats()


# Global singleton
_delphi_service: Optional[DelphiEnrichmentService] = None


def get_delphi_service() -> DelphiEnrichmentService:
    global _delphi_service
    if _delphi_service is None:
        _delphi_service = DelphiEnrichmentService()
    return _delphi_service
