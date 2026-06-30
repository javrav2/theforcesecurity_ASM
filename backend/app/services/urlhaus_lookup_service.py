"""
URLhaus Active Lookup Service

Performs on-demand queries against abuse.ch URLhaus for URLs, domains, IPs,
and file hashes that may be associated with malware distribution infrastructure.

This is distinct from the passive URLhaus feed consumed in the cyber-intel
layer.  The active lookup API lets the agent ask: "Is this specific URL/domain/
hash currently in URLhaus?" during a live recon session.

API: https://urlhaus-api.abuse.ch/v1/
Key: Free auth key from https://auth.abuse.ch/ — stored as URLHAUS_KEY env var.
     The lookup endpoints still work without a key but with stricter rate limits.

Endpoints used:
    POST /url/        — look up a URL
    POST /host/       — look up a domain or IP host
    POST /payload/    — look up a file hash (MD5 / SHA256)

Usage:
    service = URLhausLookupService()
    result = await service.lookup_url("http://malicious.example.com/payload.exe")
    result = await service.lookup_host("malicious.example.com")
    result = await service.lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

_BASE_URL = "https://urlhaus-api.abuse.ch/v1"
_TIMEOUT = 15.0


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class URLhausURLResult:
    """Result for a URL lookup."""
    url: str
    success: bool = False
    error: Optional[str] = None

    # Verdict
    query_status: str = "unknown"   # "is_malware" | "no_results"
    threat: Optional[str] = None    # malware_download, etc.
    url_status: Optional[str] = None  # online | offline | unknown
    date_added: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    payloads: list[dict] = field(default_factory=list)
    reporter: Optional[str] = None
    urlhaus_link: Optional[str] = None
    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def is_malicious(self) -> bool:
        return self.query_status == "is_malware"

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "success": self.success,
            "error": self.error,
            "is_malicious": self.is_malicious,
            "query_status": self.query_status,
            "threat": self.threat,
            "url_status": self.url_status,
            "date_added": self.date_added,
            "tags": self.tags,
            "payloads": self.payloads,
            "reporter": self.reporter,
            "urlhaus_link": self.urlhaus_link,
            "checked_at": self.checked_at,
        }


@dataclass
class URLhausHostResult:
    """Result for a host (domain or IP) lookup."""
    host: str
    success: bool = False
    error: Optional[str] = None

    query_status: str = "unknown"
    urls_count: int = 0
    blacklists: dict = field(default_factory=dict)
    urls: list[dict] = field(default_factory=list)   # up to 10 most recent
    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def is_malicious(self) -> bool:
        return self.query_status == "is_host" and self.urls_count > 0

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "success": self.success,
            "error": self.error,
            "is_malicious": self.is_malicious,
            "query_status": self.query_status,
            "urls_count": self.urls_count,
            "blacklists": self.blacklists,
            "recent_urls": self.urls[:10],
            "checked_at": self.checked_at,
        }


@dataclass
class URLhausHashResult:
    """Result for a file hash lookup."""
    hash_value: str
    success: bool = False
    error: Optional[str] = None

    query_status: str = "unknown"
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    signature: Optional[str] = None
    virustotal_result: Optional[str] = None
    imphash: Optional[str] = None
    urls: list[dict] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def is_malicious(self) -> bool:
        return self.query_status == "is_payload"

    def to_dict(self) -> dict:
        return {
            "hash": self.hash_value,
            "success": self.success,
            "error": self.error,
            "is_malicious": self.is_malicious,
            "query_status": self.query_status,
            "file_type": self.file_type,
            "file_size": self.file_size,
            "signature": self.signature,
            "virustotal_result": self.virustotal_result,
            "distribution_urls": self.urls[:10],
            "checked_at": self.checked_at,
        }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class URLhausLookupService:
    """
    Active URLhaus lookup service.

    Reads URLHAUS_KEY from environment for authenticated requests (fewer
    rate limits).  Degrades gracefully to unauthenticated if key is absent.
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        self._api_key = api_key or os.getenv("URLHAUS_KEY") or ""
        self._cache: dict[str, object] = {}

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"Content-Type": "application/x-www-form-urlencoded"}
        if self._api_key:
            h["Auth-Key"] = self._api_key
        return h

    # ------------------------------------------------------------------
    # URL lookup
    # ------------------------------------------------------------------

    async def lookup_url(self, url: str) -> URLhausURLResult:
        """Check if a specific URL is in URLhaus."""
        url = url.strip()
        cache_key = f"url:{url}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        result = URLhausURLResult(url=url)
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{_BASE_URL}/url/",
                    data={"url": url},
                    headers=self._headers(),
                )
            if resp.status_code != 200:
                result.error = f"URLhaus returned HTTP {resp.status_code}"
                return result

            data = resp.json()
            result.success = True
            result.query_status = data.get("query_status", "unknown")
            result.threat = data.get("threat")
            result.url_status = data.get("url_status")
            result.date_added = data.get("date_added")
            result.tags = data.get("tags") or []
            result.payloads = data.get("payloads") or []
            result.reporter = data.get("reporter")
            result.urlhaus_link = data.get("urlhaus_reference")

        except httpx.TimeoutException:
            result.error = "URLhaus request timed out"
        except Exception as exc:
            result.error = str(exc)
            logger.warning("URLhausLookupService.lookup_url(%s) failed: %s", url, exc)

        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------
    # Host lookup (domain or IP)
    # ------------------------------------------------------------------

    async def lookup_host(self, host: str) -> URLhausHostResult:
        """Check if a domain or IP has hosted malware URLs in URLhaus."""
        host = host.strip().lower()
        cache_key = f"host:{host}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        result = URLhausHostResult(host=host)
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{_BASE_URL}/host/",
                    data={"host": host},
                    headers=self._headers(),
                )
            if resp.status_code != 200:
                result.error = f"URLhaus returned HTTP {resp.status_code}"
                return result

            data = resp.json()
            result.success = True
            result.query_status = data.get("query_status", "unknown")
            result.urls_count = data.get("urls_count") or 0
            result.blacklists = data.get("blacklists") or {}

            raw_urls = data.get("urls") or []
            result.urls = [
                {
                    "url": u.get("url"),
                    "url_status": u.get("url_status"),
                    "date_added": u.get("date_added"),
                    "threat": u.get("threat"),
                    "tags": u.get("tags") or [],
                    "urlhaus_link": u.get("urlhaus_reference"),
                }
                for u in raw_urls[:20]
            ]

        except httpx.TimeoutException:
            result.error = "URLhaus request timed out"
        except Exception as exc:
            result.error = str(exc)
            logger.warning(
                "URLhausLookupService.lookup_host(%s) failed: %s", host, exc
            )

        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------
    # Hash lookup
    # ------------------------------------------------------------------

    async def lookup_hash(self, hash_value: str) -> URLhausHashResult:
        """Check if a file hash (MD5 or SHA256) is in URLhaus payload database."""
        hash_value = hash_value.strip().lower()
        cache_key = f"hash:{hash_value}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        result = URLhausHashResult(hash_value=hash_value)
        hash_type = "sha256_hash" if len(hash_value) == 64 else "md5_hash"

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.post(
                    f"{_BASE_URL}/payload/",
                    data={hash_type: hash_value},
                    headers=self._headers(),
                )
            if resp.status_code != 200:
                result.error = f"URLhaus returned HTTP {resp.status_code}"
                return result

            data = resp.json()
            result.success = True
            result.query_status = data.get("query_status", "unknown")
            result.file_type = data.get("file_type")
            result.file_size = data.get("file_size")
            result.signature = data.get("signature")
            result.virustotal_result = data.get("virustotal")
            result.imphash = data.get("imphash")
            result.urls = [
                {
                    "url": u.get("url"),
                    "url_status": u.get("url_status"),
                    "filename": u.get("filename"),
                    "date_added": u.get("date_added"),
                }
                for u in (data.get("urls") or [])[:20]
            ]

        except httpx.TimeoutException:
            result.error = "URLhaus request timed out"
        except Exception as exc:
            result.error = str(exc)
            logger.warning(
                "URLhausLookupService.lookup_hash(%s) failed: %s", hash_value, exc
            )

        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------
    # Convenience: auto-detect type and dispatch
    # ------------------------------------------------------------------

    async def lookup(self, target: str) -> dict:
        """
        Auto-dispatch: detect whether target is a URL, hash, or host and call
        the appropriate method.  Returns a unified dict with 'type' key.
        """
        target = target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            res = await self.lookup_url(target)
            return {"type": "url", **res.to_dict()}
        if len(target) in (32, 64) and all(c in "0123456789abcdef" for c in target.lower()):
            res = await self.lookup_hash(target)
            return {"type": "hash", **res.to_dict()}
        res = await self.lookup_host(target)
        return {"type": "host", **res.to_dict()}


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_service: Optional[URLhausLookupService] = None


def get_urlhaus_lookup_service() -> URLhausLookupService:
    global _service
    if _service is None:
        _service = URLhausLookupService()
    return _service
