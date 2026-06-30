"""
DNS Threat / DNSBL Service

Checks whether a domain or IP is listed on Spamhaus and other public DNS-based
blocklists (DNSBLs).  All checks are keyless and free.

Blocklists queried:
  Spamhaus:
    - ZEN (SBL + XBL + PBL — combined IP blocklist)
    - DBL (Domain Block List — domains used in spam/malware/phishing)
    - ZRD (Zero Reputation Domains — newly registered, high-risk)
  Barracuda BRBL       — IP spam sources
  SORBS DNSBL          — multi-category IP blocklist
  SpamCop (SCBL)       — IP spam sources
  Abuse.ch SURBL       — domains hosting malware/phishing
  URIBL               — domains in spam URIs

How DNSBLs work:
  For an IP  a.b.c.d  → query  d.c.b.a.<dnsbl-zone>
  For a domain        → query  domain.<dnsbl-zone>
  A successful A-record response (any 127.x.x.x) means the target IS listed.
  NXDOMAIN (no record) means it is NOT listed.

Usage:
    service = DnsThreatService()
    ip_result   = await service.check_ip("1.2.3.4")
    dom_result  = await service.check_domain("malicious.example.com")
    bulk_result = await service.check_bulk(["1.2.3.4", "bad.example.com"])
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DNSBL zones
# ---------------------------------------------------------------------------

# IP-based DNSBLs — query by reversing octets: d.c.b.a.<zone>
_IP_DNSBLS: list[tuple[str, str]] = [
    ("zen.spamhaus.org",    "Spamhaus ZEN (SBL+XBL+PBL)"),
    ("b.barracudacentral.org", "Barracuda BRBL"),
    ("dnsbl.sorbs.net",     "SORBS"),
    ("bl.spamcop.net",      "SpamCop SCBL"),
]

# Domain-based DNSBLs — query by prepending domain: domain.<zone>
_DOMAIN_DNSBLS: list[tuple[str, str]] = [
    ("dbl.spamhaus.org",    "Spamhaus DBL"),
    ("zrd.spamhaus.org",    "Spamhaus ZRD (zero-reputation domain)"),
    ("multi.surbl.org",     "SURBL (malware/phishing domains)"),
    ("multi.uribl.com",     "URIBL"),
]

# Spamhaus ZEN return codes → human-readable meaning
_SPAMHAUS_ZEN_CODES: dict[str, str] = {
    "127.0.0.2": "SBL — Spamhaus Block List (spam source)",
    "127.0.0.3": "SBL — Spamhaus Block List (spam source, CSS)",
    "127.0.0.4": "XBL — Exploits Block List (hijacked/compromised)",
    "127.0.0.5": "XBL — Exploits Block List (botnet C&C)",
    "127.0.0.6": "XBL — Exploits Block List (direct UBE source)",
    "127.0.0.7": "XBL — Exploits Block List (compromised third party)",
    "127.0.0.10": "PBL — Policy Block List (ISP end-user range)",
    "127.0.0.11": "PBL — Policy Block List (ISP end-user range)",
}

_SPAMHAUS_DBL_CODES: dict[str, str] = {
    "127.0.1.2": "spam domain",
    "127.0.1.4": "phishing domain",
    "127.0.1.5": "malware domain",
    "127.0.1.6": "botnet C&C domain",
    "127.0.1.102": "abused legit spam",
    "127.0.1.104": "abused legit phishing",
    "127.0.1.105": "abused legit malware",
    "127.0.1.106": "abused legit botnet C&C",
}

_DNS_TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DnsblHit:
    """A positive match on a specific DNSBL."""
    zone: str
    description: str
    return_code: Optional[str] = None
    return_code_meaning: Optional[str] = None


@dataclass
class DnsThreatResult:
    """Result of a DNSBL threat check for a single target."""
    target: str
    target_type: str  # "ip" or "domain"
    success: bool = False
    error: Optional[str] = None

    # Core verdict
    is_listed: bool = False
    hit_count: int = 0
    hits: list[DnsblHit] = field(default_factory=list)

    # Severity based on which lists matched
    severity: str = "clean"  # clean | low | medium | high | critical

    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "success": self.success,
            "error": self.error,
            "is_listed": self.is_listed,
            "hit_count": self.hit_count,
            "severity": self.severity,
            "hits": [
                {
                    "zone": h.zone,
                    "description": h.description,
                    "return_code": h.return_code,
                    "return_code_meaning": h.return_code_meaning,
                }
                for h in self.hits
            ],
            "checked_at": self.checked_at,
        }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class DnsThreatService:
    """
    Multi-DNSBL threat check for IPs and domains.

    All lookups are pure DNS queries — no API keys, no HTTP calls, no costs.
    DNS resolution is run in a thread pool so the async event loop is not blocked.
    """

    def __init__(self) -> None:
        self._cache: dict[str, DnsThreatResult] = {}

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def check_ip(self, ip: str) -> DnsThreatResult:
        """Check an IP address against all IP-based DNSBLs."""
        ip = ip.strip()
        cache_key = f"ip:{ip}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = DnsThreatResult(target=ip, target_type="ip")

        try:
            ipaddress.ip_address(ip)  # validate
        except ValueError:
            result.error = f"Invalid IP address: {ip}"
            return result

        try:
            reversed_ip = self._reverse_ip(ip)
            tasks = [
                self._query_dnsbl(f"{reversed_ip}.{zone}", zone, desc)
                for zone, desc in _IP_DNSBLS
            ]
            hits = [h for h in await asyncio.gather(*tasks) if h is not None]
            result.hits = hits
            result.hit_count = len(hits)
            result.is_listed = len(hits) > 0
            result.severity = self._compute_severity(hits)
            result.success = True
        except Exception as exc:
            result.error = str(exc)
            logger.warning("DnsThreatService.check_ip(%s) failed: %s", ip, exc)

        self._cache[cache_key] = result
        return result

    async def check_domain(self, domain: str) -> DnsThreatResult:
        """Check a domain against all domain-based DNSBLs."""
        domain = domain.strip().lower().rstrip(".")
        cache_key = f"domain:{domain}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = DnsThreatResult(target=domain, target_type="domain")

        try:
            tasks = [
                self._query_dnsbl(f"{domain}.{zone}", zone, desc)
                for zone, desc in _DOMAIN_DNSBLS
            ]
            hits = [h for h in await asyncio.gather(*tasks) if h is not None]
            result.hits = hits
            result.hit_count = len(hits)
            result.is_listed = len(hits) > 0
            result.severity = self._compute_severity(hits)
            result.success = True
        except Exception as exc:
            result.error = str(exc)
            logger.warning(
                "DnsThreatService.check_domain(%s) failed: %s", domain, exc
            )

        self._cache[cache_key] = result
        return result

    async def check_bulk(
        self,
        targets: list[str],
        max_concurrent: int = 10,
    ) -> dict[str, DnsThreatResult]:
        """
        Check a list of IPs and/or domains.  Target type is auto-detected.
        Returns a dict keyed by the original target string.
        """
        sem = asyncio.Semaphore(max_concurrent)

        async def _check(target: str) -> tuple[str, DnsThreatResult]:
            async with sem:
                try:
                    ipaddress.ip_address(target.strip())
                    is_ip = True
                except ValueError:
                    is_ip = False
                result = (
                    await self.check_ip(target)
                    if is_ip
                    else await self.check_domain(target)
                )
                return target, result

        pairs = await asyncio.gather(*[_check(t) for t in targets], return_exceptions=True)
        return {
            t: r
            for t, r in pairs  # type: ignore[misc]
            if not isinstance(r, BaseException)
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _query_dnsbl(
        self, query_name: str, zone: str, description: str
    ) -> Optional[DnsblHit]:
        """
        Perform a single DNSBL lookup.
        Returns a DnsblHit if listed, None if clean (NXDOMAIN / timeout).
        """
        loop = asyncio.get_event_loop()
        try:
            addrs: list[str] = await asyncio.wait_for(
                loop.run_in_executor(
                    None, lambda: socket.gethostbyname_ex(query_name)[2]
                ),
                timeout=_DNS_TIMEOUT,
            )
            if not addrs:
                return None

            return_code = addrs[0]
            meaning = (
                _SPAMHAUS_ZEN_CODES.get(return_code)
                or _SPAMHAUS_DBL_CODES.get(return_code)
            )
            return DnsblHit(
                zone=zone,
                description=description,
                return_code=return_code,
                return_code_meaning=meaning,
            )
        except (socket.gaierror, asyncio.TimeoutError, OSError):
            # NXDOMAIN or DNS timeout → not listed
            return None
        except Exception as exc:
            logger.debug("DNSBL query %s failed: %s", query_name, exc)
            return None

    @staticmethod
    def _reverse_ip(ip: str) -> str:
        """Reverse IPv4 octets for DNSBL lookup: 1.2.3.4 → 4.3.2.1"""
        return ".".join(reversed(ip.split(".")))

    @staticmethod
    def _compute_severity(hits: list[DnsblHit]) -> str:
        """Compute severity based on which blocklists matched."""
        if not hits:
            return "clean"
        zones = {h.zone for h in hits}
        # Spamhaus ZEN / DBL = authoritative, treat as high
        if "zen.spamhaus.org" in zones or "dbl.spamhaus.org" in zones:
            return "high"
        # SURBL malware/phishing domains = high
        if "multi.surbl.org" in zones:
            return "high"
        # Spamhaus ZRD = medium (newly registered, not confirmed bad yet)
        if "zrd.spamhaus.org" in zones:
            return "medium"
        # Other single-list hits = low
        if len(hits) >= 2:
            return "medium"
        return "low"


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_service: Optional[DnsThreatService] = None


def get_dns_threat_service() -> DnsThreatService:
    global _service
    if _service is None:
        _service = DnsThreatService()
    return _service
