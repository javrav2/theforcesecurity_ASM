"""
RIPEstat BGP / ASN Lookup Service

Resolves IP addresses and domains to their BGP prefix, ASN, and network
owner using the RIPEstat REST API (stat.ripe.net).

RIPEstat is keyless, free, and operated by RIPE NCC — the authoritative
Regional Internet Registry for Europe, the Middle East, and Central Asia,
with global coverage via routing data.

This replaces bgpview.io which is no longer operational.

Key use cases in corporate ASM:
  1. Given a discovered IP → find the owning ASN and netblock (Who owns this?)
  2. Given a company name / ASN → enumerate all advertised prefixes (CIDR discovery)
  3. Given a domain → resolve to IP → find BGP context

Endpoints used:
    /data/prefix-overview/data.json?resource=<prefix-or-ip>
    /data/network-info/data.json?resource=<ip-or-asn>
    /data/announced-prefixes/data.json?resource=<ASN>
    /data/as-overview/data.json?resource=<ASN>
    /data/routing-history/data.json?resource=<prefix>&starttime=<>

API docs: https://stat.ripe.net/docs/02.data-api/

Usage:
    service = RIPEstatService()
    result = await service.lookup_ip("1.2.3.4")
    result = await service.lookup_asn("AS15169")
    result = await service.lookup_prefix("1.2.3.0/24")
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import httpx

logger = logging.getLogger(__name__)

_BASE = "https://stat.ripe.net/data"
_TIMEOUT = 20.0
_SOURCE_APP = "judahsecurity-asm"  # RIPEstat asks apps to identify themselves


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BGPPrefix:
    """A single BGP-announced prefix."""
    prefix: str
    timelines: list[dict] = field(default_factory=list)
    is_less_specific: bool = False


@dataclass
class ASNInfo:
    """Overview of an Autonomous System."""
    asn: str
    name: str = ""
    description: str = ""
    country_code: str = ""
    prefixes_v4: list[str] = field(default_factory=list)
    prefixes_v6: list[str] = field(default_factory=list)
    announced_prefixes_count: int = 0


@dataclass
class RIPEstatResult:
    """Unified BGP result for an IP, prefix, or ASN."""
    resource: str
    resource_type: str = "unknown"  # ip | asn | prefix
    success: bool = False
    error: Optional[str] = None

    # IP-level
    ip_address: Optional[str] = None
    covering_prefix: Optional[str] = None
    block_name: Optional[str] = None

    # ASN-level
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    asn_description: Optional[str] = None
    asn_country: Optional[str] = None

    # Prefix-level
    announced_prefixes: list[BGPPrefix] = field(default_factory=list)

    # Flags
    is_bogon: bool = False

    checked_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return {
            "resource": self.resource,
            "resource_type": self.resource_type,
            "success": self.success,
            "error": self.error,
            "ip_address": self.ip_address,
            "covering_prefix": self.covering_prefix,
            "block_name": self.block_name,
            "asn": self.asn,
            "asn_name": self.asn_name,
            "asn_description": self.asn_description,
            "asn_country": self.asn_country,
            "is_bogon": self.is_bogon,
            "announced_prefixes": [
                {"prefix": p.prefix, "is_less_specific": p.is_less_specific}
                for p in self.announced_prefixes
            ],
            "announced_prefixes_count": len(self.announced_prefixes),
            "checked_at": self.checked_at,
        }


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

class RIPEstatService:
    """
    BGP / ASN intelligence via RIPEstat (keyless, free, authoritative).

    All calls include the sourceapp parameter per RIPEstat best practices.
    """

    def __init__(self) -> None:
        self._cache: dict[str, RIPEstatResult] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def lookup_ip(self, ip: str) -> RIPEstatResult:
        """
        Find the BGP prefix and ASN for an IP address.

        Combines /network-info (prefix + ASN number) and /as-overview (ASN name).
        """
        ip = ip.strip()
        cache_key = f"ip:{ip}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = RIPEstatResult(resource=ip, resource_type="ip", ip_address=ip)

        try:
            net_info, asn_info = await asyncio.gather(
                self._get("network-info", ip),
                asyncio.sleep(0),  # placeholder; filled after we know the ASN
            )

            if not net_info or net_info.get("status") != "ok":
                result.error = "RIPEstat network-info returned no data"
                return result

            data = net_info.get("data", {})
            result.covering_prefix = data.get("prefix")
            result.block_name = data.get("block", {}).get("name")

            asns: list[str] = data.get("asns") or []
            if asns:
                result.asn = f"AS{asns[0]}" if not str(asns[0]).startswith("AS") else str(asns[0])

            # Enrich with ASN overview
            if result.asn:
                asn_overview = await self._get(
                    "as-overview", result.asn.lstrip("AS")
                )
                if asn_overview and asn_overview.get("status") == "ok":
                    asn_data = asn_overview.get("data", {})
                    result.asn_name = (
                        asn_data.get("holder")
                        or asn_data.get("name")
                        or ""
                    )
                    result.asn_description = asn_data.get("description", "")

            result.success = True

        except Exception as exc:
            result.error = str(exc)
            logger.warning("RIPEstatService.lookup_ip(%s) failed: %s", ip, exc)

        self._cache[cache_key] = result
        return result

    async def lookup_asn(self, asn: str) -> RIPEstatResult:
        """
        Get overview + all announced prefixes for an ASN.

        Useful for corporate ASM: given "AS15169" find all Google-owned prefixes.
        asn can be "AS15169" or just "15169".
        """
        asn_num = str(asn).upper().lstrip("AS")
        cache_key = f"asn:AS{asn_num}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = RIPEstatResult(
            resource=f"AS{asn_num}",
            resource_type="asn",
            asn=f"AS{asn_num}",
        )

        try:
            overview_resp, prefixes_resp = await asyncio.gather(
                self._get("as-overview", asn_num),
                self._get("announced-prefixes", asn_num),
            )

            if overview_resp and overview_resp.get("status") == "ok":
                d = overview_resp.get("data", {})
                result.asn_name = d.get("holder") or d.get("name") or ""
                result.asn_description = d.get("description", "")
                result.asn_country = d.get("country", "")

            if prefixes_resp and prefixes_resp.get("status") == "ok":
                raw = prefixes_resp.get("data", {}).get("prefixes") or []
                result.announced_prefixes = [
                    BGPPrefix(
                        prefix=p.get("prefix", ""),
                        timelines=p.get("timelines") or [],
                    )
                    for p in raw
                    if p.get("prefix")
                ]

            result.success = True

        except Exception as exc:
            result.error = str(exc)
            logger.warning(
                "RIPEstatService.lookup_asn(%s) failed: %s", asn, exc
            )

        self._cache[cache_key] = result
        return result

    async def lookup_domain(self, domain: str) -> RIPEstatResult:
        """Resolve domain → IP then return BGP context for that IP."""
        domain = domain.strip().lower()
        try:
            loop = asyncio.get_event_loop()
            ip = await loop.run_in_executor(
                None, lambda: socket.gethostbyname(domain)
            )
        except socket.gaierror as exc:
            result = RIPEstatResult(resource=domain, resource_type="ip")
            result.error = f"DNS resolution failed: {exc}"
            return result

        result = await self.lookup_ip(ip)
        result.resource = domain
        result.ip_address = ip
        return result

    async def lookup_prefix(self, prefix: str) -> RIPEstatResult:
        """Get prefix overview and originating ASN(s) for a CIDR prefix."""
        prefix = prefix.strip()
        cache_key = f"prefix:{prefix}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        result = RIPEstatResult(
            resource=prefix, resource_type="prefix", covering_prefix=prefix
        )

        try:
            resp = await self._get("prefix-overview", prefix)
            if not resp or resp.get("status") != "ok":
                result.error = "RIPEstat prefix-overview returned no data"
                return result

            d = resp.get("data", {})
            result.block_name = d.get("block", {}).get("name")
            result.is_bogon = bool(d.get("is_less_specific"))

            asns = d.get("asns") or []
            if asns:
                first = asns[0]
                result.asn = f"AS{first.get('asn', '')}"
                result.asn_name = first.get("holder", "")

            result.success = True

        except Exception as exc:
            result.error = str(exc)
            logger.warning(
                "RIPEstatService.lookup_prefix(%s) failed: %s", prefix, exc
            )

        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _get(self, endpoint: str, resource: str) -> Optional[dict]:
        """
        Call a RIPEstat data endpoint and return the parsed JSON.
        Returns None on error instead of raising.
        """
        url = f"{_BASE}/{endpoint}/data.json"
        params = {"resource": resource, "sourceapp": _SOURCE_APP}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(url, params=params)
            if resp.status_code == 200:
                return resp.json()
            logger.debug(
                "RIPEstat %s/%s returned HTTP %s", endpoint, resource, resp.status_code
            )
        except Exception as exc:
            logger.debug("RIPEstat %s/%s error: %s", endpoint, resource, exc)
        return None


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_service: Optional[RIPEstatService] = None


def get_ripestat_service() -> RIPEstatService:
    global _service
    if _service is None:
        _service = RIPEstatService()
    return _service
