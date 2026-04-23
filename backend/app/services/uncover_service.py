"""
ProjectDiscovery Uncover integration.

Uncover is a multi-engine search CLI that federates queries across
Shodan, Censys, FOFA, Hunter, Quake, ZoomEye, Netlas, CriminalIP, Publicwww
and Odin. This service:

    * Calls the ``uncover`` binary when present (rich query DSL, auth env
      vars discovered automatically from standard locations).
    * Falls back to a subset of direct HTTP calls when the binary is
      missing but API keys are configured.

Results are returned as normalized ``UncoverHit`` rows so downstream
services (asset ingestion, agent tools, scans) can treat them uniformly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional

import httpx

logger = logging.getLogger(__name__)


UNCOVER_BIN = os.environ.get("UNCOVER_BIN", "uncover")


# Supported engine hints. The binary handles many more; this list drives
# our direct-HTTP fallback.
SUPPORTED_ENGINES = [
    "shodan",
    "censys",
    "fofa",
    "hunter",
    "quake",
    "zoomeye",
    "netlas",
    "criminalip",
    "publicwww",
]


@dataclass
class UncoverHit:
    host: str
    port: Optional[int] = None
    engine: str = ""
    raw: dict = field(default_factory=dict)

    def asset_value(self) -> str:
        if self.port and self.port not in (80, 443):
            return f"{self.host}:{self.port}"
        return self.host


@dataclass
class UncoverResult:
    query: str
    engines: list[str]
    hits: list[UncoverHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    used_binary: bool = False


def _have_binary() -> bool:
    return shutil.which(UNCOVER_BIN) is not None


async def _run_binary(
    query: str, engines: list[str], limit: int, timeout: int
) -> tuple[list[UncoverHit], list[str]]:
    args = [
        "-q", query,
        "-silent",
        "-j",
        "-l", str(limit),
    ]
    if engines:
        args.extend(["-e", ",".join(engines)])

    try:
        proc = await asyncio.create_subprocess_exec(
            UNCOVER_BIN, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except Exception as exc:
        return [], [f"binary exec error: {exc}"]

    errs: list[str] = []
    if stderr:
        stderr_text = stderr.decode(errors="ignore")
        if stderr_text:
            errs.append(stderr_text[:500])

    hits: list[UncoverHit] = []
    for line in stdout.decode(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            # Older uncover versions emit plain host:port
            host, _, port = line.partition(":")
            if host:
                hits.append(UncoverHit(
                    host=host,
                    port=int(port) if port.isdigit() else None,
                    engine="unknown",
                    raw={"raw": line},
                ))
            continue

        host = obj.get("host") or obj.get("ip") or ""
        port = obj.get("port")
        engine = obj.get("source") or obj.get("engine") or ""
        if host:
            hits.append(UncoverHit(
                host=host,
                port=int(port) if isinstance(port, int) else (int(port) if str(port).isdigit() else None),
                engine=engine,
                raw=obj,
            ))

    return hits, errs


async def _shodan_direct(
    client: httpx.AsyncClient, query: str, limit: int
) -> tuple[list[UncoverHit], list[str]]:
    token = os.environ.get("SHODAN_API_KEY")
    if not token:
        return [], []
    try:
        r = await client.get(
            "https://api.shodan.io/shodan/host/search",
            params={"key": token, "query": query, "limit": min(limit, 100)},
            timeout=30.0,
        )
        if r.status_code != 200:
            return [], [f"shodan {r.status_code}: {r.text[:200]}"]
        data = r.json()
    except Exception as exc:
        return [], [f"shodan error: {exc}"]
    hits: list[UncoverHit] = []
    for m in data.get("matches", [])[:limit]:
        host = m.get("hostnames", [None])[0] or m.get("ip_str")
        if not host:
            continue
        hits.append(UncoverHit(host=host, port=m.get("port"), engine="shodan", raw=m))
    return hits, []


async def _censys_direct(
    client: httpx.AsyncClient, query: str, limit: int
) -> tuple[list[UncoverHit], list[str]]:
    cid = os.environ.get("CENSYS_API_ID")
    csecret = os.environ.get("CENSYS_API_SECRET")
    if not cid or not csecret:
        return [], []
    try:
        r = await client.post(
            "https://search.censys.io/api/v2/hosts/search",
            auth=(cid, csecret),
            json={"q": query, "per_page": min(limit, 100)},
            timeout=30.0,
        )
        if r.status_code != 200:
            return [], [f"censys {r.status_code}: {r.text[:200]}"]
        data = r.json()
    except Exception as exc:
        return [], [f"censys error: {exc}"]
    hits: list[UncoverHit] = []
    for hit in data.get("result", {}).get("hits", [])[:limit]:
        host = hit.get("name") or hit.get("ip")
        if not host:
            continue
        services = hit.get("services", [{}])
        port = services[0].get("port") if services else None
        hits.append(UncoverHit(host=host, port=port, engine="censys", raw=hit))
    return hits, []


async def run_uncover(
    query: str,
    engines: Optional[list[str]] = None,
    limit: int = 100,
    timeout: int = 120,
) -> UncoverResult:
    start = datetime.utcnow()
    engines = engines or ["shodan", "censys", "fofa"]
    result = UncoverResult(query=query, engines=engines)

    if _have_binary():
        hits, errs = await _run_binary(query, engines, limit, timeout)
        result.hits = hits
        result.errors = errs
        result.used_binary = True
        result.duration_seconds = (datetime.utcnow() - start).total_seconds()
        return result

    # Fallback: direct HTTP for engines we understand
    async with httpx.AsyncClient(verify=True) as client:
        tasks = []
        for e in engines:
            if e == "shodan":
                tasks.append(_shodan_direct(client, query, limit))
            elif e == "censys":
                tasks.append(_censys_direct(client, query, limit))
            else:
                result.errors.append(
                    f"engine '{e}' requires the uncover binary (direct HTTP not implemented)"
                )

        outs = await asyncio.gather(*tasks, return_exceptions=True)
        for o in outs:
            if isinstance(o, Exception):
                result.errors.append(f"engine failure: {o}")
                continue
            hits, errs = o
            result.hits.extend(hits)
            result.errors.extend(errs)

    result.duration_seconds = (datetime.utcnow() - start).total_seconds()
    return result


# ---------------------------------------------------------------------------
# Persistence helper
# ---------------------------------------------------------------------------


def persist_uncover_assets(
    db,
    organization_id: int,
    result: UncoverResult,
    scan_id: Optional[int] = None,
) -> int:
    """Materialize uncover hits as Asset rows. Returns count created."""
    from app.models.asset import Asset, AssetType, AssetStatus

    created = 0
    seen: set[str] = set()
    for h in result.hits:
        value = h.asset_value()
        if not value or value in seen:
            continue
        seen.add(value)
        existing = (
            db.query(Asset)
            .filter(
                Asset.organization_id == organization_id,
                Asset.value == value,
            )
            .first()
        )
        if existing:
            existing.last_seen = datetime.utcnow()
            continue
        asset = Asset(
            organization_id=organization_id,
            asset_type=AssetType.IP if _looks_like_ip(h.host) else AssetType.DOMAIN,
            name=value,
            value=value,
            discovery_source=f"uncover:{h.engine or 'unknown'}",
            status=AssetStatus.DISCOVERED if hasattr(AssetStatus, "DISCOVERED") else AssetStatus.ACTIVE,
        )
        db.add(asset)
        created += 1
    db.commit()
    return created


def _looks_like_ip(s: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False
