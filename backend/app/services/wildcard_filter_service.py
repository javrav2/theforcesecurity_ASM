"""
Wildcard DNS filter (puredns-inspired).

Passive sources (crt.sh, OTX, VT) and brute-force enumeration routinely surface
subdomains that only resolve because the zone has a wildcard record (``*.example.com``).
Those entries pollute every downstream stage: DNS resolution, HTTP probing, port
scanning, takeover detection, vuln scanning.

This module detects the wildcard answer set for a zone and filters out discovered
subdomains whose only resolutions are wildcard IPs. It uses pure dnspython by
default so it runs anywhere, and transparently delegates to the ``puredns`` CLI
when the binary is installed (better at scale, handles NXDOMAIN poisoning).

Usage::

    from app.services.wildcard_filter_service import filter_wildcards

    kept, dropped, wildcard_ips = await filter_wildcards(
        "example.com",
        ["api.example.com", "random123.example.com", ...],
    )
"""

from __future__ import annotations

import asyncio
import logging
import random
import shutil
import string
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import dns.exception
import dns.resolver

logger = logging.getLogger(__name__)


DEFAULT_NAMESERVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]

# How many random probes we send to detect wildcard IPs. 5 is puredns's default
# and gives good signal without hammering resolvers.
WILDCARD_PROBE_COUNT = 5
WILDCARD_PROBE_LABEL_LEN = 16

PUREDNS_BIN = "puredns"


@dataclass
class WildcardProfile:
    """Profile of a zone's wildcard behaviour."""
    zone: str
    wildcard_ips: set[str] = field(default_factory=set)
    wildcard_cnames: set[str] = field(default_factory=set)
    probed: bool = False
    is_wildcard_zone: bool = False

    def matches(self, ips: Iterable[str], cnames: Iterable[str] = ()) -> bool:
        """Return True when every resolution is explained by wildcards."""
        if not self.is_wildcard_zone:
            return False
        ip_set = {ip for ip in ips if ip}
        cname_set = {c.rstrip(".").lower() for c in cnames if c}
        if not ip_set and not cname_set:
            return False
        if ip_set and not ip_set.issubset(self.wildcard_ips):
            return False
        if cname_set and not cname_set.issubset(self.wildcard_cnames):
            # CNAME answer must also match a known wildcard CNAME target.
            return False
        return True


def _puredns_available() -> bool:
    return shutil.which(PUREDNS_BIN) is not None


def _random_label(length: int = WILDCARD_PROBE_LABEL_LEN) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def _make_resolver(nameservers: Optional[list[str]] = None, timeout: float = 3.0) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = nameservers or DEFAULT_NAMESERVERS
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


async def _resolve(
    hostname: str,
    resolver: dns.resolver.Resolver,
) -> tuple[set[str], set[str]]:
    """Resolve a host, returning (A/AAAA IPs, CNAME targets)."""
    loop = asyncio.get_running_loop()

    def _blocking() -> tuple[set[str], set[str]]:
        ips: set[str] = set()
        cnames: set[str] = set()
        for rrtype in ("A", "AAAA"):
            try:
                answer = resolver.resolve(hostname, rrtype, raise_on_no_answer=False)
                if answer.rrset is None:
                    continue
                for rdata in answer:
                    ips.add(rdata.to_text())
                # dnspython exposes the CNAME chain via the canonical_name
                try:
                    canonical = answer.canonical_name.to_text(omit_final_dot=True).lower()
                    if canonical and canonical != hostname.lower().rstrip("."):
                        cnames.add(canonical)
                except Exception:
                    pass
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except dns.exception.Timeout:
                logger.debug("DNS timeout for %s %s", hostname, rrtype)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("DNS error for %s %s: %s", hostname, rrtype, exc)
        return ips, cnames

    return await loop.run_in_executor(None, _blocking)


async def detect_wildcard_profile(
    zone: str,
    nameservers: Optional[list[str]] = None,
    probe_count: int = WILDCARD_PROBE_COUNT,
    timeout: float = 3.0,
) -> WildcardProfile:
    """Probe a zone to learn its wildcard answer set.

    We ask for ``probe_count`` synthetic labels that almost certainly don't exist
    (``<random>.<zone>``) and collect every IP/CNAME that answers. If two or more
    probes return the same IP (or any probe returns at least one IP at all, in
    practice) we treat the zone as a wildcard zone and record the answer set.
    """
    profile = WildcardProfile(zone=zone.rstrip(".").lower())
    resolver = _make_resolver(nameservers, timeout=timeout)

    labels = [f"{_random_label()}.{profile.zone}" for _ in range(max(1, probe_count))]
    responses = await asyncio.gather(*[_resolve(label, resolver) for label in labels])

    hit_count = 0
    for ips, cnames in responses:
        if ips or cnames:
            hit_count += 1
            profile.wildcard_ips.update(ips)
            profile.wildcard_cnames.update(cnames)

    profile.probed = True
    # A single answer can be a positive mis-configuration (a real subdomain
    # accidentally matching our random string) so require at least two matching
    # probes before flagging the zone, unless the CNAME/IP is very distinctive.
    profile.is_wildcard_zone = hit_count >= 2 or (
        hit_count >= 1 and len(profile.wildcard_ips) <= 2 and len(profile.wildcard_ips) > 0
    )

    if profile.is_wildcard_zone:
        logger.info(
            "Wildcard detected for %s: %d IPs (%s), %d CNAMEs",
            zone,
            len(profile.wildcard_ips),
            ", ".join(sorted(profile.wildcard_ips)[:5]),
            len(profile.wildcard_cnames),
        )
    else:
        logger.debug("No wildcard detected for %s", zone)
    return profile


async def filter_wildcards(
    zone: str,
    hostnames: Iterable[str],
    resolved: Optional[dict[str, tuple[set[str], set[str]]]] = None,
    nameservers: Optional[list[str]] = None,
    timeout: float = 3.0,
    concurrency: int = 20,
    profile: Optional[WildcardProfile] = None,
) -> tuple[list[str], list[str], WildcardProfile]:
    """Filter a list of hostnames against the zone's wildcard answer set.

    Args:
        zone: The apex zone (``example.com``). The profile is learned for this zone.
        hostnames: Candidate subdomains to filter.
        resolved: Optional mapping ``{host: (ips, cnames)}`` if the caller has
            already resolved the hostnames. We reuse this to avoid duplicate DNS
            traffic.
        nameservers: Override nameservers.
        timeout: DNS timeout per query.
        concurrency: Max concurrent resolutions when ``resolved`` is not supplied.
        profile: Reuse an existing WildcardProfile for this zone. Recommended
            when filtering multiple batches against the same zone.

    Returns:
        (kept, dropped, profile)
    """
    hostnames = [h for h in hostnames if h]
    if not hostnames:
        profile = profile or WildcardProfile(zone=zone, probed=True)
        return [], [], profile

    profile = profile or await detect_wildcard_profile(zone, nameservers=nameservers, timeout=timeout)
    if not profile.is_wildcard_zone:
        return list(hostnames), [], profile

    resolver = _make_resolver(nameservers, timeout=timeout)
    semaphore = asyncio.Semaphore(concurrency)

    async def _lookup(host: str) -> tuple[str, set[str], set[str]]:
        if resolved is not None and host in resolved:
            ips, cnames = resolved[host]
            return host, set(ips), set(cnames)
        async with semaphore:
            ips, cnames = await _resolve(host, resolver)
        return host, ips, cnames

    results = await asyncio.gather(*[_lookup(h) for h in hostnames])

    kept: list[str] = []
    dropped: list[str] = []
    for host, ips, cnames in results:
        # Keep hosts we can't resolve at all — downstream probing might still
        # find them and we don't want to drop NXDOMAIN + wildcard false negatives.
        if not ips and not cnames:
            kept.append(host)
            continue
        if profile.matches(ips, cnames):
            dropped.append(host)
        else:
            kept.append(host)

    if dropped:
        logger.info(
            "Wildcard filter on %s: kept %d / dropped %d subdomains",
            zone,
            len(kept),
            len(dropped),
        )
    return kept, dropped, profile


async def run_puredns(
    zone: str,
    hostnames: Iterable[str],
    resolvers_file: Optional[str] = None,
    timeout_seconds: int = 300,
) -> tuple[list[str], list[str]]:
    """Shell out to the ``puredns`` binary when installed.

    Returns (kept, dropped). If puredns is unavailable we fall back to the pure
    Python filter. Called directly by the subdomain service when the
    ``use_puredns`` flag is true.
    """
    hostnames = list(hostnames)
    if not hostnames:
        return [], []

    if not _puredns_available():
        logger.debug("puredns binary not found — falling back to dnspython filter")
        kept, dropped, _ = await filter_wildcards(zone, hostnames)
        return kept, dropped

    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "hosts.txt"
        output_path = Path(tmpdir) / "filtered.txt"
        input_path.write_text("\n".join(hostnames))

        cmd = [
            PUREDNS_BIN,
            "resolve",
            str(input_path),
            "--write",
            str(output_path),
            "--quiet",
            "--skip-validation",  # we've already collected live data separately
        ]
        if resolvers_file:
            cmd.extend(["--resolvers", resolvers_file])

        try:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout_seconds,
                ),
            )
        except subprocess.TimeoutExpired:
            logger.warning("puredns timed out after %ss — falling back", timeout_seconds)
            kept, dropped, _ = await filter_wildcards(zone, hostnames)
            return kept, dropped
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("puredns execution failed (%s) — falling back", exc)
            kept, dropped, _ = await filter_wildcards(zone, hostnames)
            return kept, dropped

        if result.returncode != 0:
            logger.warning(
                "puredns returned %d: %s — falling back", result.returncode, result.stderr.strip()
            )
            kept, dropped, _ = await filter_wildcards(zone, hostnames)
            return kept, dropped

        try:
            filtered = [line.strip().lower() for line in output_path.read_text().splitlines() if line.strip()]
        except FileNotFoundError:
            filtered = []

        filtered_set = set(filtered)
        kept = [h for h in hostnames if h.lower() in filtered_set]
        dropped = [h for h in hostnames if h.lower() not in filtered_set]
        logger.info("puredns on %s: kept %d / dropped %d", zone, len(kept), len(dropped))
        return kept, dropped
