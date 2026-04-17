"""
Atlas - Aegis Vanguard's attack-surface cartographer.

Atlas was the titan condemned to hold up the heavens, often depicted mapping
the world. Here he wraps Praetorian's `pius` CLI (24+ OSINT plugins across
certificate transparency, passive DNS, WHOIS/RDAP, all 5 RIRs, GLEIF, BGP)
to map an organization's external domains, subdomains, and IP netblocks.

The wrapper shape and normalized Finding output are defined in
`scanners/pius.py`; this module is the public Aegis-branded entry point.
"""

from __future__ import annotations

from typing import List, Optional

from asm_scanner_core.findings import Finding
from asm_scanner_core.scanners.pius import PiusResult as _PiusResult, run_pius as _run_pius

AtlasResult = _PiusResult  # same shape; re-exported under the Aegis brand


def run_atlas(
    org: str,
    *,
    domain: Optional[str] = None,
    asn: Optional[str] = None,
    mode: str = "passive",
    plugins: Optional[List[str]] = None,
    disable: Optional[List[str]] = None,
    concurrency: int = 5,
    timeout: int = 900,
    binary: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> AtlasResult:
    """
    Map an organization's external attack surface from just a company name.

    Discovers domains, subdomains, and CIDR blocks. Passive mode is default
    (safe for continuous monitoring); pass `mode='active'` to also include
    DNS brute-force and zone transfer plugins.
    """
    return _run_pius(
        org=org,
        domain=domain,
        asn=asn,
        mode=mode,
        plugins=plugins,
        disable=disable,
        concurrency=concurrency,
        timeout=timeout,
        binary=binary,
        extra_args=extra_args,
    )


__all__ = ["run_atlas", "AtlasResult", "Finding"]
