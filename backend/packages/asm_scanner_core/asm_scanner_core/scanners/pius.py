"""
Praetorian Pius attack surface / asset discovery wrapper.

CLI: https://github.com/praetorian-inc/pius

Typical invocation:
    pius run --org "Acme Corp" --domain acme.com --output ndjson --mode passive

NDJSON output: one object per line with keys like:
    {"type": "domain", "value": "api.acme.com", "source": "crt-sh", "confidence": 0.85}
    {"type": "cidr",   "value": "203.0.113.0/24", "source": "arin"}
    {"type": "domain", "value": "acme.com", "source": "reverse-whois", "needs_review": true, "confidence": 0.42}

Real pius NDJSON schemas have varied across releases; the parser is defensive.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

from asm_scanner_core.findings import Finding
from asm_scanner_core.runner import run_command, which

logger = logging.getLogger(__name__)


@dataclass
class PiusResult:
    findings: List[Finding] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    cidrs: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_stdout: str = ""


_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


def _as_asset_type(value: str, declared_type: Optional[str]) -> str:
    if declared_type:
        t = declared_type.lower()
        if t in ("cidr", "ip_range", "netblock"):
            return "ip_range"
        if t == "ip" or t == "ip_address":
            return "ip_address"
        if t in ("domain", "subdomain", "host"):
            pass  # fall through to detection below
    try:
        ipaddress.ip_network(value, strict=False)
        if "/" in value:
            return "ip_range"
        return "ip_address"
    except ValueError:
        pass
    if _DOMAIN_RE.match(value):
        return "subdomain" if value.count(".") > 1 else "domain"
    return "domain"


def _parse_ndjson(text: str) -> List[dict]:
    out: List[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def run_pius(
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
) -> PiusResult:
    """
    Run pius organizational discovery and return parsed findings.

    Args:
        org: Organization name (required).
        domain: Optional domain hint to unlock crt-sh / DNS plugins.
        asn: Optional ASN (e.g. 'AS12345') to query BGP directly.
        mode: 'passive' (default), 'active', or 'all'.
        plugins: Optional plugin whitelist.
        disable: Optional plugin blacklist.
        concurrency: --concurrency value.
        timeout: Max seconds to wait.
        binary: Override pius binary path (else PIUS_PATH env or PATH lookup).
        extra_args: Additional CLI flags appended to the run command.
    """
    result = PiusResult()
    binary = binary or os.environ.get("PIUS_PATH") or which("pius")
    if not binary:
        result.errors.append("pius not found on PATH and PIUS_PATH not set")
        logger.info("pius not installed; skip")
        return result
    if not org or not org.strip():
        result.errors.append("pius requires --org")
        return result

    cmd = [binary, "run", "--org", org, "--output", "ndjson", "--mode", mode, "--concurrency", str(concurrency)]
    if domain:
        cmd.extend(["--domain", domain])
    if asn:
        cmd.extend(["--asn", asn])
    if plugins:
        cmd.extend(["--plugins", ",".join(plugins)])
    if disable:
        cmd.extend(["--disable", ",".join(disable)])
    if extra_args:
        cmd.extend([str(x) for x in extra_args])

    res = run_command(cmd, timeout=timeout)
    result.raw_stdout = res.stdout
    if res.exit_code != 0 and not res.stdout:
        result.errors.append(f"pius exit {res.exit_code}: {(res.stderr or '').strip()[:500]}")
        return result

    seen: set[str] = set()
    for obj in _parse_ndjson(res.stdout):
        declared = (obj.get("type") or obj.get("Type") or "").lower()
        value = obj.get("value") or obj.get("Value") or obj.get("name") or obj.get("host") or obj.get("cidr")
        if not value or not isinstance(value, str):
            continue
        value = value.strip().rstrip(".")
        if not value or value in seen:
            continue
        seen.add(value)

        asset_type = _as_asset_type(value, declared)
        source_plugin = obj.get("source") or obj.get("plugin") or obj.get("Source") or "pius"
        confidence = obj.get("confidence") or obj.get("Confidence")
        needs_review = bool(obj.get("needs_review") or obj.get("NeedsReview"))
        conf_str = "high"
        if isinstance(confidence, (int, float)):
            if confidence >= 0.75:
                conf_str = "high"
            elif confidence >= 0.5:
                conf_str = "medium"
            else:
                conf_str = "low"

        tags = ["atlas", "pius", f"plugin:{source_plugin}"]
        if needs_review:
            tags.append("needs-review")

        if asset_type == "ip_range":
            result.cidrs.append(value)
            result.findings.append(
                Finding(
                    type="ip_range",
                    source=f"atlas:{source_plugin}",
                    target=value,
                    title=f"CIDR: {value}",
                    severity="info",
                    confidence=conf_str,
                    tags=tags,
                    raw_data=obj,
                )
            )
        elif asset_type == "ip_address":
            result.findings.append(
                Finding(
                    type="ip_address",
                    source=f"atlas:{source_plugin}",
                    target=value,
                    ip=value,
                    title=f"IP: {value}",
                    severity="info",
                    confidence=conf_str,
                    tags=tags,
                    raw_data=obj,
                )
            )
        else:
            is_sub = asset_type == "subdomain"
            (result.subdomains if is_sub else result.domains).append(value)
            result.findings.append(
                Finding(
                    type="subdomain" if is_sub else "domain",
                    source=f"atlas:{source_plugin}",
                    target=value,
                    host=value,
                    title=f"{'Subdomain' if is_sub else 'Domain'}: {value}",
                    severity="info",
                    confidence=conf_str,
                    tags=tags,
                    raw_data=obj,
                )
            )

    return result
