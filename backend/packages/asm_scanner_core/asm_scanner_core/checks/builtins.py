"""Optional CLI-backed checks (nerva, titus, gitleaks). Extend with new tools here."""

from __future__ import annotations

import json
import logging
import os
from typing import Callable, Dict, List, Tuple

from asm_scanner_core.findings import Finding
from asm_scanner_core.checks.context import SecurityCheckContext
from asm_scanner_core.runner import run_command, which

logger = logging.getLogger(__name__)

CheckFn = Callable[[SecurityCheckContext, dict], List[Finding]]


def _parse_nerva_line(line: str) -> dict:
    line = line.strip()
    if not line:
        return {}
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return {}


def check_nerva(ctx: SecurityCheckContext, cfg: dict) -> List[Finding]:
    """
    Service fingerprinting via Praetorian nerva (optional).

    Expects targets like host:port (one per line) or IPs; uses stdin or -target
    depending on binary --help. If nerva is not on PATH, returns [].
    """
    out: List[Finding] = []
    binary = cfg.get("nerva_binary") or os.environ.get("NERVA_PATH") or which("nerva")
    if not binary:
        logger.debug("nerva not on PATH; skip nerva check")
        return out

    raw = ctx.targets or []
    if not raw and ctx.domain:
        raw = [ctx.domain]

    targets: List[str] = []
    for t in raw:
        s = str(t).strip()
        if not s:
            continue
        if ":" in s and not s.startswith("http"):
            targets.append(s)
        else:
            for p in (22, 80, 443, 8080, 8443):
                targets.append(f"{s}:{p}")

    if not targets:
        return out

    timeout = int(cfg.get("nerva_timeout", 300))
    max_hosts = int(cfg.get("nerva_max_targets", 50))
    targets = targets[:max_hosts]

    # CLI shape varies by release; override with nerva_extra_args if needed.
    extra = cfg.get("nerva_extra_args")
    if isinstance(extra, list) and extra:
        cmd = [binary] + [str(x) for x in extra] + targets[:30]
    else:
        cmd = [binary] + targets[:30]

    res = run_command(cmd, timeout=timeout)
    if res.exit_code != 0 and not res.stdout:
        logger.info("nerva exited %s: %s", res.exit_code, (res.stderr or "")[:500])
        return out

    for line in res.stdout.splitlines():
        row = _parse_nerva_line(line)
        if not row:
            continue
        host = row.get("host") or row.get("ip") or ctx.domain or "unknown"
        title = row.get("service") or row.get("name") or "Service fingerprint"
        out.append(
            Finding(
                type="vulnerability",
                source="nerva",
                target=str(host),
                host=str(host) if isinstance(host, str) else None,
                title=str(title)[:500],
                description=(res.stdout[:2000] if len(out) == 0 else line[:2000]),
                severity="info",
                template_id="nerva-fingerprint",
                raw_data=row,
                tags=["nerva", "fingerprint"],
            )
        )
    if not out and res.stdout:
        out.append(
            Finding(
                type="vulnerability",
                source="nerva",
                target=ctx.domain or (ctx.targets[0] if ctx.targets else "scan"),
                title="Nerva output (unparsed)",
                description=res.stdout[:8000],
                severity="info",
                template_id="nerva-raw",
                tags=["nerva"],
            )
        )
    return out


def check_titus(ctx: SecurityCheckContext, cfg: dict) -> List[Finding]:
    """
    Secrets scanning via Praetorian titus on a filesystem path (optional).

    Requires `titus_scan_path` (cfg, ctx.extra, or TITUS_SCAN_PATH env) and the
    `titus` binary on PATH (or TITUS_PATH). Uses the real scanner wrapper for
    structured parsing and severity mapping.
    """
    from asm_scanner_core.scanners.titus import run_titus

    scan_path = (
        cfg.get("titus_scan_path")
        or os.environ.get("TITUS_SCAN_PATH")
        or ctx.extra.get("titus_scan_path")
    )
    if not scan_path or not os.path.isdir(scan_path):
        logger.debug("titus_scan_path not set or not a directory; skip titus")
        return []

    timeout = int(cfg.get("titus_timeout", 900))
    validate = bool(cfg.get("titus_validate", False))
    extra_args = cfg.get("titus_cli_args") if isinstance(cfg.get("titus_cli_args"), list) else None
    binary = cfg.get("titus_binary")

    result = run_titus(
        scan_path,
        validate=validate,
        timeout=timeout,
        binary=binary,
        extra_args=extra_args,
    )
    for err in result.errors:
        logger.info("titus: %s", err)
    return result.findings


def check_pius(ctx: SecurityCheckContext, cfg: dict) -> List[Finding]:
    """
    Organizational asset discovery via Praetorian pius (optional).

    Requires `pius_org` (cfg, ctx.extra, or PIUS_ORG env) and the `pius` binary.
    Emits domain/subdomain/ip_range Findings the worker can persist as Assets/Netblocks.
    """
    from asm_scanner_core.scanners.pius import run_pius

    org = (
        cfg.get("pius_org")
        or os.environ.get("PIUS_ORG")
        or ctx.extra.get("pius_org")
    )
    if not org:
        logger.debug("pius_org not set; skip pius")
        return []

    domain = cfg.get("pius_domain") or ctx.domain or ctx.extra.get("pius_domain")
    asn = cfg.get("pius_asn") or ctx.extra.get("pius_asn")
    mode = cfg.get("pius_mode", "passive")
    timeout = int(cfg.get("pius_timeout", 900))
    plugins = cfg.get("pius_plugins") if isinstance(cfg.get("pius_plugins"), list) else None
    disable = cfg.get("pius_disable") if isinstance(cfg.get("pius_disable"), list) else None
    concurrency = int(cfg.get("pius_concurrency", 5))

    result = run_pius(
        org=org,
        domain=domain,
        asn=asn,
        mode=mode,
        plugins=plugins,
        disable=disable,
        concurrency=concurrency,
        timeout=timeout,
    )
    for err in result.errors:
        logger.info("pius: %s", err)
    return result.findings


def check_gitleaks(ctx: SecurityCheckContext, cfg: dict) -> List[Finding]:
    """Optional gitleaks on a git repo path (asm_core_gitleaks)."""
    out: List[Finding] = []
    binary = cfg.get("gitleaks_binary") or which("gitleaks")
    if not binary:
        return out
    repo = cfg.get("gitleaks_repo_path") or ctx.extra.get("gitleaks_repo_path")
    if not repo or not os.path.isdir(os.path.join(repo, ".git")):
        return out

    res = run_command(
        [binary, "detect", "--source", repo, "--report-format", "json", "--no-git"],
        timeout=int(cfg.get("gitleaks_timeout", 600)),
        cwd=repo,
    )
    if not res.stdout.strip():
        return out
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError:
        return out
    leaks = data if isinstance(data, list) else data.get("findings") or data.get("Leaks") or []
    for item in leaks:
        if not isinstance(item, dict):
            continue
        rule = item.get("RuleID") or item.get("rule") or "gitleaks"
        file = item.get("File") or item.get("file") or ""
        out.append(
            Finding(
                type="vulnerability",
                source="gitleaks",
                target=file or repo,
                title=f"Secret: {rule}",
                description=item.get("Secret") or item.get("Match"),
                severity="high",
                template_id=str(rule),
                raw_data=item,
                tags=["gitleaks", "secret"],
            )
        )
    return out


def registry() -> List[Tuple[str, CheckFn]]:
    """Registered checks: (settings_key, function). Key must be True to run."""
    return [
        ("asm_core_nerva", check_nerva),
        ("asm_core_titus", check_titus),
        ("asm_core_pius", check_pius),
        ("asm_core_gitleaks", check_gitleaks),
    ]
