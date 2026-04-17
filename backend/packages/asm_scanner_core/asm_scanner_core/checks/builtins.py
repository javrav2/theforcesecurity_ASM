"""Optional CLI-backed checks (nerva, Argus, Atlas, Hermes, Janus, gitleaks)."""

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


def check_argus(ctx: SecurityCheckContext, cfg: dict) -> List[Finding]:
    """
    Argus (Aegis Vanguard) — secrets scanning via Praetorian `titus`.

    Requires `argus_scan_path` (cfg, ctx.extra, or ARGUS_SCAN_PATH env) and the
    `titus` binary on PATH (or TITUS_PATH). Findings are tagged `argus` and
    flow through the standard Aegis ingest pipeline.
    """
    from asm_scanner_core.scanners.argus import run_argus

    scan_path = (
        cfg.get("argus_scan_path")
        or os.environ.get("ARGUS_SCAN_PATH")
        or ctx.extra.get("argus_scan_path")
    )
    if not scan_path or not os.path.isdir(scan_path):
        logger.debug("argus_scan_path not set or not a directory; skip argus")
        return []

    timeout = int(cfg.get("argus_timeout", 900))
    validate = bool(cfg.get("argus_validate", False))
    extra_args = cfg.get("argus_cli_args") if isinstance(cfg.get("argus_cli_args"), list) else None
    binary = cfg.get("argus_binary") or cfg.get("titus_binary")

    result = run_argus(
        scan_path,
        validate=validate,
        timeout=timeout,
        binary=binary,
        extra_args=extra_args,
    )
    for err in result.errors:
        logger.info("argus: %s", err)
    return result.findings


def check_atlas(ctx: SecurityCheckContext, cfg: dict) -> List[Finding]:
    """
    Atlas (Aegis Vanguard) — organizational asset discovery via Praetorian `pius`.

    Requires `atlas_org` (cfg, ctx.extra, or ATLAS_ORG env) and the `pius`
    binary. Emits domain / subdomain / ip_range Findings the worker can
    persist as Assets / Netblocks.
    """
    from asm_scanner_core.scanners.atlas import run_atlas

    org = (
        cfg.get("atlas_org")
        or os.environ.get("ATLAS_ORG")
        or ctx.extra.get("atlas_org")
    )
    if not org:
        logger.debug("atlas_org not set; skip atlas")
        return []

    domain = cfg.get("atlas_domain") or ctx.domain or ctx.extra.get("atlas_domain")
    asn = cfg.get("atlas_asn") or ctx.extra.get("atlas_asn")
    mode = cfg.get("atlas_mode", "passive")
    timeout = int(cfg.get("atlas_timeout", 900))
    plugins = cfg.get("atlas_plugins") if isinstance(cfg.get("atlas_plugins"), list) else None
    disable = cfg.get("atlas_disable") if isinstance(cfg.get("atlas_disable"), list) else None
    concurrency = int(cfg.get("atlas_concurrency", 5))

    result = run_atlas(
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
        logger.info("atlas: %s", err)
    return result.findings


def check_hermes(ctx: SecurityCheckContext, cfg: dict) -> List[Finding]:
    """
    Hermes (Aegis Vanguard) — remote secrets via TruffleHog v3.

    Runs when `hermes_source` and `hermes_target` are both set. Example configs:
        hermes_source: 'github' | 'gitlab' | 's3' | 'docker' | 'filesystem' | ...
        hermes_target: 'acme' (org), 'https://github.com/acme/repo', bucket, image, ...
        hermes_only_verified: True to emit only live-validated secrets
        hermes_env: { GITHUB_TOKEN: ..., AWS_ACCESS_KEY_ID: ... } for auth'd sources
    """
    from asm_scanner_core.scanners.hermes import run_hermes

    source = cfg.get("hermes_source") or ctx.extra.get("hermes_source")
    target = cfg.get("hermes_target") or ctx.extra.get("hermes_target")
    if not source or not target:
        logger.debug("hermes_source/hermes_target not set; skip Hermes")
        return []

    timeout = int(cfg.get("hermes_timeout", 900))
    only_verified = bool(cfg.get("hermes_only_verified", False))
    extra_args = cfg.get("hermes_cli_args") if isinstance(cfg.get("hermes_cli_args"), list) else None
    env = cfg.get("hermes_env") if isinstance(cfg.get("hermes_env"), dict) else None
    binary = cfg.get("hermes_binary")

    result = run_hermes(
        source=source,
        target=target,
        only_verified=only_verified,
        timeout=timeout,
        binary=binary,
        extra_args=extra_args,
        env=env,
    )
    for err in result.errors:
        logger.info("hermes: %s", err)
    return result.findings


def check_janus(ctx: SecurityCheckContext, cfg: dict) -> List[Finding]:
    """
    Janus (Aegis Vanguard) — OWASP ZAP DAST (baseline by default).

    Runs when `janus_target_url` is set or when ctx.domain is http-probable.
    Defaults to `baseline` mode (passive, safe). Set `janus_mode: 'full'` to
    enable active attacks — in-scope only.
    """
    from asm_scanner_core.scanners.janus import run_janus

    target_url = (
        cfg.get("janus_target_url")
        or ctx.extra.get("janus_target_url")
        or (f"https://{ctx.domain}" if ctx.domain else None)
    )
    if not target_url:
        logger.debug("janus_target_url not set; skip Janus")
        return []

    mode = cfg.get("janus_mode", "baseline")
    minutes = cfg.get("janus_minutes")
    ajax = bool(cfg.get("janus_ajax", False))
    timeout = int(cfg.get("janus_timeout", 1800))
    extra_args = cfg.get("janus_cli_args") if isinstance(cfg.get("janus_cli_args"), list) else None
    context_file = cfg.get("janus_context_file")
    binary = cfg.get("janus_binary")

    result = run_janus(
        target_url=target_url,
        mode=mode,
        minutes=int(minutes) if minutes else None,
        ajax=ajax,
        timeout=timeout,
        binary=binary,
        context_file=context_file,
        extra_args=extra_args,
    )
    for err in result.errors:
        logger.info("janus: %s", err)
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
        ("asm_core_argus", check_argus),
        ("asm_core_atlas", check_atlas),
        ("asm_core_hermes", check_hermes),
        ("asm_core_janus", check_janus),
        ("asm_core_gitleaks", check_gitleaks),
    ]
