"""
Janus - Aegis Vanguard's two-faced DAST gatekeeper.

Janus had two faces: one looking backward (passive observation), one looking
forward (active engagement). This scanner wraps OWASP ZAP in both modes:

    baseline -> passive spider + passive rules only (safe, CI-friendly, ~1 min)
    full     -> baseline + active attack rules (spider, ajax-spider, active
                scan — sends real attack payloads; slower, in-scope only)

ZAP produces true DAST coverage: full application crawl, session-aware
traversal, reflective XSS, CSRF, CORS flaws, insecure deserialisation,
business-logic issues — things nuclei's template model can't find because it
doesn't spider or maintain session state.

We use the official packaged scripts shipped inside the zaproxy Docker image
(zap-baseline.py / zap-full-scan.py), but they can also be invoked directly
when zaproxy is installed on PATH. The wrapper always writes a JSON report,
then translates each ZAP alert to a normalized Finding.

CLI docs:
    https://www.zaproxy.org/docs/docker/baseline-scan/
    https://www.zaproxy.org/docs/docker/full-scan/
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

from asm_scanner_core.findings import Finding
from asm_scanner_core.runner import run_command, which

logger = logging.getLogger(__name__)


@dataclass
class JanusResult:
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    mode: str = "baseline"
    report_path: Optional[str] = None
    raw_stdout: str = ""


_ZAP_RISK_TO_SEVERITY = {
    "0": "info",     # Informational
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}
_ZAP_RISK_NAME_TO_SEVERITY = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}
_ZAP_CONFIDENCE_MAP = {
    "0": "low",       # Falsepositive
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "high",
}


def _severity(alert: dict) -> str:
    riskcode = str(alert.get("riskcode") or alert.get("risk_code") or "").strip()
    if riskcode in _ZAP_RISK_TO_SEVERITY:
        return _ZAP_RISK_TO_SEVERITY[riskcode]
    name = (alert.get("riskdesc") or alert.get("risk") or "").strip().lower().split(" ")[0]
    return _ZAP_RISK_NAME_TO_SEVERITY.get(name, "info")


def _confidence(alert: dict) -> str:
    code = str(alert.get("confidence") or "").strip()
    if code.isdigit():
        return _ZAP_CONFIDENCE_MAP.get(code, "medium")
    name = code.lower()
    if name in ("high", "medium", "low"):
        return name
    return "medium"


def _resolve_zap_command(binary: Optional[str], mode: str) -> List[str]:
    """
    Locate a runnable ZAP command. Order of preference:
        1. Explicit binary argument
        2. ZAP_BINARY / ZAP_PATH env var
        3. zap-baseline.py / zap-full-scan.py on PATH (packaged scripts)
        4. zap.sh on PATH with direct invocation
        5. docker run ghcr.io/zaproxy/zaproxy:stable (fallback if docker available)
    """
    if binary:
        return [binary]

    override = os.environ.get("ZAP_BINARY") or os.environ.get("ZAP_PATH")
    if override:
        return [override]

    script = "zap-full-scan.py" if mode == "full" else "zap-baseline.py"
    located = which(script)
    if located:
        return [located]

    if which("zap.sh"):
        return ["zap.sh"]

    if which("docker"):
        # Last resort — assumes network access out to the image registry.
        return [
            "docker", "run", "--rm",
            "-v", f"{tempfile.gettempdir()}:/zap/wrk/:rw",
            "-t", "ghcr.io/zaproxy/zaproxy:stable",
            script,
        ]

    return []


def run_janus(
    target_url: str,
    *,
    mode: str = "baseline",
    minutes: Optional[int] = None,
    ajax: bool = False,
    timeout: int = 1800,
    binary: Optional[str] = None,
    context_file: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> JanusResult:
    """
    Run an OWASP ZAP DAST scan and return normalized findings.

    Args:
        target_url: Fully qualified URL (https://example.com).
        mode: 'baseline' (passive, default, safe for CI/continuous monitoring)
              or 'full' (active — includes attack payloads; in-scope only).
        minutes: Maximum spider/scan duration (baseline -m, full -m). Caps ZAP's internal timers.
        ajax: Enable ajax-spider (-j) — required for heavy SPA apps, slower.
        timeout: Outer subprocess timeout (seconds). Must be > minutes*60.
        binary: Override ZAP entrypoint (packaged script, zap.sh, or custom).
        context_file: Optional .context file for auth / scope config.
        extra_args: Additional CLI flags passed through verbatim.

    Returns:
        JanusResult with findings, mode, the JSON report path, and errors.
    """
    result = JanusResult(mode=mode)

    if mode not in ("baseline", "full"):
        result.errors.append(f"mode must be 'baseline' or 'full' (got {mode!r})")
        return result
    if not target_url:
        result.errors.append("target_url is required")
        return result

    cmd_prefix = _resolve_zap_command(binary, mode)
    if not cmd_prefix:
        result.errors.append(
            "OWASP ZAP not available: tried ZAP_BINARY/ZAP_PATH, zap-baseline.py, "
            "zap-full-scan.py, zap.sh, and docker fallback."
        )
        logger.info("Janus: ZAP not installed; skip")
        return result

    work_dir = tempfile.mkdtemp(prefix="janus_zap_")
    report_file = os.path.join(work_dir, "zap-report.json")
    result.report_path = report_file

    try:
        is_packaged_script = (
            cmd_prefix[0].endswith("zap-baseline.py")
            or cmd_prefix[0].endswith("zap-full-scan.py")
            or (cmd_prefix[0] == "docker")
        )

        cmd: List[str] = list(cmd_prefix)

        if is_packaged_script:
            cmd += ["-t", target_url, "-J", os.path.basename(report_file) if cmd_prefix[0] == "docker" else report_file]
            if minutes:
                cmd += ["-m", str(minutes)]
            if ajax:
                cmd.append("-j")
            if context_file:
                cmd += ["-n", context_file]
            if extra_args:
                cmd += [str(x) for x in extra_args]
            cwd = work_dir if cmd_prefix[0] == "docker" else None
        else:
            # Raw zap.sh invocation — caller must provide equivalent flags via extra_args.
            cmd += [
                "-cmd",
                "-quickurl", target_url,
                "-quickout", report_file,
            ]
            if extra_args:
                cmd += [str(x) for x in extra_args]
            cwd = None

        res = run_command(cmd, timeout=timeout, cwd=cwd)
        result.raw_stdout = res.stdout

        # ZAP exits 1 when warnings present, 2 for failures — both still produce a report.
        if res.exit_code not in (0, 1, 2) and not os.path.exists(report_file):
            result.errors.append(f"ZAP exit {res.exit_code}: {(res.stderr or '').strip()[:500]}")
            return result

        if not os.path.exists(report_file):
            # Docker mode writes the report into /zap/wrk/ inside the container,
            # which is the mounted work_dir; the filename stays as -J specified.
            alt = os.path.join(work_dir, os.path.basename(report_file))
            if os.path.exists(alt):
                report_file = alt
                result.report_path = alt
            else:
                result.errors.append("ZAP produced no JSON report")
                return result

        with open(report_file, "r", encoding="utf-8", errors="replace") as fh:
            report = json.load(fh)

        sites = report.get("site") if isinstance(report.get("site"), list) else []
        for site in sites:
            host = site.get("@host") or site.get("host") or target_url
            for alert in site.get("alerts") or []:
                title = alert.get("alert") or alert.get("name") or "ZAP alert"
                severity = _severity(alert)
                confidence = _confidence(alert)
                cwe = alert.get("cweid") or alert.get("cwe_id")
                wasc = alert.get("wascid")
                solution = alert.get("solution") or alert.get("remediation")
                reference = alert.get("reference") or ""
                references = [r.strip() for r in reference.split() if r.strip().startswith("http")]

                instances = alert.get("instances") or [{}]
                # Emit one Finding per instance so each URL/param gets its own row.
                for inst in instances:
                    url = inst.get("uri") or inst.get("url") or target_url
                    method = inst.get("method") or ""
                    param = inst.get("param") or ""
                    evidence = inst.get("evidence") or ""

                    desc_parts: List[str] = []
                    if method or param:
                        desc_parts.append(f"Method: {method}  Param: {param}".strip())
                    if evidence:
                        desc_parts.append(f"Evidence: {evidence[:400]}")
                    if alert.get("desc"):
                        desc_parts.append(alert["desc"])
                    if solution:
                        desc_parts.append(f"Solution: {solution}")

                    tags = ["janus", "zap", f"mode:{mode}"]
                    if alert.get("pluginid"):
                        tags.append(f"pluginid:{alert['pluginid']}")

                    result.findings.append(
                        Finding(
                            type="vulnerability",
                            source="janus",
                            target=url,
                            host=host,
                            url=url,
                            title=str(title)[:500],
                            description="\n".join(desc_parts) if desc_parts else None,
                            severity=severity,
                            confidence=confidence,
                            cwe_id=(f"CWE-{cwe}" if cwe else None),
                            template_id=f"janus-{alert.get('pluginid') or alert.get('alertRef') or 'zap'}",
                            raw_data=alert,
                            tags=tags,
                            references=references,
                        )
                    )

        return result

    except Exception as exc:
        result.errors.append(f"Janus failed: {exc}")
        logger.exception("Janus run_janus failed")
        return result
    finally:
        # Keep the JSON report for inspection, but clean up if it never wrote.
        if not os.path.exists(report_file) and os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)


__all__ = ["run_janus", "JanusResult"]
