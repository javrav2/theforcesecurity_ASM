"""
Themis - Aegis Vanguard's cloud compliance & posture oracle.

Themis was the Greek titaness of divine law and order — the one who set the
rules of conduct for the other gods. Here she wraps Prowler (the open-source
CSPM engine) to judge whether an organization's cloud estate lives up to the
rules laid down by CIS, NIST, PCI-DSS, ISO 27001, HIPAA, SOC 2, MITRE ATT&CK,
FedRAMP, GDPR, etc.

Prowler ships as a single CLI (`prowler`) with per-provider subcommands:

    prowler aws         --output-format json-ocsf
    prowler azure       --output-format json-ocsf
    prowler gcp         --output-format json-ocsf
    prowler kubernetes  --output-format json-ocsf

It uses the **live cloud credentials already on the machine** (AWS named
profiles, Azure CLI login, gcloud ADC, kubeconfig), runs hundreds of
read-only posture checks per provider, and emits one finding per (check,
resource) pair.

We translate each finding into a normalized `Finding` object so it flows
through the same ingestion/dedup/asset-linking pipeline the rest of the
platform uses.

CLI: https://github.com/prowler-cloud/prowler

Notable Prowler v4+ flags we expose:
    --compliance <framework>   restrict to a single compliance pack
    --services <svc,svc...>    restrict to specific cloud services
    --checks <check-id,...>    run only named checks
    --severity <crit,high,...> filter by severity before writing output
    --output-directory <path>  where Prowler writes its JSON report
    --output-filename <name>   override report file stem
    --no-banner                machine-friendly output
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from asm_scanner_core.findings import Finding
from asm_scanner_core.runner import run_command, which

logger = logging.getLogger(__name__)


VALID_PROVIDERS = {"aws", "azure", "gcp", "kubernetes", "k8s"}


@dataclass
class ThemisResult:
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    provider: str = ""
    compliance: Optional[str] = None
    checks_total: int = 0
    passed: int = 0
    failed: int = 0
    report_path: Optional[str] = None
    raw_stdout: str = ""


# Prowler emits severity as lower/upper case strings across output formats.
_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
    "unknown": "info",
}


def _normalize_severity(value: Any) -> str:
    if not value:
        return "info"
    return _SEVERITY_MAP.get(str(value).strip().lower(), "info")


def _normalize_provider(provider: str) -> str:
    p = (provider or "").strip().lower()
    if p == "k8s":
        return "kubernetes"
    return p


def _resolve_prowler_binary(binary: Optional[str]) -> Optional[List[str]]:
    """Return the command prefix used to invoke Prowler, or None if unavailable."""
    if binary:
        return [binary]

    override = os.environ.get("PROWLER_BINARY") or os.environ.get("PROWLER_PATH")
    if override:
        return [override]

    located = which("prowler")
    if located:
        return [located]

    if which("python3"):
        # Prowler is a Python package; falling back to module invocation lets
        # us run it inside envs where the console-script isn't shimmed.
        return ["python3", "-m", "prowler"]

    if which("docker"):
        return [
            "docker", "run", "--rm",
            "-v", f"{tempfile.gettempdir()}:/home/prowler/output/",
            "-e", "AWS_ACCESS_KEY_ID",
            "-e", "AWS_SECRET_ACCESS_KEY",
            "-e", "AWS_SESSION_TOKEN",
            "-e", "AWS_REGION",
            "toniblyx/prowler:latest",
        ]

    return None


def _extract_resource(obj: Dict[str, Any], provider: str) -> Dict[str, Optional[str]]:
    """
    Pull a (target, region, resource_type, resource_id) tuple out of a Prowler
    finding. Handles both the OCSF-style output and the legacy v3 JSON shape.
    """
    # OCSF style (json-ocsf): resources is an array of objects.
    resources = obj.get("resources") or []
    if isinstance(resources, list) and resources:
        r0 = resources[0] if isinstance(resources[0], dict) else {}
        return {
            "resource_id": r0.get("uid") or r0.get("name") or obj.get("resource_uid"),
            "resource_type": r0.get("type") or r0.get("resource_type") or obj.get("resource_type"),
            "region": (r0.get("region") or obj.get("region") or obj.get("cloud", {}).get("region")
                       if isinstance(obj.get("cloud"), dict) else obj.get("region")),
            "account": r0.get("owner", {}).get("uid") if isinstance(r0.get("owner"), dict) else obj.get("account_uid"),
        }

    # Legacy v3 / generic JSON
    return {
        "resource_id": (
            obj.get("ResourceId") or obj.get("resource_id") or obj.get("ResourceArn")
            or obj.get("resource_uid") or obj.get("ResourceName")
        ),
        "resource_type": obj.get("ResourceType") or obj.get("resource_type"),
        "region": obj.get("Region") or obj.get("region"),
        "account": obj.get("AccountId") or obj.get("account_uid") or obj.get("Subscription"),
    }


def _extract_check_metadata(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Extract check id, title, compliance links, and remediation text."""
    meta: Dict[str, Any] = {}
    # OCSF shape
    if isinstance(obj.get("metadata"), dict):
        meta["check_id"] = obj["metadata"].get("product", {}).get("uid") or obj["metadata"].get("uid")

    # v3 / flat shape
    meta["check_id"] = meta.get("check_id") or obj.get("CheckID") or obj.get("check_id") or obj.get("check_title")
    meta["check_title"] = obj.get("CheckTitle") or obj.get("check_title") or obj.get("finding_info", {}).get("title")
    meta["service"] = obj.get("ServiceName") or obj.get("service_name") or obj.get("metadata", {}).get("product", {}).get("name")
    meta["description"] = obj.get("Description") or obj.get("description") or obj.get("finding_info", {}).get("desc")
    meta["risk"] = obj.get("Risk") or obj.get("risk_details")
    meta["remediation"] = (
        (obj.get("Remediation") or {}).get("Recommendation", {}).get("Text")
        if isinstance(obj.get("Remediation"), dict)
        else (obj.get("remediation") or {}).get("desc") if isinstance(obj.get("remediation"), dict)
        else None
    )
    # Compliance frameworks (flat dict or nested list)
    compliance = obj.get("Compliance") or obj.get("compliance") or {}
    if isinstance(compliance, dict):
        meta["compliance"] = compliance
    elif isinstance(compliance, list):
        meta["compliance"] = {"frameworks": compliance}
    else:
        meta["compliance"] = {}

    # Native status
    status = (obj.get("Status") or obj.get("status") or obj.get("status_code") or "").upper()
    meta["status"] = status
    return meta


def run_themis(
    provider: str,
    *,
    compliance: Optional[str] = None,
    services: Optional[List[str]] = None,
    checks: Optional[List[str]] = None,
    severity_filter: Optional[List[str]] = None,
    profile: Optional[str] = None,
    region: Optional[str] = None,
    subscription: Optional[str] = None,
    project_id: Optional[str] = None,
    kubeconfig: Optional[str] = None,
    context: Optional[str] = None,
    timeout: int = 1800,
    binary: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
) -> ThemisResult:
    """
    Run a Prowler CSPM audit and return normalized findings.

    Args:
        provider: One of 'aws', 'azure', 'gcp', 'kubernetes' (alias 'k8s').
        compliance: Single compliance framework key Prowler understands
                    (e.g. 'cis_1.5_aws', 'nist_800_53_revision_5',
                    'pci_3.2.1', 'soc2_cc', 'hipaa'). Passed as
                    `--compliance <key>`.
        services: Restrict the run to one or more cloud services
                  (e.g. ['iam', 's3', 'ec2']).
        checks: Restrict the run to one or more specific check IDs.
        severity_filter: Drop findings below this severity set before
                         emission (maps to `--severity`).
        profile: AWS only — named credentials profile.
        region: AWS/Azure region hint passed through to Prowler.
        subscription: Azure subscription id.
        project_id: GCP project id.
        kubeconfig: Path to kubeconfig for Kubernetes provider.
        context: kubeconfig context to use.
        timeout: Subprocess hard timeout (seconds).
        binary: Override Prowler entrypoint.
        extra_args: Extra CLI flags passed verbatim.
        env: Extra environment vars merged into the subprocess env (e.g.
             AWS_* credentials, AZURE_*, GOOGLE_APPLICATION_CREDENTIALS).

    Returns:
        ThemisResult with findings, counters, the raw report path, and errors.
    """
    result = ThemisResult(provider=_normalize_provider(provider), compliance=compliance)

    prov = _normalize_provider(provider)
    if prov not in VALID_PROVIDERS and prov != "kubernetes":
        result.errors.append(f"unsupported provider '{provider}'. Valid: {sorted(VALID_PROVIDERS)}")
        return result

    cmd_prefix = _resolve_prowler_binary(binary)
    if not cmd_prefix:
        result.errors.append(
            "Prowler not available: tried PROWLER_BINARY/PROWLER_PATH, `prowler` on "
            "PATH, `python3 -m prowler`, and docker fallback."
        )
        logger.info("Themis: prowler not installed; skip")
        return result

    work_dir = tempfile.mkdtemp(prefix="themis_prowler_")
    report_stem = "themis_report"
    report_path = os.path.join(work_dir, f"{report_stem}.ocsf.json")

    cmd: List[str] = list(cmd_prefix) + [prov]
    cmd += [
        "--output-formats", "json-ocsf",
        "--output-directory", work_dir,
        "--output-filename", report_stem,
        "--no-banner",
    ]

    if compliance:
        cmd += ["--compliance", compliance]
    if services:
        cmd += ["--services"] + [str(s) for s in services]
    if checks:
        cmd += ["--checks"] + [str(c) for c in checks]
    if severity_filter:
        cmd += ["--severity"] + [str(s).lower() for s in severity_filter]

    # Provider-specific auth plumbing
    if prov == "aws":
        if profile:
            cmd += ["--aws-profile", profile]
        if region:
            cmd += ["--aws-region", region]
    elif prov == "azure":
        # Assume az login has happened; allow subscription scoping.
        cmd += ["--az-cli-auth"]
        if subscription:
            cmd += ["--subscription-ids", subscription]
    elif prov == "gcp":
        if project_id:
            cmd += ["--project-ids", project_id]
    elif prov == "kubernetes":
        if kubeconfig:
            cmd += ["--kubeconfig-file", kubeconfig]
        if context:
            cmd += ["--context", context]

    if extra_args:
        cmd += [str(x) for x in extra_args]

    merged_env = None
    if env:
        merged_env = os.environ.copy()
        merged_env.update({k: str(v) for k, v in env.items()})

    try:
        res = run_command(cmd, timeout=timeout, env=merged_env)
        result.raw_stdout = res.stdout

        # Prowler exits non-zero when FAIL findings exist; still writes the
        # report. Treat anything with a JSON file as a successful emission.
        # Prowler may append a timestamp suffix; glob for the latest matching file.
        candidate_paths: List[str] = []
        for fname in os.listdir(work_dir):
            if fname.startswith(report_stem) and fname.endswith(".json"):
                candidate_paths.append(os.path.join(work_dir, fname))
        if candidate_paths:
            candidate_paths.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            report_path = candidate_paths[0]
            result.report_path = report_path
        elif not os.path.exists(report_path):
            # Exit code only matters if we got no output.
            result.errors.append(
                f"prowler exit {res.exit_code}: {(res.stderr or '').strip()[:500] or 'no report written'}"
            )
            return result

        with open(report_path, "r", encoding="utf-8", errors="replace") as fh:
            try:
                report = json.load(fh)
            except json.JSONDecodeError:
                fh.seek(0)
                # Older Prowler versions emit NDJSON; tolerate both shapes.
                report = [json.loads(line) for line in fh if line.strip().startswith("{")]

        if isinstance(report, dict) and "findings" in report:
            findings_in = report.get("findings") or []
        elif isinstance(report, list):
            findings_in = report
        else:
            findings_in = []

        for obj in findings_in:
            if not isinstance(obj, dict):
                continue
            meta = _extract_check_metadata(obj)
            res_info = _extract_resource(obj, prov)
            severity = _normalize_severity(obj.get("Severity") or obj.get("severity") or obj.get("severity_id"))
            status = meta.get("status") or ""

            result.checks_total += 1
            if status in ("PASS", "MANUAL", "INFO") and "fail" not in status.lower():
                result.passed += 1
                # Skip PASS findings — they're noise at ingestion time.
                if status == "PASS":
                    continue
            if status in ("FAIL", "FAILED") or "fail" in status.lower():
                result.failed += 1

            target = (
                res_info.get("resource_id")
                or res_info.get("account")
                or f"{prov}-resource"
            )
            check_id = meta.get("check_id") or "prowler-check"
            service = meta.get("service") or prov
            title = meta.get("check_title") or check_id or "Prowler finding"

            desc_parts: List[str] = []
            if meta.get("description"):
                desc_parts.append(str(meta["description"]).strip())
            if meta.get("risk"):
                desc_parts.append(f"Risk: {str(meta['risk']).strip()}")
            if meta.get("remediation"):
                desc_parts.append(f"Remediation: {str(meta['remediation']).strip()}")
            if res_info.get("account"):
                desc_parts.append(f"Account: {res_info['account']}")
            if res_info.get("region"):
                desc_parts.append(f"Region: {res_info['region']}")
            if res_info.get("resource_type"):
                desc_parts.append(f"Resource Type: {res_info['resource_type']}")

            tags: List[str] = ["themis", "prowler", f"provider:{prov}", f"service:{service}".lower()]
            if status:
                tags.append(f"status:{status.lower()}")
            compliance_meta = meta.get("compliance") or {}
            if compliance:
                tags.append(f"compliance:{compliance}")
            if isinstance(compliance_meta, dict):
                for fw_key in list(compliance_meta.keys())[:5]:
                    tags.append(f"compliance:{fw_key}".lower())

            references: List[str] = []
            for ref_key in ("Url", "url", "reference", "References"):
                val = obj.get(ref_key)
                if isinstance(val, str) and val.startswith("http"):
                    references.append(val)
                elif isinstance(val, list):
                    references.extend([str(v) for v in val if isinstance(v, str) and v.startswith("http")])

            result.findings.append(
                Finding(
                    type="vulnerability",
                    source="themis",
                    target=str(target)[:500],
                    host=str(target)[:500] if "." in str(target) else None,
                    title=str(title)[:500],
                    description="\n".join(desc_parts) if desc_parts else None,
                    severity=severity,
                    confidence="high",
                    template_id=f"themis-{prov}-{check_id}".replace("/", "-")[:255],
                    raw_data=obj,
                    tags=tags,
                    references=references,
                    is_risky=severity in ("critical", "high"),
                    risk_reason=(
                        f"Prowler posture failure ({severity}) on {service} in {prov}"
                        if status == "FAIL" else None
                    ),
                )
            )

        return result

    except Exception as exc:
        result.errors.append(f"Themis failed: {exc}")
        logger.exception("Themis run_themis failed")
        return result
    finally:
        # Keep the JSON report so operators can download it, but clean up the
        # scratch dir if Prowler never produced one.
        if (not result.report_path or not os.path.exists(result.report_path)) and os.path.isdir(work_dir):
            shutil.rmtree(work_dir, ignore_errors=True)


__all__ = ["run_themis", "ThemisResult", "VALID_PROVIDERS"]
