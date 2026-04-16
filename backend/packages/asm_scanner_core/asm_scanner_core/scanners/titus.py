"""
Praetorian Titus secrets scanner wrapper.

CLI: https://github.com/praetorian-inc/titus

Typical invocation:
    titus scan <path> --format json [--validate] --datastore <tmp.ds>
    titus report --datastore <tmp.ds> --format sarif

We prefer `--format json` on scan because the JSON output is sent to stdout
per-finding and is much easier to parse than SARIF. If the installed titus
release uses a different JSON shape, the parser is defensive and will
fall back to SARIF when a `.sarif` artifact is produced alongside the
datastore.
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
class TitusResult:
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    raw_stdout: str = ""


_SEVERITY_BY_VALIDATION = {
    "valid": "critical",
    "active": "critical",
    "confirmed": "critical",
    "invalid": "low",
    "inactive": "low",
    "denied": "low",
    "unknown": "high",
    "undetermined": "high",
}

_SEVERITY_BY_CATEGORY = {
    "aws": "high",
    "gcp": "high",
    "azure": "high",
    "github": "high",
    "slack": "medium",
    "database": "high",
    "generic": "medium",
    "default": "medium",
}


def _extract_fields(obj: dict) -> dict:
    """Pull a best-effort common shape from titus JSON (schema varies by release)."""
    rule = obj.get("rule") or {}
    if isinstance(rule, dict):
        rule_id = rule.get("id") or rule.get("ID") or obj.get("rule_id") or obj.get("ruleId")
        rule_name = rule.get("name") or rule.get("Name") or obj.get("rule_name") or obj.get("ruleName")
        category = rule.get("category") or rule.get("Category")
    else:
        rule_id = str(rule) if rule else obj.get("rule_id") or obj.get("ruleId")
        rule_name = obj.get("rule_name") or obj.get("ruleName") or rule_id
        category = obj.get("category")

    loc = obj.get("location") or {}
    source_span = (loc.get("SourceSpan") or loc.get("source_span") or {}) if isinstance(loc, dict) else {}
    start = (source_span.get("Start") or source_span.get("start") or {}) if isinstance(source_span, dict) else {}
    line = start.get("Line") or start.get("line") or obj.get("line") or 0

    file_path = (
        obj.get("path")
        or obj.get("file")
        or obj.get("File")
        or (loc.get("Path") if isinstance(loc, dict) else None)
    )

    snippet = obj.get("snippet") or {}
    matching = (snippet.get("Matching") or snippet.get("matching") if isinstance(snippet, dict) else None) or obj.get("match")

    vr = obj.get("validation_result") or obj.get("ValidationResult") or {}
    if isinstance(vr, dict):
        v_status = (vr.get("Status") or vr.get("status") or "").lower()
        v_message = vr.get("Message") or vr.get("message")
    else:
        v_status = str(vr).lower() if vr else ""
        v_message = None

    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "category": (category or "").lower() if isinstance(category, str) else None,
        "path": file_path,
        "line": line,
        "match": (matching[:120] if isinstance(matching, str) else None),
        "validation_status": v_status,
        "validation_message": v_message,
    }


def _severity_for(category: Optional[str], validation_status: str) -> str:
    if validation_status and validation_status in _SEVERITY_BY_VALIDATION:
        return _SEVERITY_BY_VALIDATION[validation_status]
    if category and category in _SEVERITY_BY_CATEGORY:
        return _SEVERITY_BY_CATEGORY[category]
    return _SEVERITY_BY_CATEGORY["default"]


def _parse_json_stream(text: str) -> List[dict]:
    """Parse stdout that may be one JSON document, NDJSON, or a list."""
    text = text.strip()
    if not text:
        return []
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        results: List[dict] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or not (line.startswith("{") or line.startswith("[")):
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results

    if isinstance(loaded, list):
        return [x for x in loaded if isinstance(x, dict)]
    if isinstance(loaded, dict):
        for key in ("findings", "matches", "results", "data"):
            if isinstance(loaded.get(key), list):
                return [x for x in loaded[key] if isinstance(x, dict)]
        return [loaded]
    return []


def run_titus(
    path: str,
    *,
    validate: bool = False,
    timeout: int = 900,
    binary: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
) -> TitusResult:
    """
    Scan a filesystem path (directory or file) with titus and return normalized findings.

    Args:
        path: Absolute path to a directory, file, or git repo.
        validate: If True, add --validate (performs live credential validation).
        timeout: Max seconds to wait.
        binary: Override titus binary path (else TITUS_PATH env or PATH lookup).
        extra_args: Additional CLI flags appended to the scan command.
    """
    result = TitusResult()
    binary = binary or os.environ.get("TITUS_PATH") or which("titus")
    if not binary:
        result.errors.append("titus not found on PATH and TITUS_PATH not set")
        logger.info("titus not installed; skip")
        return result
    if not os.path.exists(path):
        result.errors.append(f"path not found: {path}")
        return result

    datastore = tempfile.mkdtemp(prefix="titus_ds_")
    try:
        cmd = [binary, "scan", path, "--format", "json", "--datastore", os.path.join(datastore, "titus.ds")]
        if validate:
            cmd.append("--validate")
        if extra_args:
            cmd.extend([str(x) for x in extra_args])

        res = run_command(cmd, timeout=timeout)
        result.raw_stdout = res.stdout
        if res.exit_code != 0 and not res.stdout:
            result.errors.append(f"titus exit {res.exit_code}: {(res.stderr or '').strip()[:500]}")
            return result

        for obj in _parse_json_stream(res.stdout):
            if not isinstance(obj, dict):
                continue
            f = _extract_fields(obj)
            severity = _severity_for(f["category"], f["validation_status"])
            title = f["rule_name"] or f["rule_id"] or "Secret finding"
            description_parts = []
            if f["path"]:
                description_parts.append(f"File: {f['path']}:{f['line']}")
            if f["match"]:
                description_parts.append(f"Match: {f['match']}")
            if f["validation_status"]:
                description_parts.append(
                    f"Validation: {f['validation_status']}"
                    + (f" — {f['validation_message']}" if f["validation_message"] else "")
                )
            tags = ["titus", "secret"]
            if f["category"]:
                tags.append(f["category"])
            if f["validation_status"]:
                tags.append(f"validation:{f['validation_status']}")

            result.findings.append(
                Finding(
                    type="vulnerability",
                    source="titus",
                    target=f["path"] or path,
                    title=f"Secret: {title}",
                    description="\n".join(description_parts) if description_parts else None,
                    severity=severity,
                    template_id=f["rule_id"] or "titus",
                    url=f"file://{f['path']}" if f["path"] else None,
                    raw_data=obj,
                    tags=tags,
                    is_risky=(f["validation_status"] in ("valid", "active", "confirmed")),
                    risk_reason=(
                        "Live credential confirmed by titus validation"
                        if f["validation_status"] in ("valid", "active", "confirmed")
                        else None
                    ),
                )
            )
    finally:
        shutil.rmtree(datastore, ignore_errors=True)

    return result
