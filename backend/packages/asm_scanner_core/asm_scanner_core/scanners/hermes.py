"""
Hermes - Aegis Vanguard's remote secrets-finder.

Hermes was the swift messenger who moved between worlds and could slip past
any guard. Here he wraps TruffleHog v3 to hunt secrets in sources that live
*outside* the local filesystem: GitHub/GitLab orgs, S3/GCS/Azure blobs,
Docker registries, Postman workspaces, Jenkins, Jira/Confluence, and more.

This is the complement to Argus (local filesystem / git repo secrets via
Praetorian titus). TruffleHog v3 has its own detection engine (~800+
detectors) with live credential verification — similar philosophy to titus's
--validate, different coverage.

CLI: https://github.com/trufflesecurity/trufflehog

Typical invocations:
    trufflehog git      https://github.com/org/repo   --json --no-update
    trufflehog github   --org=acme --only-verified    --json --no-update
    trufflehog gitlab   --endpoint=https://gitlab.example.com --token=$T --json --no-update
    trufflehog s3       --bucket=my-bucket            --json --no-update
    trufflehog gcs      --project-id=my-project       --json --no-update
    trufflehog docker   --image=acme/app:latest       --json --no-update
    trufflehog postman  --workspace=<id> --token=$T   --json --no-update
    trufflehog filesystem /path/to/dir                --json --no-update

Each stdout line is a JSON document. Key fields:
    DetectorName        e.g. "AWS", "GitHub", "SlackWebhook"
    DetectorType        numeric enum
    Verified            bool — live credential validation
    VerificationError   string (populated only when verification failed)
    Raw, RawV2          the raw secret material
    Redacted            redacted form suitable for UI
    SourceMetadata.Data shape varies by source (git / github / s3 / docker / etc.)
    SourceName          e.g. "trufflehog - git"
    SourceID / SourceType
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from asm_scanner_core.findings import Finding
from asm_scanner_core.runner import run_command, which

logger = logging.getLogger(__name__)


@dataclass
class HermesResult:
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    sources_scanned: List[str] = field(default_factory=list)
    raw_stdout: str = ""


VALID_SOURCES = {
    "git",
    "github",
    "gitlab",
    "bitbucket",
    "s3",
    "gcs",
    "azure",
    "docker",
    "postman",
    "jenkins",
    "jira",
    "confluence",
    "elasticsearch",
    "filesystem",
    "syslog",
}

_HIGH_RISK_DETECTORS = {
    "aws",
    "awssessionkey",
    "gcp",
    "azure",
    "stripe",
    "privatekey",
    "sshprivatekey",
    "pgpprivatekey",
    "rsaprivatekey",
    "github",
    "gitlab",
    "databasecredentials",
    "jdbc",
    "postgres",
    "mysql",
    "mongodb",
    "redis",
}


def _severity_for(detector: str, verified: bool) -> str:
    """Verified = critical; unverified = high for privileged detectors else medium."""
    d = (detector or "").lower().replace("_", "").replace("-", "")
    if verified:
        return "critical"
    if d in _HIGH_RISK_DETECTORS:
        return "high"
    return "medium"


def _target_from_metadata(meta: dict, source_name: str) -> str:
    """Extract a human-readable target (url/path/bucket) from SourceMetadata.Data."""
    if not isinstance(meta, dict):
        return source_name or "trufflehog"
    for adapter_key in (
        "Git",
        "Github",
        "Gitlab",
        "Bitbucket",
        "S3",
        "GCS",
        "Azure",
        "Docker",
        "Postman",
        "Jenkins",
        "Jira",
        "Confluence",
        "Filesystem",
    ):
        data = meta.get(adapter_key)
        if not isinstance(data, dict):
            continue
        for candidate_key in (
            "link", "Link",
            "repository", "Repository",
            "file", "File",
            "bucket", "Bucket",
            "image", "Image",
            "workspace", "Workspace",
            "url", "URL",
            "path", "Path",
            "commit", "Commit",
            "email", "Email",
        ):
            v = data.get(candidate_key)
            if isinstance(v, str) and v:
                return v
    return source_name or "trufflehog"


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


def run_hermes(
    source: str,
    target: str,
    *,
    only_verified: bool = False,
    timeout: int = 900,
    binary: Optional[str] = None,
    extra_args: Optional[List[str]] = None,
    env: Optional[Dict[str, str]] = None,
) -> HermesResult:
    """
    Scan a remote source for leaked secrets using TruffleHog.

    Args:
        source: One of git, github, gitlab, s3, gcs, azure, docker, postman,
                jenkins, jira, confluence, filesystem, ...
        target: Primary target for the source (e.g. a repo URL for `git`, an
                org name for `github`, a bucket name for `s3`, an image ref
                for `docker`, a directory for `filesystem`).
        only_verified: If True, add --only-verified so TruffleHog emits only
                credentials it could live-validate.
        timeout: Max seconds to run.
        binary: Override trufflehog binary (else TRUFFLEHOG_PATH or PATH).
        extra_args: Additional CLI flags.
        env: Extra environment variables (auth tokens) for the subprocess.
    """
    result = HermesResult()

    src = (source or "").strip().lower()
    if src not in VALID_SOURCES:
        result.errors.append(f"unsupported source '{source}'. Valid: {sorted(VALID_SOURCES)}")
        return result
    if not target:
        result.errors.append("target is required")
        return result

    binary = binary or os.environ.get("TRUFFLEHOG_PATH") or which("trufflehog")
    if not binary:
        result.errors.append("trufflehog not found on PATH and TRUFFLEHOG_PATH not set")
        logger.info("trufflehog not installed; skip Hermes")
        return result

    # Flag shape maps source to its primary argument.
    primary_flag: Dict[str, str] = {
        "git": "",            # positional URL or local path
        "github": "--repo",   # or --org — caller can override via extra_args
        "gitlab": "--repo",
        "bitbucket": "--repo",
        "s3": "--bucket",
        "gcs": "--project-id",
        "azure": "--storage-account",
        "docker": "--image",
        "postman": "--workspace",
        "jenkins": "--url",
        "jira": "--domain",
        "confluence": "--domain",
        "elasticsearch": "--nodes",
        "filesystem": "",     # positional path
        "syslog": "--address",
    }.get(src, "")

    cmd: List[str] = [binary, src]
    if primary_flag:
        # Auto-promote to --org when target looks like a bare org name (no slash, no URL) for github/gitlab
        if src in ("github", "gitlab") and "/" not in target and "://" not in target:
            cmd += ["--org", target]
        else:
            cmd += [primary_flag, target]
    else:
        cmd.append(target)

    cmd += ["--json", "--no-update"]
    if only_verified:
        cmd.append("--only-verified")
    if extra_args:
        cmd += [str(x) for x in extra_args]

    merged_env = None
    if env:
        merged_env = os.environ.copy()
        merged_env.update({k: str(v) for k, v in env.items()})

    res = run_command(cmd, timeout=timeout, env=merged_env)
    result.raw_stdout = res.stdout
    result.sources_scanned.append(f"{src}:{target}")

    if res.exit_code not in (0, 183) and not res.stdout:
        # TruffleHog exits 183 when findings were emitted (v3 behaviour on some versions).
        result.errors.append(f"trufflehog exit {res.exit_code}: {(res.stderr or '').strip()[:500]}")
        return result

    for obj in _parse_ndjson(res.stdout):
        detector = (obj.get("DetectorName") or obj.get("detector_name") or "Unknown").strip()
        verified = bool(obj.get("Verified") or obj.get("verified"))
        redacted = obj.get("Redacted") or obj.get("redacted") or ""
        raw_v2 = obj.get("RawV2") or obj.get("raw_v2")
        verification_error = obj.get("VerificationError") or obj.get("verification_error")
        source_metadata: Any = obj.get("SourceMetadata") or obj.get("source_metadata") or {}
        source_name = obj.get("SourceName") or obj.get("source_name") or f"trufflehog - {src}"

        meta_data = source_metadata.get("Data") if isinstance(source_metadata, dict) else None
        tgt = _target_from_metadata(meta_data if isinstance(meta_data, dict) else {}, source_name)

        description_parts = [f"Source: {source_name}"]
        if redacted:
            description_parts.append(f"Match (redacted): {redacted[:200]}")
        if verified:
            description_parts.append("Verification: live credential confirmed")
        elif verification_error:
            description_parts.append(f"Verification: failed ({str(verification_error)[:200]})")
        if isinstance(meta_data, dict):
            commit = meta_data.get("Git", {}).get("commit") if isinstance(meta_data.get("Git"), dict) else None
            if commit:
                description_parts.append(f"Commit: {commit}")

        tags = ["hermes", "trufflehog", "secret", f"source:{src}", f"detector:{detector.lower()}"]
        if verified:
            tags.append("verified")

        severity = _severity_for(detector, verified)

        result.findings.append(
            Finding(
                type="vulnerability",
                source="hermes",
                target=tgt,
                title=f"Secret: {detector}" + (" (verified)" if verified else ""),
                description="\n".join(description_parts),
                severity=severity,
                confidence="high" if verified else "medium",
                template_id=f"hermes-{detector.lower()}",
                url=tgt if tgt.startswith("http") else None,
                raw_data=obj,
                tags=tags,
                is_risky=verified,
                risk_reason=(
                    f"Live {detector} credential confirmed by TruffleHog verification"
                    if verified
                    else None
                ),
            )
        )

    return result


__all__ = ["run_hermes", "HermesResult", "VALID_SOURCES"]
