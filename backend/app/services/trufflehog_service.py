"""
TruffleHog Deep Secret Scanner
==============================

Wraps the ``trufflehog`` binary and runs it with ``--only-verified`` (or
``--results=verified,unknown``) so the scanner only surfaces secrets
that TruffleHog actively confirmed against the issuer API.

Supported source types:

    * ``git``       - any git URL (with optional branch / since commit)
    * ``github``    - a GitHub org or user
    * ``gitlab``    - a GitLab group or user
    * ``s3``        - an S3 bucket
    * ``filesystem``- a local path (for artifact scans)

Findings are normalised into ``TruffleFinding`` dataclasses and persisted
with a deterministic ``template_id`` for cross-scan deduplication. All
secrets are one-way hashed before being stored in the ``match`` column so
the raw credential never hits the database.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import Awaitable, Callable, Iterable, Optional

logger = logging.getLogger(__name__)


TRUFFLEHOG_BINARY = os.environ.get("TRUFFLEHOG_BIN", "trufflehog")


@dataclass
class TruffleFinding:
    source_type: str          # git / github / s3 / filesystem
    source_name: str          # repo URL / bucket / path
    detector: str             # GitHub, AWS, Stripe, ...
    verified: bool
    severity: str             # "critical" if verified else "high"
    raw_hash: str             # SHA-256 of the raw secret (for dedupe)
    file: str = ""
    line: int = 0
    commit: str = ""
    email: str = ""
    evidence: str = ""
    extras: dict = field(default_factory=dict)


@dataclass
class TruffleScanResult:
    source_type: str = ""
    source_name: str = ""
    findings: list[TruffleFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    binary_available: bool = True


def _have_binary() -> bool:
    return shutil.which(TRUFFLEHOG_BINARY) is not None


async def _run(args: list[str], timeout: int) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        TRUFFLEHOG_BINARY, *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        raise
    return proc.returncode or 0, stdout.decode(errors="ignore"), stderr.decode(errors="ignore")


def _parse_jsonl(output: str, source_type: str, source_name: str) -> list[TruffleFinding]:
    findings: list[TruffleFinding] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        detector = obj.get("DetectorName") or obj.get("Detector") or "unknown"
        verified = bool(obj.get("Verified") or obj.get("verified"))
        raw = obj.get("Raw") or ""
        redacted = obj.get("Redacted") or ""
        sr = obj.get("SourceMetadata", {}).get("Data", {}) or {}

        file_ = ""
        line_no = 0
        commit = ""
        email = ""
        extras: dict = {}
        if "Git" in sr:
            g = sr["Git"]
            file_ = g.get("file", "")
            line_no = int(g.get("line") or 0)
            commit = g.get("commit", "")
            email = g.get("email", "")
            extras = {"repository": g.get("repository"), "timestamp": g.get("timestamp")}
        elif "Github" in sr:
            g = sr["Github"]
            file_ = g.get("file", "")
            line_no = int(g.get("line") or 0)
            commit = g.get("commit", "")
            extras = {"repository": g.get("repository"), "link": g.get("link")}
        elif "Filesystem" in sr:
            f = sr["Filesystem"]
            file_ = f.get("file", "")
            line_no = int(f.get("line") or 0)
        elif "S3" in sr:
            s = sr["S3"]
            file_ = s.get("key", "")
            extras = {"bucket": s.get("bucket")}

        raw_hash = hashlib.sha256((raw or redacted or "").encode()).hexdigest()[:16]
        severity = "critical" if verified else "high"

        findings.append(TruffleFinding(
            source_type=source_type,
            source_name=source_name,
            detector=detector,
            verified=verified,
            severity=severity,
            raw_hash=raw_hash,
            file=file_,
            line=line_no,
            commit=commit,
            email=email,
            evidence=redacted or f"{detector} token matched",
            extras=extras,
        ))
    return findings


async def run_trufflehog(
    source_type: str,
    source_name: str,
    only_verified: bool = True,
    include_unverified: bool = False,
    since_commit: Optional[str] = None,
    branch: Optional[str] = None,
    concurrency: int = 4,
    timeout: int = 900,
    extra_args: Optional[list[str]] = None,
    progress_callback: Optional[Callable[[int, str], Awaitable[None]]] = None,
) -> TruffleScanResult:
    """Run TruffleHog against ``source_name`` and return structured findings."""
    start = datetime.utcnow()
    result = TruffleScanResult(source_type=source_type, source_name=source_name)

    if not _have_binary():
        result.binary_available = False
        result.errors.append(f"{TRUFFLEHOG_BINARY} binary not found in PATH")
        logger.warning("TruffleHog binary missing; skipping scan for %s", source_name)
        return result

    async def _progress(pct: int, step: str) -> None:
        if progress_callback:
            try:
                await progress_callback(pct, step)
            except Exception:
                pass

    args: list[str] = [source_type]

    if source_type == "git":
        args.append(source_name)
        if since_commit:
            args.extend(["--since-commit", since_commit])
        if branch:
            args.extend(["--branch", branch])
    elif source_type == "github":
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            args.extend(["--token", token])
        # ``--org`` or ``--user`` -- fall back to ``--org`` if caller passes a plain slug.
        if "/" in source_name:
            args.extend(["--repo", f"https://github.com/{source_name.strip('/')}.git"])
        else:
            args.extend(["--org", source_name])
    elif source_type == "gitlab":
        args.extend(["--repo", source_name])
    elif source_type == "s3":
        args.extend(["--bucket", source_name])
    elif source_type == "filesystem":
        args.extend([source_name])
    else:
        result.errors.append(f"Unsupported source type: {source_type}")
        return result

    args.extend(["--json", "--no-update"])
    args.extend(["--concurrency", str(concurrency)])

    # Verification mode
    if only_verified:
        args.extend(["--only-verified"])
    elif include_unverified:
        # TruffleHog 3.78+: --results=verified,unknown,unverified
        args.extend(["--results=verified,unknown"])

    if extra_args:
        args.extend(extra_args)

    await _progress(20, f"Running trufflehog {source_type}")

    try:
        rc, out, err = await _run(args, timeout=timeout)
    except asyncio.TimeoutError:
        result.errors.append(f"trufflehog timed out after {timeout}s")
        result.duration_seconds = (datetime.utcnow() - start).total_seconds()
        return result

    if rc != 0 and not out:
        # TruffleHog returns non-zero when it finds findings, so only treat
        # empty-stdout/non-zero as a hard error.
        result.errors.append(f"trufflehog exited {rc}: {err[:500]}")

    await _progress(80, "Parsing trufflehog output")
    result.findings = _parse_jsonl(out, source_type, source_name)
    result.duration_seconds = (datetime.utcnow() - start).total_seconds()
    logger.info(
        "TruffleHog %s scan for %s completed: %d findings (%.2fs)",
        source_type, source_name, len(result.findings), result.duration_seconds,
    )
    return result


async def run_trufflehog_batch(
    sources: Iterable[tuple[str, str]],
    concurrency: int = 2,
    **kwargs,
) -> list[TruffleScanResult]:
    """Run TruffleHog against multiple (source_type, source_name) pairs."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(src: tuple[str, str]) -> TruffleScanResult:
        async with sem:
            return await run_trufflehog(src[0], src[1], **kwargs)

    return await asyncio.gather(*( _one(s) for s in sources ))


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def persist_trufflehog_findings(
    db,
    organization_id: int,
    scan_id: Optional[int],
    result: TruffleScanResult,
    asset_value: Optional[str] = None,
) -> int:
    """Write TruffleHog findings into the vulnerabilities table. Returns count created."""
    from app.models.asset import Asset, AssetType
    from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus

    sev_enum = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM}

    asset_key = asset_value or result.source_name
    asset = (
        db.query(Asset)
        .filter(
            Asset.organization_id == organization_id,
            Asset.value == asset_key,
        )
        .first()
    )
    if not asset:
        # Map source type -> AssetType for the placeholder row.
        at_map = {
            "git": AssetType.REPOSITORY if hasattr(AssetType, "REPOSITORY") else AssetType.DOMAIN,
            "github": AssetType.REPOSITORY if hasattr(AssetType, "REPOSITORY") else AssetType.DOMAIN,
            "gitlab": AssetType.REPOSITORY if hasattr(AssetType, "REPOSITORY") else AssetType.DOMAIN,
            "s3": AssetType.CLOUD_RESOURCE if hasattr(AssetType, "CLOUD_RESOURCE") else AssetType.DOMAIN,
            "filesystem": AssetType.DOMAIN,
        }
        asset = Asset(
            organization_id=organization_id,
            asset_type=at_map.get(result.source_type, AssetType.DOMAIN),
            name=asset_key,
            value=asset_key,
            discovery_source="trufflehog",
        )
        db.add(asset)
        db.flush()

    created = 0
    for f in result.findings:
        template_id = f"trufflehog-{f.detector.lower()}-{f.raw_hash}"
        existing = (
            db.query(Vulnerability)
            .filter(
                Vulnerability.asset_id == asset.id,
                Vulnerability.template_id == template_id,
            )
            .first()
        )
        severity = sev_enum.get(f.severity, Severity.HIGH)
        title = f"Verified {f.detector} secret leaked" if f.verified else f"Potential {f.detector} secret leaked"
        description = (
            f"TruffleHog {'actively verified' if f.verified else 'detected'} a "
            f"**{f.detector}** credential in ``{result.source_name}``"
            + (f" at ``{f.file}:{f.line}``" if f.file else "")
            + (f" (commit {f.commit[:10]})" if f.commit else "")
            + ". "
            + ("The secret is live and must be rotated immediately." if f.verified
               else "Verify the exposure manually; pattern match suggests a real credential.")
        )

        meta = {
            "detector": f.detector,
            "verified": f.verified,
            "source_type": f.source_type,
            "source_name": f.source_name,
            "file": f.file,
            "line": f.line,
            "commit": f.commit,
            "email": f.email,
            "raw_hash": f.raw_hash,
            **(f.extras or {}),
        }

        if existing:
            existing.severity = severity
            existing.last_detected = datetime.utcnow()
            existing.metadata_ = meta
            existing.evidence = f.evidence
            existing.status = VulnerabilityStatus.OPEN
            continue

        vuln = Vulnerability(
            title=title[:500],
            description=description[:4000],
            severity=severity,
            asset_id=asset.id,
            scan_id=scan_id,
            detected_by="trufflehog",
            template_id=template_id,
            status=VulnerabilityStatus.OPEN,
            evidence=(f.evidence or "")[:5000],
            tags=["secret-leak", f.detector.lower()] + (["verified"] if f.verified else []),
            metadata_=meta,
            remediation=(
                "Rotate the credential at the provider, purge it from git history "
                "(git filter-repo / BFG), invalidate dependent tokens, and add the "
                "detector pattern to your pre-commit secret-scan config."
            ),
        )
        db.add(vuln)
        created += 1

    db.commit()
    return created
