"""
JS Sensitive Data Scanning API Routes.

Endpoints for detecting sensitive data (API keys, passwords, tokens, credentials)
in JavaScript files discovered across an organization's web assets.

Workflow (matches the infosecwriteups methodology):
  1. Provide domain list -> httpx checks liveness
  2. Katana crawls live sites for JS files
  3. Regex + AI analysis on each JS file for secrets
  4. Results stored as scan findings

Reference tools:
- https://github.com/projectdiscovery/httpx
- https://github.com/projectdiscovery/katana
- https://github.com/m4ll0k/SecretFinder
"""

import logging
from typing import List, Optional, Dict
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.asset import Asset, AssetType
from app.models.user import User
from app.models.label import Label
from app.api.deps import get_current_active_user, require_analyst

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/js-secrets", tags=["JS Secrets Scanning"])


# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class JsSecretsScanRequest(BaseModel):
    """Request to scan domains for JS secrets."""
    organization_id: int
    domains: List[str] = Field(default_factory=list, description="List of domains/URLs to scan")
    domains_text: Optional[str] = Field(None, description="Newline-separated domains (alternative to list)")
    label_ids: Optional[List[int]] = Field(None, description="Scan assets with these labels")
    use_all_in_scope: bool = Field(False, description="Use all in-scope domain assets")
    name: Optional[str] = None
    config: Dict = Field(default_factory=dict)


class JsSecretsQuickScanRequest(BaseModel):
    """Quick scan: provide URLs directly (skip httpx/katana)."""
    organization_id: int
    urls: List[str] = Field(..., description="JS file URLs to scan directly")
    use_ai: bool = Field(True, description="Use AI for deep analysis (requires API key)")
    regex_only: bool = Field(False, description="Use only regex patterns (no AI)")
    name: Optional[str] = None


class JsSecretsFinding(BaseModel):
    """A single JS secret finding."""
    url: str
    type: str
    snippet: str
    severity: str
    line_hint: Optional[str] = None
    source: str = "regex"
    description: Optional[str] = None


class JsSecretsScanResponse(BaseModel):
    """Response from a JS secrets scan."""
    scan_id: Optional[int] = None
    status: str
    input_domains: int = 0
    live_domains: int = 0
    js_files_discovered: int = 0
    urls_scanned: int = 0
    total_findings: int = 0
    severity_breakdown: Dict[str, int] = Field(default_factory=dict)
    findings: List[JsSecretsFinding] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    message: str = ""


# =============================================================================
# HELPER
# =============================================================================

def _check_org_access(user: User, org_id: int) -> bool:
    if user.is_superuser:
        return True
    return user.organization_id == org_id


def _parse_domains(request: JsSecretsScanRequest) -> List[str]:
    """Parse domains from request."""
    import re
    domains = list(request.domains) if request.domains else []
    if request.domains_text:
        for line in request.domains_text.strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                line = re.sub(r"^https?://", "", line)
                line = line.split("/")[0]
                line = line.split(":")[0]
                if line and "." in line:
                    domains.append(line)
    return list(set(domains))


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/status")
async def get_js_secrets_status():
    """
    Check JS secrets scanning availability.

    Returns status of:
    - Regex scanning (always available)
    - AI scanning (requires OPENAI_API_KEY or ANTHROPIC_API_KEY)
    - httpx (for domain liveness check)
    - Katana (for JS file discovery)
    """
    import shutil
    from app.services.js_secrets_scan_service import is_ai_secrets_scan_available

    return {
        "available": True,
        "regex_scanning": True,
        "ai_scanning": is_ai_secrets_scan_available(),
        "httpx_installed": shutil.which("httpx") is not None,
        "katana_installed": shutil.which("katana") is not None,
        "pattern_count": len(REGEX_PATTERNS),
    }


@router.get("/patterns")
async def list_detection_patterns():
    """
    List all regex patterns used for JS secret detection.

    These are SecretFinder-style patterns that detect:
    - Cloud provider keys (AWS, GCP, Azure)
    - SaaS tokens (GitHub, Slack, Stripe, etc.)
    - Passwords, credentials, connection strings
    - Private keys
    - Internal endpoints
    - ICS/SCADA credentials
    """
    from app.services.js_secrets_scan_service import REGEX_PATTERNS

    patterns = []
    for name, info in REGEX_PATTERNS.items():
        patterns.append({
            "name": name,
            "description": info["description"],
            "severity": info["severity"],
        })
    return {"patterns": patterns, "total": len(patterns)}


@router.post("/scan", response_model=JsSecretsScanResponse)
async def create_js_secrets_scan(
    request: JsSecretsScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Full JS secrets scan pipeline.

    Workflow:
    1. Collect target domains (from request, labels, or all in-scope)
    2. Run httpx to find live domains
    3. Run Katana to discover JS files (depth 5, JS crawl, exclude images/fonts/css)
    4. Analyze each JS file with regex patterns + AI (if configured)
    5. Store results as a scan record

    Equivalent CLI commands:
        httpx -l domains.txt -silent >> live_domains.txt
        katana -u live_domains.txt -d 5 -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif -o js_urls.txt
        # Then regex + AI analysis on each JS URL

    Config options:
        depth (int): Katana crawl depth (default 5)
        use_ai (bool): Use LLM for deep analysis (default true)
        regex_only (bool): Skip AI, regex only (default false)
        max_js_urls (int): Max JS URLs to analyze (default 50)
        httpx_first (bool): Run httpx liveness check first (default true)
        headless (bool): Use headless browser for JS-heavy sites (default false)
    """
    if not _check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied to this organization")

    # Collect domains
    domains = _parse_domains(request)

    # Add domains from labels
    if request.label_ids:
        query = db.query(Asset).filter(
            Asset.organization_id == request.organization_id,
            Asset.in_scope == True,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        )
        query = query.filter(Asset.labels.any(Label.id.in_(request.label_ids)))
        assets = query.distinct().all()
        domains.extend([a.value for a in assets])

    # Use all in-scope domains
    if request.use_all_in_scope and not domains:
        assets = db.query(Asset).filter(
            Asset.organization_id == request.organization_id,
            Asset.in_scope == True,
            Asset.asset_type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
        ).all()
        domains.extend([a.value for a in assets])

    domains = list(set(domains))
    if not domains:
        raise HTTPException(
            status_code=400,
            detail="No domains specified. Provide domains, label_ids, or set use_all_in_scope=true",
        )

    # Merge config
    config = {
        "depth": 5,
        "use_ai": True,
        "regex_only": False,
        "max_js_urls": 50,
        "httpx_first": True,
        "headless": False,
        **request.config,
    }

    # Create scan record
    scan_name = request.name or f"JS Secrets Scan - {len(domains)} domains"
    scan = Scan(
        name=scan_name,
        scan_type=ScanType.JS_SECRETS_SCAN,
        organization_id=request.organization_id,
        targets=domains,
        config=config,
        status=ScanStatus.PENDING,
        started_by=current_user.username,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Try SQS first, fall back to background task
    from app.api.routes.scans import send_scan_to_sqs
    if not send_scan_to_sqs(scan):
        background_tasks.add_task(_run_js_secrets_scan_bg, scan.id)

    return JsSecretsScanResponse(
        scan_id=scan.id,
        status="pending",
        input_domains=len(domains),
        message=f"JS secrets scan queued for {len(domains)} domains. Scan ID: {scan.id}",
    )


@router.post("/quick-scan", response_model=JsSecretsScanResponse)
async def quick_js_secrets_scan(
    request: JsSecretsQuickScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Quick scan: analyze provided JS URLs directly (skip httpx/katana).

    Use this when you already have a list of JS file URLs from Katana or other tools.
    Equivalent to:
        cat js_urls.txt | while read url; do python3 SecretFinder.py -i $url -o cli; done
    """
    if not _check_org_access(current_user, request.organization_id):
        raise HTTPException(status_code=403, detail="Access denied to this organization")

    if not request.urls:
        raise HTTPException(status_code=400, detail="No URLs provided")

    from app.services.js_secrets_scan_service import scan_urls_for_sensitive_data

    results = await scan_urls_for_sensitive_data(
        urls=request.urls,
        use_ai=request.use_ai,
        regex_only=request.regex_only,
    )

    # Build response
    findings = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for r in results:
        for f in r.findings:
            findings.append(JsSecretsFinding(
                url=r.url,
                type=f.type,
                snippet=f.snippet,
                severity=f.severity,
                line_hint=f.line_hint,
                source=f.source,
                description=f.description,
            ))
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    # Save scan record
    scan = Scan(
        name=request.name or f"JS Secrets Quick Scan - {len(request.urls)} URLs",
        scan_type=ScanType.JS_SECRETS_SCAN,
        organization_id=request.organization_id,
        targets=request.urls[:100],
        config={"quick_scan": True, "use_ai": request.use_ai, "regex_only": request.regex_only},
        status=ScanStatus.COMPLETED,
        started_by=current_user.username,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        vulnerabilities_found=len(findings),
        results={
            "urls_scanned": len(results),
            "total_findings": len(findings),
            "severity_breakdown": severity_counts,
            "findings": [f.model_dump() for f in findings[:500]],
        },
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Log JS URLs on asset records and create vulnerability findings
    from urllib.parse import urlparse
    from app.models.vulnerability import Vulnerability, Severity as VulnSeverity
    import json as _json

    severity_map = {
        "critical": VulnSeverity.CRITICAL, "high": VulnSeverity.HIGH,
        "medium": VulnSeverity.MEDIUM, "low": VulnSeverity.LOW, "info": VulnSeverity.INFO,
    }
    asset_cache = {}
    findings_created = 0

    for f in findings:
        try:
            hostname = urlparse(f.url).hostname or ""
        except Exception:
            hostname = ""
        if not hostname:
            continue

        # Get or create asset
        if hostname not in asset_cache:
            asset = db.query(Asset).filter(
                Asset.organization_id == request.organization_id,
                Asset.value == hostname,
            ).first()
            if not asset:
                parts = hostname.split(".")
                a_type = AssetType.SUBDOMAIN if len(parts) > 2 else AssetType.DOMAIN
                asset = Asset(
                    organization_id=request.organization_id,
                    name=hostname, value=hostname, asset_type=a_type,
                    in_scope=True, is_monitored=True,
                    discovery_source="js_secrets_scan",
                )
                db.add(asset)
                db.flush()
            # Log the JS URL on the asset
            existing_js = set(asset.js_files or [])
            existing_js.add(f.url)
            asset.js_files = sorted(existing_js)[:500]
            asset.last_seen = datetime.utcnow()
            asset_cache[hostname] = asset

        asset = asset_cache[hostname]

        # Create vulnerability finding
        template_id = f"js-secret-{f.type}"
        vuln = Vulnerability(
            title=f"Exposed {f.description or f.type} in JS file",
            description=(
                f"Sensitive data detected in JavaScript file.\n\n"
                f"**URL:** {f.url}\n**Type:** {f.type}\n"
                f"**Detection:** {f.source}\n**Context:** {f.snippet}"
            ),
            severity=severity_map.get(f.severity, VulnSeverity.INFO),
            asset_id=asset.id,
            scan_id=scan.id,
            detected_by="js_secrets_scan",
            template_id=template_id,
            remediation=(
                "1. Immediately rotate the exposed credential\n"
                "2. Remove the secret from the JavaScript file\n"
                "3. Use environment variables or a secrets manager instead\n"
                "4. Review git history for the same secret in previous commits\n"
                "5. Monitor for unauthorized usage of the exposed credential"
            ),
            evidence=_json.dumps({
                "url": f.url, "type": f.type,
                "snippet": f.snippet, "line": f.line_hint,
            }),
            tags=["js-secrets", f.type, f.source],
        )
        db.add(vuln)
        findings_created += 1

    db.commit()

    # Update scan with actual findings count
    scan.vulnerabilities_found = findings_created
    db.commit()

    return JsSecretsScanResponse(
        scan_id=scan.id,
        status="completed",
        urls_scanned=len(results),
        total_findings=len(findings),
        severity_breakdown=severity_counts,
        findings=findings[:200],
        message=f"Scanned {len(results)} URLs, found {len(findings)} potential secrets, created {findings_created} findings",
    )


@router.get("/scan/{scan_id}/results")
async def get_js_secrets_results(
    scan_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low, info"),
    finding_type: Optional[str] = Query(None, description="Filter by type: api_key, password, token, etc."),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get results from a JS secrets scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not _check_org_access(current_user, scan.organization_id):
        raise HTTPException(status_code=403, detail="Access denied")
    if scan.scan_type != ScanType.JS_SECRETS_SCAN:
        raise HTTPException(status_code=400, detail="Not a JS secrets scan")

    results = scan.results or {}
    findings = results.get("findings", [])

    # Also include ai_secrets_findings from katana scans
    ai_findings = results.get("ai_secrets_findings", [])
    for af in ai_findings:
        url = af.get("url", "")
        for f in af.get("findings", []):
            findings.append({
                "url": url,
                "type": f.get("type", "other"),
                "snippet": f.get("snippet", ""),
                "severity": f.get("severity", "info"),
                "line_hint": f.get("line_hint"),
                "source": "ai",
            })

    # Apply filters
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if finding_type:
        findings = [f for f in findings if f.get("type") == finding_type]

    severity_breakdown = {}
    for f in findings:
        s = f.get("severity", "info")
        severity_breakdown[s] = severity_breakdown.get(s, 0) + 1

    return {
        "scan_id": scan.id,
        "scan_name": scan.name,
        "status": scan.status.value,
        "targets": scan.targets or [],
        "total_findings": len(findings),
        "severity_breakdown": severity_breakdown,
        "findings": findings[:500],
        "js_files_discovered": results.get("js_files_discovered", []),
        "urls_scanned": results.get("urls_scanned", 0),
        "pipeline_summary": results.get("summary", {}),
    }


# =============================================================================
# BACKGROUND TASK
# =============================================================================

async def _run_js_secrets_scan_bg(scan_id: int):
    """Run the full JS secrets pipeline as a background task (fallback when no SQS)."""
    from app.db.database import SessionLocal
    from app.services.js_secrets_scan_service import run_full_js_secrets_pipeline
    from app.models.vulnerability import Vulnerability, Severity as VulnSeverity
    from urllib.parse import urlparse
    import json as _json

    severity_map = {
        "critical": VulnSeverity.CRITICAL, "high": VulnSeverity.HIGH,
        "medium": VulnSeverity.MEDIUM, "low": VulnSeverity.LOW, "info": VulnSeverity.INFO,
    }

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.utcnow()
        scan.current_step = "Starting JS secrets pipeline"
        db.commit()

        config = scan.config or {}
        domains = scan.targets or []
        organization_id = scan.organization_id

        pipeline_result = await run_full_js_secrets_pipeline(
            domains=domains,
            use_ai=config.get("use_ai", True),
            regex_only=config.get("regex_only", False),
            max_js_urls=config.get("max_js_urls", 50),
            katana_depth=config.get("depth", 5),
            httpx_first=config.get("httpx_first", True),
        )

        # Log JS files on asset records
        js_by_host = pipeline_result.get("js_files_by_host", {})
        assets_updated = 0
        for hostname, js_urls in js_by_host.items():
            asset = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == hostname,
            ).first()
            if asset:
                existing_js = set(asset.js_files or [])
                existing_js.update(js_urls)
                asset.js_files = sorted(existing_js)[:500]
                if not asset.metadata_:
                    asset.metadata_ = {}
                asset.metadata_["js_secrets_scan_last"] = datetime.utcnow().isoformat()
                asset.metadata_["js_secrets_scan_files_found"] = len(js_urls)
                asset.last_seen = datetime.utcnow()
                assets_updated += 1
        db.commit()

        # Create vulnerability findings
        findings_created = 0
        asset_cache = {}
        for finding in pipeline_result.get("findings", []):
            try:
                hostname = urlparse(finding["url"]).hostname or ""
            except Exception:
                hostname = ""
            if not hostname:
                continue

            if hostname not in asset_cache:
                asset = db.query(Asset).filter(
                    Asset.organization_id == organization_id,
                    Asset.value == hostname,
                ).first()
                if not asset:
                    parts = hostname.split(".")
                    a_type = AssetType.SUBDOMAIN if len(parts) > 2 else AssetType.DOMAIN
                    asset = Asset(
                        organization_id=organization_id,
                        name=hostname, value=hostname, asset_type=a_type,
                        in_scope=True, is_monitored=True,
                        discovery_source="js_secrets_scan",
                    )
                    db.add(asset)
                    db.flush()
                asset_cache[hostname] = asset

            asset = asset_cache[hostname]
            template_id = f"js-secret-{finding['type']}"

            vuln = Vulnerability(
                title=f"Exposed {finding.get('description') or finding['type']} in JS file",
                description=(
                    f"Sensitive data detected in JavaScript file.\n\n"
                    f"**URL:** {finding['url']}\n**Type:** {finding['type']}\n"
                    f"**Detection:** {finding.get('source', 'regex')}\n"
                    f"**Context:** {finding.get('snippet', 'N/A')}"
                ),
                severity=severity_map.get(finding["severity"], VulnSeverity.INFO),
                asset_id=asset.id,
                scan_id=scan_id,
                detected_by="js_secrets_scan",
                template_id=template_id,
                remediation=(
                    "1. Immediately rotate the exposed credential\n"
                    "2. Remove the secret from the JavaScript file\n"
                    "3. Use environment variables or a secrets manager\n"
                    "4. Review git history for previous commits with the same secret\n"
                    "5. Monitor for unauthorized usage of the exposed credential"
                ),
                evidence=_json.dumps({
                    "url": finding["url"], "type": finding["type"],
                    "snippet": finding.get("snippet", ""), "line": finding.get("line_hint"),
                }),
                tags=["js-secrets", finding["type"], finding.get("source", "regex")],
            )
            db.add(vuln)
            findings_created += 1
        db.commit()

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.current_step = None
        scan.vulnerabilities_found = findings_created
        scan.assets_discovered = assets_updated
        scan.results = pipeline_result
        db.commit()

    except Exception as e:
        logger.error(f"JS secrets scan {scan_id} failed: {e}", exc_info=True)
        try:
            db.rollback()
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)[:500]
                scan.completed_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


# Import for the status endpoint
from app.services.js_secrets_scan_service import REGEX_PATTERNS
