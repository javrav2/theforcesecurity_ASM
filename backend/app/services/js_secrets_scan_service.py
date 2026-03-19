"""
AI-powered sensitive data scan for JS and other files discovered by Katana.

Fetches file content from discovered URLs and uses the same LLM as the agent
(OpenAI or Anthropic) to identify:
- API keys, tokens, secrets
- Passwords, credentials
- PII, internal endpoints
- Other sensitive patterns

Two scanning modes:
1. Regex pre-filter (fast, no LLM needed) — SecretFinder-style pattern matching
2. AI deep analysis (uses LLM) — for nuanced detection beyond regex

Workflow (matches the infosecwriteups article methodology):
  1. Provide domain list → httpx checks liveness → katana crawls JS files
  2. This service fetches each JS URL, runs regex patterns, then optionally uses LLM

Enable via Katana scan config: ai_secrets_scan=true (and set OPENAI_API_KEY or ANTHROPIC_API_KEY).
Or use the dedicated JS_SECRETS_SCAN scan type for a standalone scan.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings

logger = logging.getLogger(__name__)

# Max file size to fetch (bytes)
MAX_FETCH_SIZE = 300 * 1024
# Max content to send to LLM per file (chars)
MAX_CONTENT_CHARS = 80_000
FETCH_TIMEOUT = 15
MAX_URLS_PER_SCAN = 50
# Redact actual secret in snippet (show only type and context)
REDACT_SNIPPET = True


# =============================================================================
# SecretFinder-style regex patterns for fast pre-filtering
# Reference: https://github.com/m4ll0k/SecretFinder
# =============================================================================

REGEX_PATTERNS: Dict[str, Dict[str, Any]] = {
    # Cloud provider keys
    "aws_access_key": {
        "pattern": r"(?:AKIA|A3T[A-Z0-9]|ABIA|ACCA|ASIA)[A-Z0-9]{16}",
        "severity": "critical",
        "description": "AWS Access Key ID",
    },
    "aws_secret_key": {
        "pattern": r"""(?:aws.{0,20})?(?:secret.{0,20})?['"\s=:]+([A-Za-z0-9/+=]{40})""",
        "severity": "critical",
        "description": "AWS Secret Access Key",
    },
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "high",
        "description": "Google API Key",
    },
    "google_oauth": {
        "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "severity": "high",
        "description": "Google OAuth Client ID",
    },
    "google_cloud_sa": {
        "pattern": r'"type"\s*:\s*"service_account"',
        "severity": "critical",
        "description": "Google Cloud Service Account JSON",
    },
    "azure_subscription_key": {
        "pattern": r"[a-f0-9]{32}",
        "severity": "medium",
        "description": "Potential Azure Subscription Key",
        "requires_context": True,  # Only flag if near 'azure' or 'subscription'
        "context_pattern": r"(?i)azure|subscription|cognitive|ocp-apim",
    },

    # API keys & tokens
    "generic_api_key": {
        "pattern": r"""(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9\-_]{16,64})['"]""",
        "severity": "high",
        "description": "Generic API Key",
    },
    "generic_secret": {
        "pattern": r"""(?i)(?:secret[_-]?key|client[_-]?secret|app[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9\-_]{16,64})['"]""",
        "severity": "critical",
        "description": "Generic Secret Key",
    },
    "bearer_token": {
        "pattern": r"""(?i)(?:bearer|authorization)\s*[:=]\s*['"]?Bearer\s+([A-Za-z0-9\-_.~+/]+=*)['"]?""",
        "severity": "critical",
        "description": "Bearer/Authorization Token",
    },
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "severity": "high",
        "description": "JSON Web Token (JWT)",
    },

    # SaaS-specific
    "github_token": {
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        "severity": "critical",
        "description": "GitHub Personal Access Token",
    },
    "slack_token": {
        "pattern": r"xox[bpors]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}",
        "severity": "critical",
        "description": "Slack Token",
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}",
        "severity": "high",
        "description": "Slack Webhook URL",
    },
    "stripe_key": {
        "pattern": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}",
        "severity": "critical",
        "description": "Stripe API Key",
    },
    "twilio_api_key": {
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": "high",
        "description": "Twilio API Key",
    },
    "sendgrid_api_key": {
        "pattern": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "severity": "critical",
        "description": "SendGrid API Key",
    },
    "mailgun_api_key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "description": "Mailgun API Key",
    },
    "firebase_url": {
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "severity": "medium",
        "description": "Firebase Database URL",
    },
    "firebase_api_key": {
        "pattern": r"""(?i)(?:firebase|FIREBASE).*?['"]([A-Za-z0-9_-]{39})['"]""",
        "severity": "high",
        "description": "Firebase API Key",
    },
    "heroku_api_key": {
        "pattern": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        "severity": "high",
        "description": "Heroku API Key",
    },
    "mapbox_token": {
        "pattern": r"(?:pk|sk)\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "severity": "medium",
        "description": "Mapbox Access Token",
    },

    # Passwords & credentials
    "password_assignment": {
        "pattern": r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{4,})['"]""",
        "severity": "critical",
        "description": "Hardcoded Password",
    },
    "basic_auth_credentials": {
        "pattern": r"https?://[^/\s]+:[^/\s]+@[^/\s]+",
        "severity": "critical",
        "description": "Basic Auth Credentials in URL",
    },
    "connection_string": {
        "pattern": r"""(?i)(?:mongodb|postgres|mysql|redis|amqp|mssql)(?:\+\w+)?://[^\s'"<>]+""",
        "severity": "critical",
        "description": "Database Connection String",
    },

    # Private keys
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "critical",
        "description": "Private Key",
    },

    # PII
    "email_address": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "severity": "low",
        "description": "Email Address",
    },

    # Internal endpoints
    "internal_ip": {
        "pattern": r"""(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/\S*)?""",
        "severity": "medium",
        "description": "Internal IP Address/Endpoint",
    },
    "localhost_url": {
        "pattern": r"""https?://(?:localhost|127\.0\.0\.1)(?::\d+)?(?:/\S*)?""",
        "severity": "low",
        "description": "Localhost URL",
    },

    # ICS/OT-specific (Rockwell, Siemens, etc.)
    "rockwell_ftview_key": {
        "pattern": r"""(?i)(?:factorytalk|ftview|rslinx|plc|hmi).*?(?:key|password|token|secret)\s*[:=]\s*['"]([^'"]+)['"]""",
        "severity": "critical",
        "description": "FactoryTalk/Rockwell Credential",
    },
    "scada_endpoint": {
        "pattern": r"""(?i)(?:https?://[^\s'"]*(?:scada|hmi|plc|modbus|opcua|bacnet|dnp3)[^\s'"]*)""",
        "severity": "high",
        "description": "SCADA/ICS Endpoint URL",
    },
}

# Compiled patterns cache
_compiled_patterns: Dict[str, re.Pattern] = {}


def _get_compiled_pattern(name: str) -> re.Pattern:
    """Get or compile a regex pattern."""
    if name not in _compiled_patterns:
        _compiled_patterns[name] = re.compile(
            REGEX_PATTERNS[name]["pattern"],
            re.IGNORECASE if name != "aws_access_key" else 0,
        )
    return _compiled_patterns[name]


@dataclass
class SensitiveFinding:
    """A single sensitive data finding."""
    type: str  # api_key, password, token, secret, pii, internal_url, etc.
    snippet: str  # Short context; actual secret redacted if REDACT_SNIPPET
    severity: str  # critical, high, medium, low, info
    line_hint: Optional[str] = None
    source: str = "regex"  # "regex" or "ai"
    description: Optional[str] = None


@dataclass
class UrlScanResult:
    """Result of scanning one URL."""
    url: str
    success: bool
    findings: List[SensitiveFinding] = field(default_factory=list)
    error: Optional[str] = None
    content_preview_len: int = 0


def _get_llm():
    """Build the same LLM as the agent (OpenAI or Anthropic) for one-off prompts."""
    provider = (settings.AI_PROVIDER or "anthropic").lower()
    if provider == "anthropic" and settings.ANTHROPIC_API_KEY:
        try:
            from langchain_anthropic import ChatAnthropic
            import os
            os.environ["ANTHROPIC_API_KEY"] = (settings.ANTHROPIC_API_KEY or "").strip()
            return ChatAnthropic(
                model=settings.ANTHROPIC_MODEL,
                temperature=0,
                max_tokens=4096,
            )
        except ImportError:
            pass
    if provider == "openai" and settings.OPENAI_API_KEY:
        try:
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=settings.OPENAI_MODEL,
                api_key=settings.OPENAI_API_KEY,
                temperature=0,
                max_tokens=4096,
            )
        except ImportError:
            pass
    # Fallback
    if settings.ANTHROPIC_API_KEY:
        try:
            from langchain_anthropic import ChatAnthropic
            import os
            os.environ["ANTHROPIC_API_KEY"] = (settings.ANTHROPIC_API_KEY or "").strip()
            return ChatAnthropic(
                model=settings.ANTHROPIC_MODEL,
                temperature=0,
                max_tokens=4096,
            )
        except ImportError:
            pass
    if settings.OPENAI_API_KEY:
        try:
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=settings.OPENAI_MODEL,
                api_key=settings.OPENAI_API_KEY,
                temperature=0,
                max_tokens=4096,
            )
        except ImportError:
            pass
    return None


SENSITIVE_ANALYSIS_PROMPT = """You are a security analyst. Analyze the following content from a web-accessible file (JavaScript or similar) and identify any sensitive or security-relevant data.

Look for:
- API keys, API secrets, tokens (Bearer, OAuth, JWT, etc.)
- Passwords, credentials, connection strings
- Hardcoded secrets, private keys
- PII (emails, phone numbers, names in clear context)
- Internal URLs, endpoints, or config that could aid an attacker
- ICS/SCADA credentials or endpoints (FactoryTalk, RSLinx, PLCs, HMIs)

For each finding output a JSON object with:
- "type": one of api_key, password, token, secret, credential, pii, internal_url, ics_credential, other
- "snippet": a short context line (REDACT the actual secret: replace with [REDACTED]; e.g. "apiKey: [REDACTED]" not the real key)
- "severity": critical | high | medium | low | info (critical for keys/passwords, high for tokens, lower for PII/internal URLs)
- "line_hint": optional line number or nearby identifier
- "description": brief explanation of what was found and the risk

Output ONLY a valid JSON array of findings, no markdown or explanation. If nothing sensitive found, output: []

Content from URL: {url}

---
{content}
---
JSON array of findings:"""


async def _fetch_url(url: str) -> Tuple[bool, str, Optional[str]]:
    """Fetch URL content; return (success, content_or_error, error_message)."""
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=FETCH_TIMEOUT),
                max_size=MAX_FETCH_SIZE,
                ssl=False,
            ) as resp:
                if resp.status != 200:
                    return False, "", f"HTTP {resp.status}"
                text = await resp.text()
                if len(text) > MAX_CONTENT_CHARS:
                    text = text[:MAX_CONTENT_CHARS] + "\n... [truncated]"
                return True, text, None
    except asyncio.TimeoutError:
        return False, "", "Timeout"
    except Exception as e:
        return False, "", str(e)


def _redact_match(match_str: str, keep_chars: int = 4) -> str:
    """Redact a matched secret, keeping only first few chars."""
    if len(match_str) <= keep_chars:
        return "[REDACTED]"
    return match_str[:keep_chars] + "[REDACTED]"


def regex_scan_content(content: str, url: str = "") -> List[SensitiveFinding]:
    """
    Run SecretFinder-style regex patterns against file content.

    Fast, no LLM needed. Returns findings with redacted snippets.
    """
    findings: List[SensitiveFinding] = []
    seen_snippets: set = set()
    lines = content.split("\n")

    for pattern_name, pattern_info in REGEX_PATTERNS.items():
        compiled = _get_compiled_pattern(pattern_name)
        severity = pattern_info["severity"]
        description = pattern_info["description"]

        # Skip context-dependent patterns unless context keyword is nearby
        if pattern_info.get("requires_context"):
            ctx_pattern = pattern_info.get("context_pattern", "")
            if ctx_pattern and not re.search(ctx_pattern, content):
                continue

        for match in compiled.finditer(content):
            matched_text = match.group(0)

            # De-duplicate
            dedup_key = f"{pattern_name}:{matched_text[:20]}"
            if dedup_key in seen_snippets:
                continue
            seen_snippets.add(dedup_key)

            # Find line number
            start_pos = match.start()
            line_num = content[:start_pos].count("\n") + 1

            # Build context snippet (the line containing the match)
            if line_num <= len(lines):
                context_line = lines[line_num - 1].strip()
            else:
                context_line = matched_text

            # Redact the actual secret in the snippet
            if match.lastindex and match.lastindex >= 1:
                secret_part = match.group(1)
                redacted = _redact_match(secret_part)
                snippet = context_line.replace(secret_part, redacted)
            else:
                redacted = _redact_match(matched_text)
                snippet = context_line.replace(matched_text, redacted)

            # Truncate long snippets
            snippet = snippet[:300]

            # Skip low-value email findings (common in JS comments/licenses)
            if pattern_name == "email_address":
                email = matched_text.lower()
                if any(skip in email for skip in [
                    "example.com", "test.com", "noreply", "no-reply",
                    "@w3.org", "jquery", "mozilla", "github",
                ]):
                    continue

            findings.append(SensitiveFinding(
                type=pattern_name,
                snippet=snippet,
                severity=severity,
                line_hint=str(line_num),
                source="regex",
                description=description,
            ))

    return findings


def _parse_findings_from_llm(response_text: str, url: str) -> List[SensitiveFinding]:
    """Parse LLM response into list of SensitiveFinding."""
    findings = []
    text = (response_text or "").strip()
    # Strip markdown code block if present
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```\s*$", "", text)
    try:
        arr = json.loads(text)
        if not isinstance(arr, list):
            return findings
        for item in arr:
            if not isinstance(item, dict):
                continue
            t = item.get("type") or "other"
            snippet = (item.get("snippet") or "")[:500]
            severity = (item.get("severity") or "info").lower()
            if severity not in ("critical", "high", "medium", "low", "info"):
                severity = "info"
            line_hint = item.get("line_hint")
            description = item.get("description", "")
            findings.append(SensitiveFinding(
                type=t,
                snippet=snippet,
                severity=severity,
                line_hint=str(line_hint) if line_hint is not None else None,
                source="ai",
                description=description,
            ))
    except json.JSONDecodeError as e:
        logger.warning("AI secrets scan: failed to parse LLM JSON for %s: %s", url[:80], e)
    return findings


async def analyze_url_for_sensitive_data(url: str, content: str, llm) -> UrlScanResult:
    """Run LLM analysis on one URL's content."""
    if not content.strip():
        return UrlScanResult(url=url, success=True, findings=[], content_preview_len=0)
    prompt = SENSITIVE_ANALYSIS_PROMPT.format(
        url=url,
        content=content[:MAX_CONTENT_CHARS],
    )
    try:
        from langchain_core.messages import HumanMessage
        msg = HumanMessage(content=prompt)
        response = await llm.ainvoke([msg])
        response_text = getattr(response, "content", None) or str(response)
        findings = _parse_findings_from_llm(response_text, url)
        return UrlScanResult(
            url=url,
            success=True,
            findings=findings,
            content_preview_len=len(content),
        )
    except Exception as e:
        logger.warning("AI secrets scan error for %s: %s", url[:80], e)
        return UrlScanResult(url=url, success=False, findings=[], error=str(e))


async def scan_url_combined(
    url: str,
    content: str,
    llm=None,
    use_ai: bool = True,
) -> UrlScanResult:
    """
    Scan a single URL with both regex and (optionally) AI analysis.

    1. Run regex patterns (fast, always available)
    2. If use_ai=True and regex found something interesting (or always for JS files),
       also run LLM analysis for deeper inspection
    3. Merge and deduplicate findings
    """
    regex_findings = regex_scan_content(content, url)

    ai_findings: List[SensitiveFinding] = []
    if use_ai and llm:
        ai_result = await analyze_url_for_sensitive_data(url, content, llm)
        if ai_result.success:
            ai_findings = ai_result.findings

    # Merge: regex findings first, then AI findings that don't duplicate
    all_findings = list(regex_findings)
    regex_snippets = {f.snippet[:50] for f in regex_findings}
    for af in ai_findings:
        if af.snippet[:50] not in regex_snippets:
            all_findings.append(af)

    return UrlScanResult(
        url=url,
        success=True,
        findings=all_findings,
        content_preview_len=len(content),
    )


async def scan_urls_for_sensitive_data(
    urls: List[str],
    max_urls: int = MAX_URLS_PER_SCAN,
    fetch_content: bool = True,
    use_ai: bool = True,
    regex_only: bool = False,
) -> List[UrlScanResult]:
    """
    Fetch (if needed) and analyze URLs for sensitive data.

    Pipeline (matches the infosecwriteups workflow):
      1. httpx -l domains.txt -silent >> live_urls.txt  (done externally)
      2. katana -u urls.txt -d 5 -jc -fx -ef woff,css,... -o js_urls.txt  (done externally)
      3. This function: fetch each URL, run regex + AI analysis

    Args:
        urls: List of URLs (typically JS files from Katana).
        max_urls: Cap number of URLs to analyze.
        fetch_content: If True, fetch each URL's content.
        use_ai: If True and LLM available, use AI for deep analysis.
        regex_only: If True, skip AI and use only regex patterns.

    Returns:
        List of UrlScanResult per URL.
    """
    llm = None
    if use_ai and not regex_only:
        llm = _get_llm()
        if not llm:
            logger.info("AI secrets scan: no LLM configured, using regex-only mode")

    to_scan = urls[:max_urls] if urls else []
    if not to_scan:
        return []

    results: List[UrlScanResult] = []
    for url in to_scan:
        try:
            if fetch_content:
                ok, content, err = await _fetch_url(url)
                if not ok:
                    results.append(UrlScanResult(url=url, success=False, error=err or "Fetch failed"))
                    continue
            else:
                content = ""

            if regex_only or not llm:
                # Regex-only mode
                regex_findings = regex_scan_content(content, url)
                results.append(UrlScanResult(
                    url=url,
                    success=True,
                    findings=regex_findings,
                    content_preview_len=len(content),
                ))
            else:
                # Combined regex + AI
                result = await scan_url_combined(url, content, llm=llm, use_ai=True)
                results.append(result)
        except Exception as e:
            results.append(UrlScanResult(url=url, success=False, error=str(e)))
        # Rate-limit between URLs
        await asyncio.sleep(0.3)

    return results


async def run_full_js_secrets_pipeline(
    domains: List[str],
    use_ai: bool = True,
    regex_only: bool = False,
    max_js_urls: int = MAX_URLS_PER_SCAN,
    katana_depth: int = 5,
    httpx_first: bool = True,
) -> Dict[str, Any]:
    """
    Full pipeline: domains → httpx (liveness) → katana (JS discovery) → secrets scan.

    This replicates the workflow from the infosecwriteups article:
      1. httpx -l domains.txt -silent >> live_domains.txt
      2. katana -u live_domains.txt -d 5 -jc -fx -ef woff,css,... | grep '.js$'
      3. For each JS URL: regex + AI scan for sensitive data

    Args:
        domains: List of domains/URLs to scan.
        use_ai: Use LLM for deep analysis.
        regex_only: Skip AI, regex only.
        max_js_urls: Max JS URLs to analyze.
        katana_depth: Katana crawl depth.
        httpx_first: Run httpx to filter live domains first.

    Returns:
        Dict with pipeline results.
    """
    from app.services.katana_service import KatanaService
    from app.services.projectdiscovery_service import ProjectDiscoveryService

    pipeline_result = {
        "input_domains": len(domains),
        "live_domains": [],
        "js_files_discovered": [],
        "js_files_by_host": {},  # hostname -> [js_url, ...] for asset attribution
        "all_urls_by_host": {},  # hostname -> [url, ...] for asset attribution
        "urls_scanned": 0,
        "findings": [],
        "summary": {},
        "errors": [],
    }

    if not domains:
        pipeline_result["errors"].append("No domains provided")
        return pipeline_result

    # Step 1: httpx liveness check
    live_targets = list(domains)
    if httpx_first:
        try:
            pd_service = ProjectDiscoveryService()
            httpx_results = await pd_service.run_httpx(
                targets=domains,
                tech_detect=False,
                title=False,
                web_server=False,
                ip=False,
                cname=False,
                cdn=False,
            )
            live_targets = [r.url for r in httpx_results if r.url]
            pipeline_result["live_domains"] = live_targets
            logger.info(f"JS secrets pipeline: {len(live_targets)}/{len(domains)} domains live")
        except Exception as e:
            logger.warning(f"httpx check failed, using all domains: {e}")
            pipeline_result["errors"].append(f"httpx failed: {e}")
            live_targets = domains

    if not live_targets:
        pipeline_result["errors"].append("No live domains found")
        return pipeline_result

    # Step 2: Katana crawl for JS files
    try:
        katana = KatanaService()
        if not katana.is_available():
            pipeline_result["errors"].append("Katana not installed")
            return pipeline_result

        batch_result = await katana.crawl_batch_stdin(
            targets=live_targets,
            depth=katana_depth,
            js_crawl=True,
            form_extraction=True,
        )

        js_urls = batch_result.js_files if batch_result.success else []
        all_urls = batch_result.urls if batch_result.success else []
        pipeline_result["js_files_discovered"] = js_urls

        # Group JS files and all URLs by hostname for asset attribution
        from urllib.parse import urlparse as _urlparse
        js_by_host: Dict[str, List[str]] = {}
        urls_by_host: Dict[str, List[str]] = {}
        for u in all_urls:
            try:
                host = _urlparse(u).hostname or ""
                if not host:
                    continue
                urls_by_host.setdefault(host, []).append(u)
            except Exception:
                pass
        for u in js_urls:
            try:
                host = _urlparse(u).hostname or ""
                if not host:
                    continue
                js_by_host.setdefault(host, []).append(u)
            except Exception:
                pass
        pipeline_result["js_files_by_host"] = js_by_host
        pipeline_result["all_urls_by_host"] = urls_by_host
        logger.info(f"JS secrets pipeline: {len(js_urls)} JS files across {len(js_by_host)} hosts")
    except Exception as e:
        logger.error(f"Katana crawl failed: {e}")
        pipeline_result["errors"].append(f"Katana failed: {e}")
        return pipeline_result

    if not js_urls:
        pipeline_result["errors"].append("No JS files discovered by Katana")
        return pipeline_result

    # Step 3: Scan JS files for sensitive data
    scan_results = await scan_urls_for_sensitive_data(
        urls=js_urls,
        max_urls=max_js_urls,
        fetch_content=True,
        use_ai=use_ai,
        regex_only=regex_only,
    )

    pipeline_result["urls_scanned"] = len(scan_results)

    # Aggregate findings
    all_findings = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for result in scan_results:
        if result.findings:
            for f in result.findings:
                finding_dict = {
                    "url": result.url,
                    "type": f.type,
                    "snippet": f.snippet,
                    "severity": f.severity,
                    "line_hint": f.line_hint,
                    "source": f.source,
                    "description": f.description,
                }
                all_findings.append(finding_dict)
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    pipeline_result["findings"] = all_findings
    pipeline_result["summary"] = {
        "total_findings": len(all_findings),
        "severity_breakdown": severity_counts,
        "urls_with_findings": sum(1 for r in scan_results if r.findings),
        "urls_clean": sum(1 for r in scan_results if r.success and not r.findings),
        "urls_failed": sum(1 for r in scan_results if not r.success),
    }

    return pipeline_result


def is_ai_secrets_scan_available() -> bool:
    """Return True if LLM is configured so AI secrets scan can run."""
    return bool(settings.OPENAI_API_KEY or settings.ANTHROPIC_API_KEY)
