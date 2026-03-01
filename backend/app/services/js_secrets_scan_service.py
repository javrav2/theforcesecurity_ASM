"""
AI-powered sensitive data scan for JS and other files discovered by Katana.

Fetches file content from discovered URLs and uses the same LLM as the agent
(OpenAI or Anthropic) to identify:
- API keys, tokens, secrets
- Passwords, credentials
- PII, internal endpoints
- Other sensitive patterns

Enable via Katana scan config: ai_secrets_scan=true (and set OPENAI_API_KEY or ANTHROPIC_API_KEY).
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
MAX_URLS_PER_SCAN = 30
# Redact actual secret in snippet (show only type and context)
REDACT_SNIPPET = True


@dataclass
class SensitiveFinding:
    """A single sensitive data finding."""
    type: str  # api_key, password, token, secret, pii, internal_url, etc.
    snippet: str  # Short context; actual secret redacted if REDACT_SNIPPET
    severity: str  # critical, high, medium, low, info
    line_hint: Optional[str] = None


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

For each finding output a JSON object with:
- "type": one of api_key, password, token, secret, credential, pii, internal_url, other
- "snippet": a short context line (REDACT the actual secret: replace with [REDACTED]; e.g. "apiKey: [REDACTED]" not the real key)
- "severity": critical | high | medium | low | info (critical for keys/passwords, high for tokens, lower for PII/internal URLs)
- "line_hint": optional line number or nearby identifier

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
            findings.append(SensitiveFinding(
                type=t,
                snippet=snippet,
                severity=severity,
                line_hint=str(line_hint) if line_hint is not None else None,
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


async def scan_urls_for_sensitive_data(
    urls: List[str],
    max_urls: int = MAX_URLS_PER_SCAN,
    fetch_content: bool = True,
) -> List[UrlScanResult]:
    """
    Fetch (if needed) and analyze URLs for sensitive data using the configured LLM.

    Args:
        urls: List of URLs (typically JS files from Katana).
        max_urls: Cap number of URLs to analyze.
        fetch_content: If True, fetch each URL; if False, urls are ignored and you must pass content another way (not used here).

    Returns:
        List of UrlScanResult per URL.
    """
    llm = _get_llm()
    if not llm:
        logger.warning("AI secrets scan skipped: no OPENAI_API_KEY or ANTHROPIC_API_KEY")
        return []

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
            result = await analyze_url_for_sensitive_data(url, content, llm)
            results.append(result)
        except Exception as e:
            results.append(UrlScanResult(url=url, success=False, error=str(e)))
        # Rate-limit: one request per URL is already sequential; add small delay to avoid bursting the API
        await asyncio.sleep(0.5)

    return results


def is_ai_secrets_scan_available() -> bool:
    """Return True if LLM is configured so AI secrets scan can run."""
    return bool(settings.OPENAI_API_KEY or settings.ANTHROPIC_API_KEY)
