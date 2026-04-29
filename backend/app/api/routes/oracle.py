"""
Aegis Oracle proxy routes.

Forwards requests from the ASM frontend to the aegis-oracle service
running on http://aegis-oracle:8742 (or ORACLE_URL env var).

All routes require authentication via the standard ASM JWT token.
The proxy adds no additional transformation — it forwards the request
body verbatim and streams the response back, so the frontend talks
directly to Oracle's JSON API through the ASM auth layer.
"""

import logging
import os
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from app.api.deps import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/oracle", tags=["oracle"])

ORACLE_URL = os.getenv("ORACLE_URL", "http://aegis-oracle:8742").rstrip("/")
ORACLE_TIMEOUT = float(os.getenv("ORACLE_TIMEOUT", "180"))


def _oracle_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=ORACLE_URL, timeout=ORACLE_TIMEOUT)


# ─────────────────────────── Chat ──────────────────────────────────────

class ChatRequest(BaseModel):
    question: str


class AnalyzeRequest(BaseModel):
    cve_id: str
    asset_id: str


@router.post("/chat")
async def oracle_chat(
    body: ChatRequest,
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Natural-language CVE query.

    Parses the question to detect a CVE ID + asset ID pair, calls
    Oracle's /analyze endpoint, and returns a structured answer with
    an optional OracleFinding payload for rich UI rendering.
    """
    cve_id, asset_id = _parse_cve_asset(body.question)

    if cve_id and asset_id:
        # Direct analyze path — most useful question form.
        async with _oracle_client() as client:
            try:
                resp = await client.post("/analyze", json={"cve_id": cve_id, "asset_id": asset_id})
                resp.raise_for_status()
                data = resp.json()
                finding = data.get("finding")
                return {
                    "answer": _finding_to_prose(finding) if finding else "Analysis complete — no finding produced.",
                    "finding": finding,
                }
            except httpx.HTTPStatusError as e:
                detail = _safe_error(e)
                raise HTTPException(status_code=502, detail=f"Oracle error: {detail}")
            except httpx.RequestError as e:
                raise HTTPException(
                    status_code=503,
                    detail="Aegis Oracle service is unreachable. Make sure the aegis-oracle container is running.",
                )

    # Non-analyze queries: list findings, explain, etc.
    if "list" in body.question.lower() or "findings" in body.question.lower() or "open" in body.question.lower():
        async with _oracle_client() as client:
            try:
                cat_filter = _parse_category_filter(body.question)
                params = {"category": cat_filter} if cat_filter else {}
                resp = await client.get("/findings", params=params)
                resp.raise_for_status()
                data = resp.json()
                findings = data.get("findings", [])
                count = data.get("count", len(findings))
                if not findings:
                    return {"answer": "No open findings in Oracle yet. Analyze a CVE + asset pair to get started.", "finding": None}
                summary = _findings_summary(findings)
                return {"answer": f"Found {count} open finding(s):\n\n{summary}", "finding": None}
            except httpx.RequestError:
                raise HTTPException(status_code=503, detail="Aegis Oracle service is unreachable.")

    # Generic fallback — explain what Oracle can do.
    return {
        "answer": (
            "I can analyze a specific CVE + asset pair and tell you the practical exploitability.\n\n"
            "Try:\n"
            "• \"Analyze CVE-2025-55130 on asset ftds-tenant-prod-7421\"\n"
            "• \"List open P0 findings\"\n"
            "• \"What are the open findings for CVE-2024-3094?\"\n\n"
            "I need both a CVE ID and an asset ID to produce a scored analysis."
        ),
        "finding": None,
    }


@router.post("/analyze")
async def oracle_analyze(
    body: AnalyzeRequest,
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Directly trigger analysis for a (CVE, asset) pair."""
    async with _oracle_client() as client:
        try:
            resp = await client.post("/analyze", json={"cve_id": body.cve_id, "asset_id": body.asset_id})
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(status_code=502, detail=_safe_error(e))
        except httpx.RequestError:
            raise HTTPException(status_code=503, detail="Aegis Oracle service is unreachable.")


@router.get("/findings")
async def oracle_findings(
    cve_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    current_user=Depends(get_current_user),
) -> Dict[str, Any]:
    """Return open findings, optionally filtered."""
    async with _oracle_client() as client:
        try:
            params: Dict[str, str] = {}
            if cve_id:
                params["cve_id"] = cve_id
            if asset_id:
                params["asset_id"] = asset_id
            resp = await client.get("/findings", params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.RequestError:
            # Oracle might not be running yet — return empty rather than 503
            # so the UI renders gracefully.
            return {"findings": [], "count": 0}


@router.get("/health")
async def oracle_health(current_user=Depends(get_current_user)) -> Dict[str, Any]:
    """Liveness check — verifies Oracle service is reachable."""
    async with _oracle_client() as client:
        try:
            resp = await client.get("/health", timeout=5)
            resp.raise_for_status()
            return {"status": "ok", "oracle": resp.json()}
        except Exception:
            return {"status": "unavailable", "oracle": None}


# ─────────────────────────── Helpers ────────────────────────────────────

def _parse_cve_asset(question: str):
    """Extract (CVE-XXXX-XXXXX, asset_id) from freeform text."""
    import re
    cve_match = re.search(r'CVE-\d{4}-\d+', question, re.IGNORECASE)
    cve_id = cve_match.group(0).upper() if cve_match else None

    # Asset ID: look for "on asset <id>" or "on <id>"
    asset_match = re.search(r'on\s+(?:asset\s+)?([\w\-\.]+)', question, re.IGNORECASE)
    asset_id = asset_match.group(1) if asset_match else None
    # Don't treat CVE-… as asset_id
    if asset_id and asset_id.upper().startswith("CVE-"):
        asset_id = None

    return cve_id, asset_id


def _parse_category_filter(question: str) -> Optional[str]:
    import re
    m = re.search(r'\b(P[0-4])\b', question, re.IGNORECASE)
    return m.group(1).upper() if m else None


def _finding_to_prose(finding: Dict[str, Any]) -> str:
    if not finding:
        return "Analysis complete."
    opes = finding.get("opes", {})
    score = opes.get("score", 0)
    cat = opes.get("category", "?")
    label = opes.get("label", "")
    confidence = opes.get("confidence", "")
    dampener = opes.get("dampener", "")
    rec = finding.get("recommendation", "")

    lines = [
        f"{finding.get('cve_id', '')} on {finding.get('asset_id', '')}",
        f"OPES {score:.1f} / {cat} — {label} (confidence: {confidence})",
    ]
    if dampener:
        lines.append(f"⚠ {dampener}")
    if rec:
        lines.append("")
        lines.append(rec)
    return "\n".join(lines)


def _findings_summary(findings: list) -> str:
    lines = []
    for f in findings[:20]:
        opes = f.get("opes", {})
        lines.append(
            f"• {f.get('cve_id','?')} on {f.get('asset_id','?')} "
            f"— {opes.get('category','?')} ({opes.get('score',0):.1f}) {opes.get('label','')}"
        )
    if len(findings) > 20:
        lines.append(f"  … and {len(findings) - 20} more")
    return "\n".join(lines)


def _safe_error(e: httpx.HTTPStatusError) -> str:
    try:
        return e.response.json().get("error", str(e))
    except Exception:
        return str(e)
