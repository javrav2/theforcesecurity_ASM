"""
Custom Nuclei Templates API

CRUD management for analyst-written and AI-generated Nuclei templates.
Includes an AI generation endpoint that takes a CVE ID or vulnerability
description and produces a ready-to-review Nuclei YAML template using
the configured LLM (Claude or GPT-4).

Endpoints:
  GET    /nuclei-templates/                   list templates
  POST   /nuclei-templates/                   create (manual upload)
  GET    /nuclei-templates/{id}               get single
  PUT    /nuclei-templates/{id}               update
  DELETE /nuclei-templates/{id}               delete
  POST   /nuclei-templates/{id}/activate      set status=active
  POST   /nuclei-templates/{id}/disable       set status=disabled
  POST   /nuclei-templates/generate           AI generation
"""

import logging
import re
from datetime import datetime
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import get_current_active_user, get_db
from app.core.config import settings
from app.models.custom_nuclei_template import CustomNucleiTemplate
from app.models.api_config import ExternalService, resolve_api_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/nuclei-templates", tags=["nuclei-templates"])

# ── Pydantic schemas ──────────────────────────────────────────────────────────

class TemplateCreate(BaseModel):
    organization_id: int
    template_id: str
    name: str
    description: Optional[str] = None
    template_yaml: str
    cve_ids: list[str] = []
    severity: Optional[str] = None
    tags: list[str] = []
    template_type: Optional[str] = None
    status: str = "draft"


class TemplateUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    template_yaml: Optional[str] = None
    cve_ids: Optional[list[str]] = None
    severity: Optional[str] = None
    tags: Optional[list[str]] = None
    template_type: Optional[str] = None
    status: Optional[str] = None
    validated: Optional[bool] = None


class GenerateRequest(BaseModel):
    organization_id: int
    # Provide ONE of: cve_id or description
    cve_id: Optional[str] = None
    vulnerability_description: Optional[str] = None
    # Optional context from an existing finding
    affected_url: Optional[str] = None
    affected_product: Optional[str] = None
    detection_evidence: Optional[str] = None  # e.g. error message, response body snippet


def _template_response(t: CustomNucleiTemplate) -> dict:
    return {
        "id": t.id,
        "organization_id": t.organization_id,
        "template_id": t.template_id,
        "name": t.name,
        "description": t.description,
        "template_yaml": t.template_yaml,
        "cve_ids": t.cve_ids or [],
        "severity": t.severity,
        "tags": t.tags or [],
        "template_type": t.template_type,
        "source": t.source,
        "ai_model": t.ai_model,
        "status": t.status,
        "validated": t.validated,
        "times_matched": t.times_matched,
        "last_run_at": t.last_run_at.isoformat() if t.last_run_at else None,
        "last_match_at": t.last_match_at.isoformat() if t.last_match_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.get("")
def list_templates(
    organization_id: int = Query(...),
    status: Optional[str] = Query(None),
    cve_id: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    q = db.query(CustomNucleiTemplate).filter(
        CustomNucleiTemplate.organization_id == organization_id
    )
    if status:
        q = q.filter(CustomNucleiTemplate.status == status)
    if source:
        q = q.filter(CustomNucleiTemplate.source == source)
    if cve_id:
        # JSON array contains search — works in SQLite and Postgres
        q = q.filter(CustomNucleiTemplate.cve_ids.contains([cve_id.upper()]))
    templates = q.order_by(CustomNucleiTemplate.created_at.desc()).all()
    return [_template_response(t) for t in templates]


@router.post("")
def create_template(
    payload: TemplateCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    t = CustomNucleiTemplate(
        organization_id=payload.organization_id,
        template_id=payload.template_id,
        name=payload.name,
        description=payload.description,
        template_yaml=payload.template_yaml,
        cve_ids=[c.upper() for c in payload.cve_ids],
        severity=payload.severity,
        tags=payload.tags,
        template_type=payload.template_type,
        status=payload.status,
        source="manual",
        created_by_user_id=getattr(user, "id", None),
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return _template_response(t)


@router.get("/{template_id}")
def get_template(
    template_id: int,
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    return _template_response(t)


@router.put("/{template_id}")
def update_template(
    template_id: int,
    payload: TemplateUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")

    for field, val in payload.model_dump(exclude_none=True).items():
        if field == "cve_ids" and val:
            val = [c.upper() for c in val]
        if field == "validated" and val and not t.validated:
            t.validated_at = datetime.utcnow()
            t.validated_by_user_id = getattr(user, "id", None)
        setattr(t, field, val)

    t.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(t)
    return _template_response(t)


@router.delete("/{template_id}")
def delete_template(
    template_id: int,
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    db.delete(t)
    db.commit()
    return {"deleted": True}


@router.post("/{template_id}/activate")
def activate_template(
    template_id: int,
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    t.status = "active"
    t.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "active"}


@router.post("/{template_id}/disable")
def disable_template(
    template_id: int,
    db: Session = Depends(get_db),
    _user=Depends(get_current_active_user),
):
    t = db.query(CustomNucleiTemplate).filter(CustomNucleiTemplate.id == template_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Template not found")
    t.status = "disabled"
    t.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "disabled"}


# ── AI generation ─────────────────────────────────────────────────────────────

_NUCLEI_SYSTEM_PROMPT = """You are an expert security engineer specializing in writing Nuclei vulnerability detection templates.

Nuclei is a fast, customizable vulnerability scanner. Templates are YAML files that define what to look for.

## Nuclei Template Structure

```yaml
id: unique-template-id  # lowercase, hyphens only, no spaces

info:
  name: Product - Vulnerability Description
  author: judah-security-oracle
  severity: critical  # info | low | medium | high | critical
  description: |
    One paragraph explaining what this template detects and why it matters.
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-XXXX-YYYY
    cwe-id: CWE-78
  metadata:
    verified: false
    max-request: 3
  tags: cve,cveYYYY,rce,product-name

http:
  - method: GET
    path:
      - "{{BaseURL}}/path/to/vulnerable/endpoint"
    headers:
      User-Agent: Mozilla/5.0
    
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "specific string that only appears in vulnerable response"
          - "another indicator"
        condition: or
        part: body
      - type: regex
        regex:
          - "version:\\s*([0-9.]+)"
        part: body
```

## Key rules:
1. The `id` field must be globally unique — use format: cve-YYYY-NNNNN or custom-org-description
2. Always use `matchers-condition: and` for multi-matcher logic
3. Matchers should be SPECIFIC — avoid generic strings that would match on non-vulnerable targets
4. For version detection: use `type: regex` with extractors
5. For timing-based detection: use `type: dsl` with `duration > 5`
6. POST requests need a `body` field and appropriate Content-Type header
7. The `{{BaseURL}}` variable is the target URL
8. Use `{{Hostname}}` for the host only (no port)
9. Mark `verified: false` unless you have tested it manually
10. Add all relevant tags (cve, year, vulnerability type, affected tech)

## Detection strategy:
- PREFER active detection (sending a request that triggers a unique response from vulnerable systems)
- AVOID fingerprinting only (checking version numbers is weak)
- DO NOT include actual exploit payloads that would cause harm
- Use benign detection probes that confirm vulnerability without exploiting it

Return ONLY the raw YAML. No markdown code fences, no explanation, no preamble.
"""

async def _fetch_cve_context(cve_id: str, db: Session) -> dict:
    """Fetch CVE context from PDCP for use in the generation prompt."""
    pdcp_key = resolve_api_key(db, ExternalService.PDCP) or ""
    if not pdcp_key or not cve_id:
        return {}
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"https://api.projectdiscovery.io/v1/vulnerability/{cve_id.upper()}",
                headers={"X-Api-Key": pdcp_key, "Accept": "application/json"},
                timeout=15.0,
            )
            if resp.status_code == 200:
                return resp.json() or {}
    except Exception:
        pass
    return {}


def _build_generation_prompt(req: GenerateRequest, cve_ctx: dict) -> str:
    parts = []

    if req.cve_id:
        parts.append(f"Generate a Nuclei detection template for: {req.cve_id.upper()}")
    else:
        parts.append("Generate a Nuclei detection template for the following vulnerability:")

    if cve_ctx:
        parts.append(f"\n## CVE Enrichment Data")
        if cve_ctx.get("name"):
            parts.append(f"Name: {cve_ctx['name']}")
        if cve_ctx.get("description"):
            parts.append(f"Description: {cve_ctx['description']}")
        if cve_ctx.get("severity"):
            parts.append(f"Severity: {cve_ctx['severity']}")
        if cve_ctx.get("cvss_score"):
            parts.append(f"CVSS Score: {cve_ctx['cvss_score']}")
        if cve_ctx.get("cvss_vector"):
            parts.append(f"CVSS Vector: {cve_ctx['cvss_vector']}")
        if cve_ctx.get("tags"):
            parts.append(f"Tags: {', '.join(cve_ctx['tags'][:10])}")
        if cve_ctx.get("affected_products"):
            prods = cve_ctx["affected_products"][:3]
            parts.append(f"Affected Products: {', '.join(f\"{p.get('vendor','')}/{p.get('product','')}\" for p in prods)}")
        if cve_ctx.get("is_remote"):
            parts.append("Remotely exploitable: yes")
        if cve_ctx.get("is_poc"):
            parts.append("Public PoC: available")

    if req.vulnerability_description:
        parts.append(f"\n## Vulnerability Description\n{req.vulnerability_description}")

    if req.affected_url:
        parts.append(f"\n## Affected URL Pattern\n{req.affected_url}")

    if req.affected_product:
        parts.append(f"\n## Affected Product\n{req.affected_product}")

    if req.detection_evidence:
        parts.append(f"\n## Detection Evidence (response snippet / error message observed)\n{req.detection_evidence}")

    parts.append(
        "\n## Instructions\n"
        "Generate a complete, production-ready Nuclei YAML template.\n"
        "Focus on ACTIVE DETECTION — a request that gets a different response from vulnerable vs. patched systems.\n"
        "Return ONLY the raw YAML. No markdown, no explanation."
    )

    return "\n".join(parts)


def _extract_yaml_from_response(raw: str) -> str:
    """Strip markdown fences if the model included them despite instructions."""
    raw = raw.strip()
    # Remove ```yaml ... ``` or ``` ... ``` blocks
    raw = re.sub(r"^```(?:yaml)?\s*\n?", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\n?```\s*$", "", raw, flags=re.MULTILINE)
    return raw.strip()


def _parse_yaml_metadata(yaml_text: str) -> dict:
    """Extract basic metadata from YAML without importing PyYAML (best-effort)."""
    meta = {"cve_ids": [], "tags": [], "severity": None, "template_id": None, "template_type": "http"}
    for line in yaml_text.splitlines():
        line = line.strip()
        if line.startswith("id:"):
            meta["template_id"] = line.split(":", 1)[1].strip()
        elif line.startswith("severity:"):
            meta["severity"] = line.split(":", 1)[1].strip()
        elif line.startswith("tags:"):
            tags_raw = line.split(":", 1)[1].strip()
            meta["tags"] = [t.strip() for t in tags_raw.split(",")]
        elif line.startswith("cve-id:"):
            cve = line.split(":", 1)[1].strip()
            if cve:
                meta["cve_ids"].append(cve.upper())
        elif line.startswith("network:"):
            meta["template_type"] = "network"
        elif line.startswith("tcp:"):
            meta["template_type"] = "tcp"
        elif line.startswith("dns:"):
            meta["template_type"] = "dns"
    return meta


async def _call_llm(prompt: str) -> str:
    """Call the configured LLM and return the raw text response."""
    ai_provider = getattr(settings, "AI_PROVIDER", "openai")
    model_name = getattr(settings, "AI_MODEL", None)

    try:
        from langchain_anthropic import ChatAnthropic
        from langchain_core.messages import HumanMessage, SystemMessage
        anthropic_available = True
    except ImportError:
        anthropic_available = False

    try:
        from langchain_openai import ChatOpenAI
        openai_available = True
    except ImportError:
        openai_available = False

    messages_payload = [
        {"role": "system", "content": _NUCLEI_SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    if ai_provider == "anthropic" and anthropic_available:
        from langchain_anthropic import ChatAnthropic
        from langchain_core.messages import HumanMessage, SystemMessage
        llm = ChatAnthropic(
            model=model_name or "claude-sonnet-4-20250514",
            api_key=getattr(settings, "ANTHROPIC_API_KEY", ""),
            max_tokens=4096,
        )
        response = await llm.ainvoke([
            SystemMessage(content=_NUCLEI_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ])
        return response.content

    if openai_available:
        from langchain_openai import ChatOpenAI
        from langchain_core.messages import HumanMessage, SystemMessage
        llm = ChatOpenAI(
            model=model_name or "gpt-4o",
            api_key=getattr(settings, "OPENAI_API_KEY", ""),
            max_tokens=4096,
        )
        response = await llm.ainvoke([
            SystemMessage(content=_NUCLEI_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ])
        return response.content

    raise HTTPException(
        status_code=503,
        detail="No LLM provider configured. Set ANTHROPIC_API_KEY or OPENAI_API_KEY.",
    )


@router.post("/generate")
async def generate_template(
    req: GenerateRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_active_user),
):
    """
    Generate a Nuclei YAML detection template using the configured LLM.

    Provide either `cve_id` (will fetch PDCP enrichment automatically) or
    `vulnerability_description` with optional `affected_url`, `affected_product`,
    and `detection_evidence` for richer context.

    The generated template is saved as `status=draft` pending analyst review.
    Use POST /{id}/activate to enable it for scanning.
    """
    if not req.cve_id and not req.vulnerability_description:
        raise HTTPException(
            status_code=422,
            detail="Provide either cve_id or vulnerability_description",
        )

    # Fetch CVE context from PDCP for richer generation
    cve_ctx = {}
    if req.cve_id:
        cve_ctx = await _fetch_cve_context(req.cve_id.upper(), db)

    # Build prompt and call LLM
    prompt = _build_generation_prompt(req, cve_ctx)
    raw_yaml = await _call_llm(prompt)
    clean_yaml = _extract_yaml_from_response(raw_yaml)

    # Extract metadata from the generated YAML
    meta = _parse_yaml_metadata(clean_yaml)

    # Determine template_id — use YAML id or generate one
    template_id = meta.get("template_id") or ""
    if not template_id:
        if req.cve_id:
            template_id = req.cve_id.lower().replace("_", "-")
        else:
            template_id = f"custom-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"

    # Ensure uniqueness within org by suffixing
    existing = db.query(CustomNucleiTemplate).filter(
        CustomNucleiTemplate.organization_id == req.organization_id,
        CustomNucleiTemplate.template_id == template_id,
    ).first()
    if existing:
        template_id = f"{template_id}-{datetime.utcnow().strftime('%H%M%S')}"

    # Merge CVE IDs: from YAML + from request
    cve_ids = list({c.upper() for c in (meta.get("cve_ids") or []) + ([req.cve_id.upper()] if req.cve_id else [])})

    ai_model = getattr(settings, "AI_MODEL", None) or (
        "claude-sonnet-4-20250514" if getattr(settings, "AI_PROVIDER", "openai") == "anthropic" else "gpt-4o"
    )

    t = CustomNucleiTemplate(
        organization_id=req.organization_id,
        template_id=template_id,
        name=cve_ctx.get("name") or template_id,
        description=cve_ctx.get("description") or req.vulnerability_description,
        template_yaml=clean_yaml,
        cve_ids=cve_ids,
        severity=meta.get("severity") or cve_ctx.get("severity"),
        tags=meta.get("tags") or [],
        template_type=meta.get("template_type", "http"),
        source="ai_generated",
        ai_model=ai_model,
        ai_generation_context=prompt[:4000],  # store context for reproducibility
        status="draft",
        created_by_user_id=getattr(user, "id", None),
    )
    db.add(t)
    db.commit()
    db.refresh(t)

    return {
        **_template_response(t),
        "generation_note": (
            "Template saved as draft. Review the YAML carefully before activating — "
            "AI-generated templates should be validated against a known-vulnerable target."
        ),
    }
