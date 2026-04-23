"""
Agent Skills + ``/skill`` chat prefix routing.

A "skill" is a named, bounded workflow the agent knows how to run:

    * ``web-recon``    - subdomain + HTTP + tech fingerprint
    * ``vuln-scan``    - Nuclei critical/high on known assets
    * ``js-recon``     - JS bundle deep dive for secrets / maps / DOM sinks
    * ``graphql``      - Discover & audit GraphQL endpoints
    * ``takeover``     - Subdomain takeover sweep
    * ``secrets``      - TruffleHog verified secret scan
    * ``llm-redteam``  - LLM / chatbot red-team

In chat, the user can invoke any skill with::

    /skill takeover target=acme.com engines=cname,nuclei

If no ``/skill`` prefix is used, :func:`route_by_intent` asks a small LLM
to pick the most relevant skill from the registry.
"""

from __future__ import annotations

import json
import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

logger = logging.getLogger(__name__)


@dataclass
class Skill:
    id: str
    aliases: list[str]
    title: str
    description: str
    scan_type: Optional[str] = None
    playbook_id: Optional[str] = None
    default_args: dict = field(default_factory=dict)
    system_context: str = ""
    required_inputs: list[str] = field(default_factory=lambda: ["target"])


SKILLS: list[Skill] = [
    Skill(
        id="web-recon",
        aliases=["webrecon", "recon", "web"],
        title="Web reconnaissance",
        description="Subdomain enumeration, HTTP probing, tech fingerprinting.",
        scan_type="discovery",
        playbook_id="quick_recon",
        system_context=(
            "You are running the WEB-RECON skill. Prefer subfinder/httpx/wappalyzer "
            "and finish with a compact inventory. Do NOT launch active exploit tools."
        ),
    ),
    Skill(
        id="vuln-scan",
        aliases=["vuln", "nuclei", "scan-vuln"],
        title="Vulnerability scan",
        description="Run Nuclei with severity critical,high against in-scope URLs.",
        scan_type="vulnerability",
        playbook_id="vuln_scan",
        default_args={"severity": "critical,high"},
        system_context=(
            "You are running the VULN-SCAN skill. Query existing assets/vulns first "
            "to avoid duplicate work, then run execute_nuclei -severity critical,high."
        ),
    ),
    Skill(
        id="js-recon",
        aliases=["jsrecon", "js"],
        title="JavaScript reconnaissance",
        description="JS secrets, endpoint extraction, source-map / dep-confusion / DOM-sink analysis.",
        scan_type="js_recon",
        system_context=(
            "You are running the JS-RECON skill. Inspect first-party JS bundles for "
            "leaked credentials, source maps, dependency-confusion candidates, and "
            "DOM-XSS sinks. Persist everything via create_finding when warranted."
        ),
    ),
    Skill(
        id="graphql",
        aliases=["gql", "graphql-audit"],
        title="GraphQL audit",
        description="Discover GraphQL endpoints and audit for introspection / CSRF / DoS.",
        scan_type="graphql_scan",
        system_context=(
            "You are running the GRAPHQL skill. Probe /graphql, /api/graphql and "
            "common IDE paths. Check introspection, field suggestions, GET/CSRF, "
            "and query batching limits."
        ),
    ),
    Skill(
        id="takeover",
        aliases=["subtakeover", "subdomain-takeover"],
        title="Subdomain takeover",
        description="CNAME-fingerprint + Nuclei takeover templates + optional Subjack.",
        scan_type="subdomain_takeover",
        system_context=(
            "You are running the TAKEOVER skill. Only subdomains with dangling "
            "CNAMEs / 404 fingerprints warrant HIGH severity findings."
        ),
    ),
    Skill(
        id="secrets",
        aliases=["trufflehog", "secret-scan"],
        title="Deep secret scan",
        description="TruffleHog with active verification across git repos, orgs, buckets.",
        scan_type="trufflehog_scan",
        system_context=(
            "You are running the SECRETS skill. Prefer ``--only-verified`` findings; "
            "raise LOW for unverified matches and CRITICAL for verified ones."
        ),
        required_inputs=["source"],
    ),
    Skill(
        id="llm-redteam",
        aliases=["llmredteam", "ai-redteam", "chatbot"],
        title="LLM / chatbot red team",
        description="OWASP LLM Top-10 evaluation against discovered chatbot endpoints.",
        scan_type="llm_red_team",
        playbook_id="llm_red_team",
        system_context=(
            "You are running the LLM-REDTEAM skill. Discover chat endpoints, confirm "
            "them with a benign message, then call execute_llm_red_team."
        ),
    ),
    Skill(
        id="fireteam",
        aliases=["scatter", "parallel-agents"],
        title="Fireteam (parallel specialists)",
        description="Scatter-gather: run web-recon, vuln-triage, secrets specialists in parallel.",
        system_context=(
            "You are the fireteam coordinator. Call fireteam_dispatch with an "
            "appropriate mission and the relevant specialist names."
        ),
        required_inputs=["mission"],
    ),
]


_BY_ID: dict[str, Skill] = {s.id: s for s in SKILLS}
_BY_ALIAS: dict[str, Skill] = {
    **_BY_ID,
    **{alias.lower(): s for s in SKILLS for alias in s.aliases},
}


def list_skills() -> list[dict]:
    return [
        {
            "id": s.id,
            "aliases": s.aliases,
            "title": s.title,
            "description": s.description,
            "scan_type": s.scan_type,
            "required_inputs": s.required_inputs,
        }
        for s in SKILLS
    ]


def get_skill(name: str) -> Optional[Skill]:
    return _BY_ALIAS.get((name or "").strip().lower().lstrip("/"))


# ---------------------------------------------------------------------------
# /skill prefix parsing
# ---------------------------------------------------------------------------


_SKILL_PREFIX_RE = re.compile(r"^\s*/skill\s+([a-zA-Z0-9_\-]+)\b(.*)$", re.DOTALL)
_SHORT_PREFIX_RE = re.compile(r"^\s*/([a-zA-Z0-9_\-]+)\b(.*)$", re.DOTALL)


def parse_skill_prefix(message: str) -> tuple[Optional[Skill], dict, str]:
    """
    Return ``(skill, parsed_args, stripped_message)``.

    Accepts both ``/skill <name> key=val ...`` and the shorter ``/<alias>
    key=val ...``. If no prefix matches the registered skills, returns
    ``(None, {}, message)`` unchanged.
    """
    if not message:
        return None, {}, message

    m = _SKILL_PREFIX_RE.match(message)
    if not m:
        m = _SHORT_PREFIX_RE.match(message)
        if not m:
            return None, {}, message
        name = m.group(1)
        if name.lower() not in _BY_ALIAS:
            return None, {}, message

    name = m.group(1)
    rest = (m.group(2) or "").strip()

    skill = get_skill(name)
    if not skill:
        return None, {}, message

    args: dict[str, Any] = dict(skill.default_args)
    free_text_parts: list[str] = []
    try:
        tokens = shlex.split(rest) if rest else []
    except ValueError:
        tokens = rest.split() if rest else []

    for tok in tokens:
        if "=" in tok:
            k, _, v = tok.partition("=")
            k = k.strip()
            v = v.strip()
            if not k:
                continue
            if "," in v:
                args[k] = [x.strip() for x in v.split(",") if x.strip()]
            else:
                args[k] = v
        else:
            free_text_parts.append(tok)

    free_text = " ".join(free_text_parts).strip()
    return skill, args, free_text


# ---------------------------------------------------------------------------
# Intent routing (light LLM classifier)
# ---------------------------------------------------------------------------


_INTENT_PROMPT = """\
You are an intent classifier for a security platform.

Given a user message, pick the single best-matching skill ID from the list
below, or return "none" if no skill matches. Respond with JSON only:

{{"skill": "<id-or-none>", "confidence": 0.0-1.0, "why": "<=15 words"}}

Available skills:
{skills}

User message:
{message}
"""


async def route_by_intent(message: str, llm: Any) -> Optional[dict]:
    """Use ``llm`` to classify the user's message into a skill.

    Returns ``{"skill": Skill, "confidence": float, "why": str}`` or ``None``
    if the classifier picks "none" or fails.
    """
    if not message or not message.strip():
        return None
    from langchain_core.messages import HumanMessage

    skill_list = "\n".join(
        f"- {s.id}: {s.description}" for s in SKILLS
    )
    prompt = _INTENT_PROMPT.format(skills=skill_list, message=message.strip())
    try:
        response = await llm.ainvoke([HumanMessage(content=prompt)])
        text = getattr(response, "content", "") or ""
    except Exception as exc:
        logger.debug("route_by_intent LLM failure: %s", exc)
        return None

    try:
        data = _extract_json(text) or {}
    except Exception:
        return None

    skill_id = (data.get("skill") or "").strip().lower()
    if not skill_id or skill_id == "none":
        return None
    skill = get_skill(skill_id)
    if not skill:
        return None
    conf = float(data.get("confidence") or 0.0)
    if conf < 0.5:
        return None
    return {"skill": skill, "confidence": conf, "why": data.get("why") or ""}


def _extract_json(text: str) -> Optional[dict]:
    if not text:
        return None
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        nl = text.find("\n")
        if nl >= 0:
            text = text[nl + 1:]
        if text.endswith("```"):
            text = text[:-3]
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start: end + 1])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Context injection
# ---------------------------------------------------------------------------


def build_skill_context(skill: Skill, args: dict, free_text: str = "") -> str:
    """Return the extra system-prompt block to inject when this skill runs."""
    parts = [
        f"## Active skill: {skill.title}",
        skill.system_context or "",
    ]
    if args:
        parts.append("Arguments:")
        for k, v in args.items():
            parts.append(f"- {k}: {v}")
    if free_text:
        parts.append(f"Extra user instructions: {free_text}")
    return "\n".join(p for p in parts if p)


def resolve(message: str) -> dict:
    """Convenience wrapper for frontend: parse a chat message and return
    a structured object the chat layer can render as either:

        * "We'll run the SKILL skill with these args..."  (prefix hit)
        * Pass-through, so the agent handles it directly  (no prefix)

    The caller is expected to also use :func:`route_by_intent` if they want
    natural-language routing when no prefix is present.
    """
    skill, args, rest = parse_skill_prefix(message)
    if not skill:
        return {"matched": False, "message": message}
    return {
        "matched": True,
        "skill": {
            "id": skill.id,
            "title": skill.title,
            "description": skill.description,
            "scan_type": skill.scan_type,
            "playbook_id": skill.playbook_id,
            "required_inputs": skill.required_inputs,
        },
        "args": args,
        "free_text": rest,
        "system_context": build_skill_context(skill, args, rest),
    }
