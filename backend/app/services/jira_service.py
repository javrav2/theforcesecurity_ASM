"""Atlassian Jira REST API v3 client for ASM vulnerability ticket creation."""

import base64
import logging
from typing import Any, Dict, List, Optional

import httpx

from app.models.jira_integration import JiraIntegration
from app.models.vulnerability import Vulnerability
from app.services.remediation_playbook_service import RemediationPlaybookService
from app.services.cwe_service import get_cwe_service

logger = logging.getLogger(__name__)


def _auth_header(email: str, api_token: str) -> str:
    credentials = f"{email}:{api_token}"
    encoded = base64.b64encode(credentials.encode()).decode()
    return f"Basic {encoded}"


def _base_url(hostname: str) -> str:
    host = hostname.rstrip("/")
    if not host.startswith("http"):
        host = f"https://{host}"
    return f"{host}/rest/api/3"


async def test_connection(hostname: str, email: str, api_token: str) -> Dict[str, Any]:
    """
    Test connection by calling /rest/api/3/myself.
    Returns {"ok": bool, "message": str, "display_name": str | None}.
    """
    url = f"{_base_url(hostname)}/myself"
    headers = {
        "Authorization": _auth_header(email, api_token),
        "Accept": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            return {"ok": True, "message": "Connection successful", "display_name": data.get("displayName")}
        elif resp.status_code == 401:
            return {"ok": False, "message": "Authentication failed — check your email and API token.", "display_name": None}
        else:
            return {"ok": False, "message": f"Jira returned HTTP {resp.status_code}", "display_name": None}
    except httpx.ConnectError:
        return {"ok": False, "message": f"Could not connect to {hostname} — verify the hostname.", "display_name": None}
    except Exception as exc:
        logger.exception("Jira test_connection error")
        return {"ok": False, "message": str(exc), "display_name": None}


async def get_projects(hostname: str, email: str, api_token: str) -> List[Dict[str, Any]]:
    """Return a list of accessible Jira projects."""
    url = f"{_base_url(hostname)}/project/search?maxResults=100&orderBy=name"
    headers = {
        "Authorization": _auth_header(email, api_token),
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return [
        {
            "key": p["key"],
            "name": p["name"],
            "project_type": p.get("projectTypeKey"),
        }
        for p in data.get("values", [])
    ]


async def get_issue_types(hostname: str, email: str, api_token: str, project_key: str) -> List[Dict[str, Any]]:
    """Return issue types available for a project."""
    url = f"{_base_url(hostname)}/project/{project_key}"
    headers = {
        "Authorization": _auth_header(email, api_token),
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return [
        {
            "id": it["id"],
            "name": it["name"],
            "description": it.get("description", ""),
        }
        for it in data.get("issueTypes", [])
    ]


def _severity_emoji(severity: str) -> str:
    return {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }.get((severity or "").lower(), "⚪")


def _build_adf_doc(sections: List[Dict]) -> Dict:
    """Wrap a list of ADF block nodes into a top-level doc node."""
    return {"version": 1, "type": "doc", "content": sections}


def _adf_heading(text: str, level: int = 2) -> Dict:
    return {
        "type": "heading",
        "attrs": {"level": level},
        "content": [{"type": "text", "text": text}],
    }


def _adf_para(text: str) -> Dict:
    return {
        "type": "paragraph",
        "content": [{"type": "text", "text": text}],
    }


def _adf_code_block(text: str, language: str = "text") -> Dict:
    return {
        "type": "codeBlock",
        "attrs": {"language": language},
        "content": [{"type": "text", "text": text}],
    }


def _adf_bullet_list(items: List[str]) -> Dict:
    return {
        "type": "bulletList",
        "content": [
            {
                "type": "listItem",
                "content": [_adf_para(item)],
            }
            for item in items
        ],
    }


def _adf_rule() -> Dict:
    return {"type": "rule"}


def _adf_ordered_list(items: List[Dict]) -> Dict:
    """Ordered list where each item is a list of ADF block nodes."""
    return {
        "type": "orderedList",
        "content": [
            {"type": "listItem", "content": blocks}
            for blocks in items
        ],
    }


def _adf_strong(text: str) -> Dict:
    return {"type": "text", "text": text, "marks": [{"type": "strong"}]}


def _adf_para_nodes(nodes: List[Dict]) -> Dict:
    return {"type": "paragraph", "content": nodes}


def _build_playbook_blocks(playbook: Dict) -> List[Dict]:
    """Convert a RemediationPlaybook dict into ADF block nodes."""
    blocks: List[Dict] = []

    blocks.append(_adf_heading("Remediation Playbook", 2))

    # Metadata summary
    meta_lines = [
        f"Summary: {playbook.get('summary', '')}",
        f"Estimated Time: {playbook.get('estimated_time', 'unknown')}",
        f"Effort: {playbook.get('effort', 'unknown').title()}",
        f"Priority: {playbook.get('priority', 'unknown').upper()}",
    ]
    access_list = playbook.get("required_access", [])
    if access_list:
        meta_lines.append(f"Required Access: {', '.join(a.replace('_', ' ').title() for a in access_list)}")
    blocks.append(_adf_bullet_list(meta_lines))

    impact = playbook.get("impact_if_not_fixed", "")
    if impact:
        blocks.append(_adf_para(f"⚠️ Impact if Not Fixed: {impact}"))

    # Numbered steps
    steps = playbook.get("steps", [])
    if steps:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Remediation Steps", 3))

        step_items: List[List[Dict]] = []
        for step in steps:
            item_blocks: List[Dict] = []

            # Step title + description
            label = f"Step {step['order']}: {step['title']}"
            if not step.get("is_required", True):
                label += " (optional)"
            elif step.get("is_alternative", False):
                label += " (alternative)"
            item_blocks.append(_adf_para_nodes([_adf_strong(label)]))
            item_blocks.append(_adf_para(step["description"]))

            # CLI command
            if step.get("command"):
                item_blocks.append(_adf_code_block(step["command"].strip(), "bash"))

            # Code snippet
            if step.get("code_snippet"):
                item_blocks.append(_adf_code_block(step["code_snippet"].strip()))

            # Notes/warnings
            if step.get("notes"):
                item_blocks.append(_adf_para(f"📝 Note: {step['notes']}"))

            step_items.append(item_blocks)

        blocks.append(_adf_ordered_list(step_items))

    # Verification steps
    verification = playbook.get("verification", [])
    if verification:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Verification Steps", 3))
        verify_items: List[List[Dict]] = []
        for v in verification:
            item_blocks = [
                _adf_para_nodes([_adf_strong(f"Step {v['order']}: {v['description']}")]),
                _adf_para(f"Expected: {v['expected_result']}"),
            ]
            if v.get("command"):
                item_blocks.append(_adf_code_block(v["command"].strip(), "bash"))
            verify_items.append(item_blocks)
        blocks.append(_adf_ordered_list(verify_items))

    # Common mistakes
    common_mistakes = playbook.get("common_mistakes", [])
    if common_mistakes:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Common Mistakes to Avoid", 3))
        blocks.append(_adf_bullet_list(common_mistakes))

    return blocks


def _build_description(
    vuln: Vulnerability,
    include_description: bool,
    include_evidence: bool,
    include_remediation: bool,
    include_references: bool,
    include_enrichment: bool,
    playbook: Optional[Dict] = None,
    cwe_info: Optional[Dict] = None,
) -> Dict:
    """Build an Atlassian Document Format description for the Jira issue."""
    blocks: List[Dict] = []

    asset_value = vuln.asset.value if vuln.asset else "Unknown"
    severity_str = f"{_severity_emoji(vuln.severity.value)} {vuln.severity.value.upper()}"

    # Overview section
    blocks.append(_adf_heading("Overview", 2))
    overview_lines = [
        f"Severity: {severity_str}",
        f"Affected Asset: {asset_value}",
        f"Status: {(vuln.status.value if vuln.status else 'open').replace('_', ' ').title()}",
        f"Detected By: {vuln.detected_by or 'unknown'}",
    ]
    if vuln.cve_id:
        overview_lines.append(f"CVE: {vuln.cve_id}")
    if vuln.cwe_id:
        overview_lines.append(f"CWE: {vuln.cwe_id}")
    if vuln.cvss_score is not None:
        overview_lines.append(f"CVSS Score: {vuln.cvss_score:.1f}")
    blocks.append(_adf_bullet_list(overview_lines))

    # Description
    if include_description and vuln.description:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Description", 2))
        blocks.append(_adf_para(vuln.description))

    # Evidence
    if include_evidence and vuln.evidence:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("Evidence", 2))
        blocks.append(_adf_code_block(vuln.evidence[:2000]))

    # Proof of Concept
    if include_evidence and vuln.proof_of_concept:
        blocks.append(_adf_heading("Proof of Concept", 3))
        blocks.append(_adf_code_block(vuln.proof_of_concept[:2000]))

    # Steps to reproduce
    if include_evidence and vuln.steps_to_reproduce:
        blocks.append(_adf_heading("Steps to Reproduce", 3))
        blocks.append(_adf_para(vuln.steps_to_reproduce))

    # Remediation — structured playbook takes priority over the raw remediation text
    if include_remediation:
        if playbook:
            blocks.append(_adf_rule())
            blocks.extend(_build_playbook_blocks(playbook))
        elif vuln.remediation:
            blocks.append(_adf_rule())
            blocks.append(_adf_heading("Remediation", 2))
            blocks.append(_adf_para(vuln.remediation))

        # CWE-based guidance (appended regardless of playbook presence)
        if cwe_info:
            blocks.append(_adf_heading("CWE Guidance", 3))
            cwe_lines = [f"{cwe_info.get('cwe_id', '')}: {cwe_info.get('name', '')}"]
            if cwe_info.get("description"):
                cwe_lines.append(cwe_info["description"][:300])
            mitigations = cwe_info.get("mitigations", [])
            if mitigations:
                cwe_lines.append("Mitigations: " + "; ".join(str(m) for m in mitigations[:3]))
            blocks.append(_adf_bullet_list(cwe_lines))

    # Enrichment (Delphi + Oracle)
    if include_enrichment and vuln.metadata_ and isinstance(vuln.metadata_, dict):
        delphi = vuln.metadata_.get("delphi")
        if delphi:
            blocks.append(_adf_rule())
            blocks.append(_adf_heading("Threat Intelligence (Delphi)", 2))
            delphi_lines = []
            if delphi.get("kev"):
                kev = delphi["kev"]
                delphi_lines.append("⚠️ CISA Known Exploited Vulnerability (KEV)")
                if kev.get("required_action"):
                    delphi_lines.append(f"Required Action: {kev['required_action']}")
                if kev.get("due_date"):
                    delphi_lines.append(f"CISA Due Date: {kev['due_date']}")
            if delphi.get("epss"):
                epss = delphi["epss"]
                delphi_lines.append(
                    f"EPSS Score: {epss.get('score', 0):.3f} "
                    f"(percentile: {epss.get('percentile', 0) * 100:.1f}%)"
                )
            if delphi.get("priority") and delphi["priority"] != "none":
                delphi_lines.append(f"Delphi Priority: {delphi['priority'].upper()}")
            if delphi_lines:
                blocks.append(_adf_bullet_list(delphi_lines))

        oracle = vuln.metadata_.get("oracle")
        if oracle and oracle.get("opes_category"):
            blocks.append(_adf_heading("Aegis Oracle OPES Analysis", 3))
            oracle_lines = [
                f"OPES Category: {oracle['opes_category']}",
            ]
            if oracle.get("opes_score") is not None:
                oracle_lines.append(f"OPES Score: {oracle['opes_score']:.1f}")
            if oracle.get("opes_label"):
                oracle_lines.append(f"Label: {oracle['opes_label']}")
            if oracle.get("attack_path_class"):
                oracle_lines.append(f"Attack Path: {oracle['attack_path_class']}")
            if oracle.get("recommendation_text"):
                oracle_lines.append(f"Recommendation: {oracle['recommendation_text'][:300]}")
            blocks.append(_adf_bullet_list(oracle_lines))

    # References
    refs = list(vuln.references or [])
    if include_references and refs:
        blocks.append(_adf_rule())
        blocks.append(_adf_heading("References", 2))
        blocks.append(_adf_bullet_list(refs[:10]))

    # Footer
    blocks.append(_adf_rule())
    blocks.append(_adf_para("This ticket was created automatically by Judah Security ASM."))

    return _build_adf_doc(blocks)


async def create_jira_ticket(
    integration: JiraIntegration,
    vuln: Vulnerability,
    project_key: str,
    issue_type: str = "Bug",
    include_description: bool = True,
    include_evidence: bool = True,
    include_remediation: bool = True,
    include_references: bool = True,
    include_enrichment: bool = True,
    assignee_account_id: Optional[str] = None,
    extra_labels: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Create a Jira issue from a vulnerability.
    Returns Jira's response (contains 'id', 'key', 'self').
    """
    url = f"{_base_url(integration.hostname)}/issue"
    headers = {
        "Authorization": _auth_header(integration.email, integration.api_token),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    severity_str = vuln.severity.value if vuln.severity else "unknown"
    asset_value = vuln.asset.value if vuln.asset else "unknown"
    title = f"[ASM] [{severity_str.upper()}] {vuln.title or vuln.template_id}"
    if len(title) > 255:
        title = title[:252] + "..."

    labels = [f"asm-{severity_str}", "judah-security"]
    if vuln.cve_id:
        labels.append(vuln.cve_id.replace(" ", "-"))
    if extra_labels:
        labels.extend(extra_labels)

    # Fetch structured remediation playbook + CWE guidance
    playbook_dict: Optional[Dict] = None
    cwe_info: Optional[Dict] = None
    if include_remediation:
        try:
            playbook_obj = RemediationPlaybookService.get_playbook_for_finding(
                title=vuln.title,
                template_id=vuln.template_id,
                port=vuln.metadata_.get("port") if vuln.metadata_ else None,
                tags=vuln.tags or [],
                cwe_id=vuln.cwe_id,
                cve_id=vuln.cve_id,
            )
            if playbook_obj:
                playbook_dict = playbook_obj.to_dict()
        except Exception:
            logger.warning("Could not fetch remediation playbook for vuln %s", vuln.id)

        if vuln.cwe_id:
            try:
                cwe_info = get_cwe_service().get_dict(vuln.cwe_id)
            except Exception:
                logger.warning("Could not fetch CWE info for %s", vuln.cwe_id)

    description_adf = _build_description(
        vuln=vuln,
        include_description=include_description,
        include_evidence=include_evidence,
        include_remediation=include_remediation,
        include_references=include_references,
        include_enrichment=include_enrichment,
        playbook=playbook_dict,
        cwe_info=cwe_info,
    )

    fields: Dict[str, Any] = {
        "project": {"key": project_key},
        "summary": title,
        "issuetype": {"name": issue_type},
        "description": description_adf,
        "labels": labels,
    }

    if assignee_account_id:
        fields["assignee"] = {"accountId": assignee_account_id}

    payload = {"fields": fields}

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, headers=headers, json=payload)

    if resp.status_code not in (200, 201):
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        raise ValueError(f"Jira API error {resp.status_code}: {detail}")

    data = resp.json()
    issue_key = data["key"]
    hostname = integration.hostname.rstrip("/")
    if not hostname.startswith("http"):
        hostname = f"https://{hostname}"
    issue_url = f"{hostname}/browse/{issue_key}"

    return {"key": issue_key, "url": issue_url, "id": data.get("id")}
