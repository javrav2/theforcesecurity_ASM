"""Preset playbook objectives for the agent. No full playbook engine; just rich initial objectives and optional todos."""

from typing import List, Dict, Any, Optional

PLAYBOOKS: List[Dict[str, Any]] = [
    {
        "id": "web_assessment",
        "name": "Web assessment",
        "description": "Structured web application assessment: discovery then vulnerability scanning.",
        "objective": (
            "Perform a structured web application assessment. "
            "1) Discovery: identify technologies, endpoints, and authentication mechanisms using query_assets, query_technologies, execute_httpx, execute_katana. "
            "2) Vulnerability scanning: run Nuclei with severity critical,high on discovered URLs. "
            "3) Summarize findings and recommend remediation. Stay within the organization's scope."
        ),
        "initial_todos": [
            {"description": "Enumerate technologies and endpoints", "status": "pending", "priority": "high"},
            {"description": "Run Nuclei with severity critical,high", "status": "pending", "priority": "high"},
            {"description": "Summarize findings and remediation", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "quick_recon",
        "name": "Quick recon",
        "description": "Fast reconnaissance: subdomains, DNS, and HTTP probing.",
        "objective": (
            "Perform quick reconnaissance on the target. "
            "1) Discover subdomains (execute_subfinder, execute_dnsx). "
            "2) Probe HTTP with execute_httpx. "
            "3) Report open ports and live hosts. Use query_assets first to see existing scope."
        ),
        "initial_todos": [
            {"description": "Subdomain and DNS discovery", "status": "pending", "priority": "high"},
            {"description": "HTTP probing and live host list", "status": "pending", "priority": "high"},
            {"description": "Brief recon summary", "status": "pending", "priority": "medium"},
        ],
    },
    {
        "id": "vuln_scan",
        "name": "Vuln scan",
        "description": "Vulnerability scan with Nuclei on in-scope assets.",
        "objective": (
            "Run a vulnerability scan focused on critical and high severity. "
            "1) Use query_assets and query_vulnerabilities to see current scope and existing findings. "
            "2) Run Nuclei (execute_nuclei) on in-scope web URLs with -severity critical,high. "
            "3) Summarize new and existing critical/high findings and remediation steps."
        ),
        "initial_todos": [
            {"description": "Review scope and existing vulns", "status": "pending", "priority": "high"},
            {"description": "Run Nuclei critical,high on targets", "status": "pending", "priority": "high"},
            {"description": "Summarize findings", "status": "pending", "priority": "medium"},
        ],
    },
]


def get_playbook(playbook_id: str) -> Optional[Dict[str, Any]]:
    """Return preset by id or None."""
    for p in PLAYBOOKS:
        if p["id"] == playbook_id:
            return p
    return None


def list_playbooks() -> List[Dict[str, Any]]:
    """Return list of { id, name, description } for UI."""
    return [
        {"id": p["id"], "name": p["name"], "description": p["description"]}
        for p in PLAYBOOKS
    ]


def build_initial_objective(playbook_id: str, target: Optional[str] = None) -> tuple:
    """
    Build (objective_string, initial_todos) for the given preset and optional target.
    Returns (objective, initial_todos); objective includes target line if target is set.
    """
    p = get_playbook(playbook_id)
    if not p:
        return ("", [])
    objective = p["objective"]
    if target and target.strip():
        objective = f"{objective}\n\nTarget: {target.strip()}"
    return (objective, p.get("initial_todos", []))
