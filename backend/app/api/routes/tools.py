"""Tools status and management API routes."""

import subprocess
import shutil
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.api.deps import get_current_active_user
from app.models.user import User
from app.models.api_config import APIConfig

router = APIRouter(prefix="/tools", tags=["Tools"])


# Tool definitions with their check commands and categories
TOOLS = {
    # Installed CLI Tools
    "nuclei": {
        "name": "Nuclei",
        "description": "Fast vulnerability scanner with YAML-based templates",
        "category": "vulnerability",
        "type": "cli",
        "check_command": ["nuclei", "-version"],
        "installed": False,
        "version": None,
    },
    "subfinder": {
        "name": "Subfinder",
        "description": "ProjectDiscovery subdomain enumeration tool",
        "category": "dns",
        "type": "cli",
        "check_command": ["subfinder", "-version"],
        "installed": False,
        "version": None,
    },
    "httpx": {
        "name": "HTTPX",
        "description": "Multi-purpose HTTP toolkit with probing capabilities",
        "category": "http",
        "type": "cli",
        "check_command": ["httpx", "-version"],
        "installed": False,
        "version": None,
    },
    "naabu": {
        "name": "Naabu",
        "description": "Fast port scanner with focus on reliability",
        "category": "ports",
        "type": "cli",
        "check_command": ["naabu", "-version"],
        "installed": False,
        "version": None,
    },
    "katana": {
        "name": "Katana",
        "description": "Next-gen crawling and spidering framework",
        "category": "crawler",
        "type": "cli",
        "check_command": ["katana", "-version"],
        "installed": False,
        "version": None,
    },
    "waybackurls": {
        "name": "Wayback Machine",
        "description": "Historical subdomain discovery from web archives",
        "category": "passive",
        "type": "cli",
        "check_command": ["waybackurls", "-h"],
        "installed": False,
        "version": None,
    },
    "masscan": {
        "name": "Masscan",
        "description": "Fast port scanner with banner grabbing",
        "category": "ports",
        "type": "cli",
        "check_command": ["masscan", "--version"],
        "installed": False,
        "version": None,
    },
    "nmap": {
        "name": "Nmap",
        "description": "Advanced port scanner with NSE scripts for service detection",
        "category": "ports",
        "type": "cli",
        "check_command": ["nmap", "--version"],
        "installed": False,
        "version": None,
    },
    "dnsx": {
        "name": "dnsx",
        "description": "Fast DNS resolver and enumeration tool",
        "category": "dns",
        "type": "cli",
        "check_command": ["dnsx", "-version"],
        "installed": False,
        "version": None,
    },
    "eyewitness": {
        "name": "EyeWitness",
        "description": "Screenshot and header capture for web assets",
        "category": "screenshot",
        "type": "cli",
        "check_command": None,  # Python script, check differently
        "check_path": "/opt/EyeWitness/Python/EyeWitness.py",
        "installed": False,
        "version": None,
    },
    # API-based services
    "whoisxml_netblocks": {
        "name": "WhoisXML IP Netblocks",
        "description": "Organization IP netblock discovery",
        "category": "whois",
        "type": "api",
        "service_name": "whoisxml_netblocks",
        "configured": False,
    },
    "whoxy": {
        "name": "Whoxy API",
        "description": "WHOIS lookups and domain intelligence",
        "category": "whois",
        "type": "api",
        "service_name": "whoxy",
        "configured": False,
    },
    "ip2location": {
        "name": "IP2Location / ip-api.com",
        "description": "IP geolocation lookup for mapping asset locations",
        "category": "intelligence",
        "type": "builtin",
        "configured": True,
    },
    # Passive/Free services
    "crtsh": {
        "name": "crt.sh",
        "description": "Certificate Transparency log subdomain enumeration",
        "category": "passive",
        "type": "builtin",
        "configured": True,
    },
    "wappalyzer": {
        "name": "Wappalyzer",
        "description": "Technology detection for web applications",
        "category": "technology",
        "type": "builtin",
        "configured": True,
    },
    # Not yet installed
    "amass": {
        "name": "OWASP Amass",
        "description": "In-depth attack surface mapping and asset discovery",
        "category": "dns",
        "type": "cli",
        "check_command": ["amass", "version"],
        "installed": False,
        "version": None,
    },
    "rustscan": {
        "name": "RustScan",
        "description": "Modern fast port scanner with adaptive timing",
        "category": "ports",
        "type": "cli",
        "check_command": ["rustscan", "--version"],
        "installed": False,
        "version": None,
    },
    "massdns": {
        "name": "MassDNS",
        "description": "High-performance DNS resolver for subdomain enumeration",
        "category": "dns",
        "type": "cli",
        "check_command": ["massdns", "--help"],
        "installed": False,
        "version": None,
    },
    "paramspider": {
        "name": "ParamSpider",
        "description": "Web parameter discovery with filtering",
        "category": "crawler",
        "type": "cli",
        "check_command": ["paramspider", "-h"],
        "installed": False,
        "version": None,
    },
    # API services not yet configured
    "virustotal": {
        "name": "VirusTotal",
        "description": "Domain and IP threat analysis and reputation",
        "category": "intelligence",
        "type": "api",
        "service_name": "virustotal",
        "configured": False,
    },
    "alienvault": {
        "name": "AlienVault OTX",
        "description": "Threat intelligence and passive DNS data",
        "category": "intelligence",
        "type": "api",
        "service_name": "alienvault_otx",
        "configured": False,
    },
    "chaos": {
        "name": "Chaos",
        "description": "ProjectDiscovery subdomain dataset for passive recon",
        "category": "passive",
        "type": "api",
        "service_name": "chaos",
        "configured": False,
    },
    "certspotter": {
        "name": "CertSpotter",
        "description": "Certificate transparency log monitoring by SSLMate",
        "category": "passive",
        "type": "api",
        "service_name": "certspotter",
        "configured": False,
    },
    "rapiddns": {
        "name": "RapidDNS",
        "description": "Fast subdomain enumeration via RapidDNS",
        "category": "passive",
        "type": "builtin",
        "configured": True,  # Free API
    },
    "commoncrawl": {
        "name": "Common Crawl",
        "description": "Passive subdomain discovery from web archives",
        "category": "passive",
        "type": "builtin",
        "configured": True,  # Free API
    },
}

# Categories for grouping
CATEGORIES = {
    "vulnerability": {"name": "Vulnerability Scanning", "icon": "shield"},
    "dns": {"name": "DNS & Subdomain Enumeration", "icon": "globe"},
    "ports": {"name": "Port Scanning", "icon": "network"},
    "http": {"name": "HTTP Analysis", "icon": "globe"},
    "crawler": {"name": "Web Crawling", "icon": "spider"},
    "passive": {"name": "Passive Reconnaissance", "icon": "search"},
    "screenshot": {"name": "Screenshot Capture", "icon": "camera"},
    "whois": {"name": "WHOIS & Domain Intel", "icon": "info"},
    "intelligence": {"name": "Threat Intelligence", "icon": "alert"},
    "technology": {"name": "Technology Detection", "icon": "cpu"},
    "cloud": {"name": "Cloud Enumeration", "icon": "cloud"},
}


def check_cli_tool(tool_config: dict) -> dict:
    """Check if a CLI tool is installed and get its version."""
    result = tool_config.copy()
    
    if tool_config.get("check_path"):
        # Check if file exists
        import os
        result["installed"] = os.path.exists(tool_config["check_path"])
        if result["installed"]:
            result["version"] = "Installed"
        return result
    
    if not tool_config.get("check_command"):
        return result
    
    try:
        # Check if command exists
        if shutil.which(tool_config["check_command"][0]):
            result["installed"] = True
            # Try to get version
            try:
                proc = subprocess.run(
                    tool_config["check_command"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                output = proc.stdout or proc.stderr
                # Extract version from first line
                if output:
                    lines = output.strip().split('\n')
                    result["version"] = lines[0][:100]  # Limit length
            except:
                result["version"] = "Unknown"
        else:
            result["installed"] = False
    except Exception as e:
        result["installed"] = False
        result["error"] = str(e)
    
    return result


def check_api_tool(tool_config: dict, db: Session) -> dict:
    """Check if an API tool is configured."""
    result = tool_config.copy()
    
    if tool_config.get("type") == "builtin":
        result["configured"] = True
        return result
    
    service_name = tool_config.get("service_name")
    if not service_name:
        return result
    
    # Check if API key exists in database
    config = db.query(APIConfig).filter(
        APIConfig.service_name == service_name,
        APIConfig.is_active == True
    ).first()
    
    result["configured"] = config is not None
    if config:
        result["organization_id"] = config.organization_id
    
    return result


@router.get("/status")
def get_tools_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get status of all enumeration tools."""
    tools_status = {}
    
    for tool_id, tool_config in TOOLS.items():
        if tool_config["type"] == "cli":
            tools_status[tool_id] = check_cli_tool(tool_config)
        else:
            tools_status[tool_id] = check_api_tool(tool_config, db)
    
    # Group by category
    by_category = {}
    for tool_id, tool_data in tools_status.items():
        category = tool_data.get("category", "other")
        if category not in by_category:
            by_category[category] = {
                **CATEGORIES.get(category, {"name": category, "icon": "tool"}),
                "tools": []
            }
        by_category[category]["tools"].append({
            "id": tool_id,
            **tool_data
        })
    
    # Calculate summary
    total = len(tools_status)
    installed_cli = sum(1 for t in tools_status.values() if t.get("type") == "cli" and t.get("installed"))
    configured_api = sum(1 for t in tools_status.values() if t.get("type") in ["api", "builtin"] and t.get("configured"))
    
    return {
        "summary": {
            "total_tools": total,
            "cli_tools_installed": installed_cli,
            "cli_tools_total": sum(1 for t in tools_status.values() if t.get("type") == "cli"),
            "api_tools_configured": configured_api,
            "api_tools_total": sum(1 for t in tools_status.values() if t.get("type") in ["api", "builtin"]),
        },
        "tools": tools_status,
        "by_category": by_category,
        "categories": CATEGORIES,
    }


@router.get("/categories")
def get_tool_categories():
    """Get tool categories."""
    return CATEGORIES


@router.get("/{tool_id}")
def get_tool_status(
    tool_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Get status of a specific tool."""
    if tool_id not in TOOLS:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found")
    
    tool_config = TOOLS[tool_id]
    
    if tool_config["type"] == "cli":
        return check_cli_tool(tool_config)
    else:
        return check_api_tool(tool_config, db)


@router.post("/{tool_id}/test")
async def test_tool(
    tool_id: str,
    target: Optional[str] = "example.com",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    """Test a specific tool with a sample target."""
    if tool_id not in TOOLS:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_id}' not found")
    
    tool_config = TOOLS[tool_id]
    
    if tool_config["type"] != "cli":
        return {"error": "Only CLI tools can be tested directly"}
    
    # Map tool to test command
    test_commands = {
        "nuclei": ["nuclei", "-u", target, "-silent", "-no-update-templates", "-timeout", "10"],
        "subfinder": ["subfinder", "-d", target, "-silent", "-timeout", "10"],
        "httpx": ["httpx", "-u", f"https://{target}", "-silent", "-timeout", "10"],
        "naabu": ["naabu", "-host", target, "-top-ports", "10", "-silent"],
        "masscan": ["masscan", target, "-p80", "--rate=100", "--wait=0"],
        "nmap": ["nmap", "-sT", "-p80", "--open", target],
        "dnsx": ["dnsx", "-d", target, "-silent"],
    }
    
    if tool_id not in test_commands:
        return {"error": f"No test command configured for {tool_id}"}
    
    try:
        proc = subprocess.run(
            test_commands[tool_id],
            capture_output=True,
            text=True,
            timeout=30
        )
        return {
            "success": proc.returncode == 0,
            "stdout": proc.stdout[:2000] if proc.stdout else None,
            "stderr": proc.stderr[:2000] if proc.stderr else None,
            "return_code": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out after 30 seconds"}
    except Exception as e:
        return {"error": str(e)}


