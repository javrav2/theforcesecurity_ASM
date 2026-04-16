"""
Specialized Security Agents for NanoClaw

Defines the multi-agent architecture:
  Orchestrator -> Recon Agent -> Vuln Agent -> Exploit Agent -> Report Agent

Each agent has focused instructions, specific tools, and knows
when to hand off to the next agent in the chain.
"""

import json
import logging
from typing import List

from agent.core import Agent
from agent.tools import security_tool, ToolRegistry

logger = logging.getLogger("agent.agents")

# Ensure scanners module is importable (adds /agent to path if needed)
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from asm_bridge import ASMBridge

_bridge = None

def _get_bridge() -> ASMBridge:
    global _bridge
    if _bridge is None:
        _bridge = ASMBridge()
    return _bridge


# =========================================================================
# Registered Security Tools (wrapped scanners for LLM tool-calling)
# =========================================================================

@security_tool(category="recon", risk="safe")
def scan_subdomains(domain: str, timeout: int = 300) -> str:
    """Enumerate subdomains for a domain using subfinder passive sources.

    Args:
        domain: Root domain to enumerate (e.g. example.com)
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_subfinder(domain, _get_bridge(), timeout=timeout)
    return json.dumps({"subdomains": results, "count": len(results)})


@security_tool(category="recon", risk="safe")
def resolve_dns(hosts: list, timeout: int = 300) -> str:
    """Resolve hostnames to IPs using dnsx.

    Args:
        hosts: List of hostnames to resolve
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_dnsx(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"resolved": results, "count": len(results)})


@security_tool(category="recon", risk="safe")
def probe_http(hosts: list, timeout: int = 300) -> str:
    """Probe hosts for live HTTP services, detect technologies and status codes.

    Args:
        hosts: List of hostnames or IPs to probe
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_httpx(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"live_hosts": results, "count": len(results)}, default=str)


@security_tool(category="recon", risk="low")
def scan_ports(target: str, ports: str = "top-1000", rate: int = 1000, timeout: int = 600) -> str:
    """Fast port scanning using naabu.

    Args:
        target: Host or IP to scan
        ports: Port spec (top-1000, full, or specific like 80,443,8080)
        rate: Packets per second
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_naabu(target, _get_bridge(), ports=ports, rate=rate, timeout=timeout)
    return json.dumps({"ports": results, "count": len(results)}, default=str)


@security_tool(category="recon", risk="low")
def scan_ports_nmap(target: str, ports: str = "1-1000", args: str = "-sV -sC", timeout: int = 900) -> str:
    """Service detection and scripting via nmap.

    Args:
        target: Host or IP to scan
        ports: Port range
        args: Nmap arguments
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_nmap(target, _get_bridge(), ports=ports, args=args, timeout=timeout)
    return json.dumps({"services": results, "count": len(results)}, default=str)


@security_tool(category="recon", risk="safe")
def fingerprint_tech(target_url: str, timeout: int = 300) -> str:
    """Identify technologies, frameworks, and CMS using whatweb.

    Args:
        target_url: URL to fingerprint
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_whatweb(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"technologies": results}, default=str)


@security_tool(category="recon", risk="safe")
def detect_waf(target_url: str, timeout: int = 120) -> str:
    """Detect Web Application Firewall using wafw00f.

    Args:
        target_url: URL to check for WAF
        timeout: Max seconds to run
    """
    import scanners
    waf = scanners.run_wafw00f(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"waf_detected": waf or None})


@security_tool(category="recon", risk="safe")
def detect_cms(target_url: str, timeout: int = 300) -> str:
    """Detect Content Management System using CMSeeK.

    Args:
        target_url: URL to check for CMS
        timeout: Max seconds to run
    """
    import scanners
    cms = scanners.run_cmseek(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"cms_detected": cms or None})


@security_tool(category="recon", risk="safe")
def crawl_urls(target_url: str, depth: int = 5, timeout: int = 600) -> str:
    """Crawl a web application to discover URLs and endpoints using katana.

    Args:
        target_url: Starting URL to crawl
        depth: Crawl depth
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_katana(target_url, _get_bridge(), depth=depth, timeout=timeout)
    return json.dumps({"urls": results[:400], "total_count": len(results)})


@security_tool(category="recon", risk="safe")
def scan_js_urls_for_secrets(urls: str, max_urls: int = 30) -> str:
    """Download remote JavaScript or text URLs and scan for hardcoded secrets (Gitleaks + regex).

    Use after crawl_urls or discover_historical_urls: pass discovered .js URLs (newline- or comma-separated).

    Args:
        urls: Newline- or comma-separated https URLs to fetch and scan
        max_urls: Maximum URLs to fetch (default 30, max 100)
    """
    import scanners
    try:
        mu = int(max_urls) if max_urls is not None else 30
    except (TypeError, ValueError):
        mu = 30
    result = scanners.run_js_url_secret_scan(urls, _get_bridge(), max_urls=mu)
    return json.dumps(result, default=str)


@security_tool(category="recon", risk="safe")
def discover_historical_urls(domain: str, timeout: int = 300) -> str:
    """Find historical URLs from Wayback Machine and other archives.

    Args:
        domain: Domain to search historical URLs for
        timeout: Max seconds to run
    """
    import scanners
    wb = scanners.run_waybackurls(domain, _get_bridge(), timeout=timeout)
    gau_urls = scanners.run_gau(domain, _get_bridge(), timeout=timeout)
    combined = list(set(wb + gau_urls))
    return json.dumps({"urls": combined[:300], "total_count": len(combined)})


@security_tool(category="recon", risk="low")
def fuzz_directories(target_url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", timeout: int = 600) -> str:
    """Fuzz directories and API paths using ffuf.

    Args:
        target_url: Base URL to fuzz (FUZZ keyword appended automatically)
        wordlist: Path to wordlist file
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_ffuf(target_url, _get_bridge(), wordlist=wordlist, timeout=timeout)
    return json.dumps({"paths": results, "count": len(results)}, default=str)


@security_tool(category="recon", risk="low")
def discover_parameters(target_url: str, timeout: int = 300) -> str:
    """Discover hidden HTTP parameters on an endpoint using arjun.

    Args:
        target_url: URL to discover parameters on
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_arjun(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"parameters": results, "count": len(results)})


# --- Vulnerability Analysis Tools ---

@security_tool(category="recon", risk="safe")
def discover_org_assets(
    org: str,
    domain: str = "",
    asn: str = "",
    mode: str = "passive",
    timeout: int = 900,
) -> str:
    """Organizational attack-surface discovery using Praetorian pius.

    Given a company name, discovers owned domains, subdomains, and IP netblocks
    (CIDRs) across all 5 RIRs using 24+ OSINT plugins (CT logs, passive DNS,
    WHOIS, GLEIF, BGP, etc.). Each result is streamed to the ASM platform.

    Args:
        org: Organization / company name (required, e.g. "Acme Corp")
        domain: Optional known root domain hint (unlocks crt-sh, DNS plugins)
        asn: Optional ASN hint (e.g. "AS12345") for direct BGP lookup
        mode: "passive" (default, safe), "active", or "all"
        timeout: Max seconds to run
    """
    import scanners
    summary = scanners.run_pius(
        org=org,
        bridge=_get_bridge(),
        domain=domain or None,
        asn=asn or None,
        mode=mode,
        timeout=timeout,
    )
    return json.dumps(summary, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def scan_secrets_titus(path: str, validate: bool = False, timeout: int = 900) -> str:
    """Scan a filesystem path (directory / file / local git repo) for leaked secrets with Praetorian titus.

    Uses 487 detection rules covering AWS, GCP, Azure, GitHub, Slack, databases,
    CI/CD, etc. When validate=True, detected secrets are checked against their
    source APIs and marked active/inactive (slower, makes outbound requests).

    Args:
        path: Absolute filesystem path (directory, file, or git clone) to scan
        validate: Enable live credential validation (default False)
        timeout: Max seconds to run
    """
    import scanners
    findings = scanners.run_titus(
        path=path,
        bridge=_get_bridge(),
        validate=validate,
        timeout=timeout,
    )
    return json.dumps({"findings": findings, "count": len(findings)}, default=str)


@security_tool(category="vuln_analysis", risk="low")
def scan_nuclei(target: str, templates: str = "", severity: str = "low,medium,high,critical", timeout: int = 900) -> str:
    """Run nuclei vulnerability scanner with template-based detection.

    Args:
        target: URL or host to scan
        templates: Specific template path/tag (empty = all templates)
        severity: Comma-separated severity filter
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_nuclei(
        target, _get_bridge(), templates=templates or None, severity=severity, timeout=timeout,
    )
    summary = []
    for v in results:
        info = v.get("info", {})
        summary.append({
            "template": v.get("template-id"),
            "name": info.get("name"),
            "severity": info.get("severity"),
            "matched_at": v.get("matched-at"),
            "tags": info.get("tags", [])[:5],
        })
    return json.dumps({"vulnerabilities": summary, "count": len(summary)}, default=str)


@security_tool(category="vuln_analysis", risk="low")
def scan_nikto(target: str, timeout: int = 600) -> str:
    """Web server vulnerability scanning via nikto.

    Args:
        target: URL to scan
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_nikto(target, _get_bridge(), timeout=timeout)
    return json.dumps({"findings": results, "count": len(results)}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def analyze_security_headers(hosts: list, timeout: int = 300) -> str:
    """Check security headers (HSTS, CSP, X-Frame-Options, CORS) on live hosts.

    Args:
        hosts: List of hostnames to analyze
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_security_headers(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results, "count": len(results)}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def analyze_tls(hosts: list, timeout: int = 300) -> str:
    """Deep TLS/SSL analysis: cipher grading, cert scoring A-F, key analysis.

    Args:
        hosts: List of hostnames to analyze TLS on
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_tlsx(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results, "count": len(results)}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def check_subdomain_takeover(hosts: list, timeout: int = 300) -> str:
    """Check subdomains for dangling CNAME takeover vulnerabilities (55+ fingerprints).

    Args:
        hosts: List of subdomains to check
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_subdomain_takeover(hosts, _get_bridge(), timeout=timeout)
    risky = [r for r in results if r.get("status") in ("confirmed", "potential")]
    return json.dumps({"results": results, "at_risk": len(risky), "total": len(results)}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def analyze_mail_security(domains: list, timeout: int = 300) -> str:
    """Map mail infrastructure: MX, SPF, DKIM, DMARC, BIMI, MTA-STS, DANE with risk scoring.

    Args:
        domains: List of root domains to analyze
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_mail_intel(domains, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results}, default=str)


@security_tool(category="vuln_analysis", risk="safe")
def detect_third_party_vendors(hosts: list, timeout: int = 300) -> str:
    """Detect third-party vendors from response body, CSP headers, and JS sources.

    Args:
        hosts: List of hostnames to analyze
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_third_party_intel(hosts, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results}, default=str)


# --- Exploit Validation Tools ---

@security_tool(category="exploit", risk="high")
def sql_injection_test(target_url: str, timeout: int = 600) -> str:
    """Test a URL for SQL injection using sqlmap in safe batch mode.

    Args:
        target_url: URL with parameters to test (e.g. https://site.com/page?id=1)
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_sqlmap(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results, "vulnerable": len(results) > 0}, default=str)


@security_tool(category="exploit", risk="high")
def xss_test(target_url: str, timeout: int = 300) -> str:
    """Test a URL for Cross-Site Scripting using XSStrike.

    Args:
        target_url: URL with parameters to test for XSS
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_xsstrike(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"results": results, "vulnerable": len(results) > 0}, default=str)


@security_tool(category="exploit", risk="medium")
def wordpress_scan(target_url: str, timeout: int = 600) -> str:
    """Scan a WordPress site for vulnerabilities using wpscan.

    Args:
        target_url: WordPress site URL
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_wpscan(target_url, _get_bridge(), timeout=timeout)
    return json.dumps({"findings": results, "count": len(results)}, default=str)


@security_tool(category="exploit", risk="medium")
def deep_tls_test(target: str, timeout: int = 600) -> str:
    """Comprehensive TLS testing via testssl.sh for hosts with poor TLS grades.

    Args:
        target: Hostname to test
        timeout: Max seconds to run
    """
    import scanners
    results = scanners.run_testssl(target, _get_bridge(), timeout=timeout)
    return json.dumps({"issues": results, "count": len(results)}, default=str)


# --- Reporting Tools ---

@security_tool(category="report", risk="safe")
def generate_report(
    target_url: str,
    scope_domain: str,
    pre_recon: str,
    discovery: str,
    vuln_analysis: str,
    exploit_validation: str,
) -> str:
    """Generate comprehensive pentest report from collected findings.

    Args:
        target_url: The target URL that was tested
        scope_domain: Root domain scope
        pre_recon: JSON string of pre-recon findings
        discovery: JSON string of discovery findings
        vuln_analysis: JSON string of vulnerability analysis findings
        exploit_validation: JSON string of exploit validation findings
    """
    from reporter import PentestReporter

    report = PentestReporter(
        target_url=target_url,
        scope_domain=scope_domain,
        started_at="",
        pre_recon=json.loads(pre_recon) if isinstance(pre_recon, str) else pre_recon,
        discovery=json.loads(discovery) if isinstance(discovery, str) else discovery,
        vuln_analysis=json.loads(vuln_analysis) if isinstance(vuln_analysis, str) else vuln_analysis,
        exploit_validation=json.loads(exploit_validation) if isinstance(exploit_validation, str) else exploit_validation,
        bridge_stats=_get_bridge().stats,
    ).generate()

    report_path = "/agent/workspaces/latest/deliverables/pentest_report.md"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report)

    return json.dumps({"report_path": report_path, "report_length": len(report)})


@security_tool(category="report", risk="safe")
def submit_findings_to_platform() -> str:
    """Flush any remaining buffered findings to the ASM platform."""
    bridge = _get_bridge()
    bridge.flush()
    return json.dumps({"stats": bridge.stats})


# =========================================================================
# Agent Definitions
# =========================================================================

RECON_TOOLS = [
    "scan_subdomains", "resolve_dns", "probe_http", "scan_ports",
    "scan_ports_nmap", "fingerprint_tech", "detect_waf", "detect_cms",
    "crawl_urls", "discover_historical_urls", "scan_js_urls_for_secrets",
    "fuzz_directories", "discover_parameters",
]

VULN_TOOLS = [
    "scan_nuclei", "scan_nikto", "analyze_security_headers", "analyze_tls",
    "check_subdomain_takeover", "analyze_mail_security", "detect_third_party_vendors",
    "scan_js_urls_for_secrets",
]

EXPLOIT_TOOLS = [
    "sql_injection_test", "xss_test", "wordpress_scan", "deep_tls_test",
    "scan_nuclei",
]

REPORT_TOOLS = [
    "generate_report", "submit_findings_to_platform",
]


def create_report_agent() -> Agent:
    return Agent(
        name="report_agent",
        instructions="""You are the Report Agent. Your job is to compile all findings
from reconnaissance, vulnerability analysis, and exploit validation into a
comprehensive security assessment report.

When you receive findings from the Exploit Agent:
1. Organize findings by severity (Critical > High > Medium > Low)
2. Generate the report using the generate_report tool
3. Submit remaining findings to the platform
4. Provide a brief executive summary to the user""",
        tool_names=REPORT_TOOLS,
        max_turns=5,
    )


def create_exploit_agent() -> Agent:
    report_agent = create_report_agent()
    return Agent(
        name="exploit_agent",
        instructions="""You are the Exploit Validation Agent. Your job is to confirm
discovered vulnerabilities with targeted validation attempts.

RULES:
- Only validate, never escalate or cause damage
- sqlmap: always use --batch mode (already enforced)
- Focus on parameterized URLs from the discovery/vuln phases
- Skip validation if no injectable endpoints were found

Strategy:
1. Review nuclei findings - re-validate any high/critical with targeted templates
2. Test parameterized URLs for SQL injection
3. Test parameterized URLs for XSS
4. If WordPress detected, run wpscan
5. If TLS grades are D/F, run deep TLS testing
6. When done, hand off to the Report Agent with a summary of validated findings""",
        tool_names=EXPLOIT_TOOLS,
        handoffs=[report_agent],
        max_turns=20,
    )


def create_vuln_agent() -> Agent:
    exploit_agent = create_exploit_agent()
    return Agent(
        name="vuln_agent",
        instructions="""You are the Vulnerability Analysis Agent. Your job is to
identify vulnerabilities across the discovered attack surface.

Strategy:
1. Run nuclei against all discovered live URLs (most important)
2. Run scan_js_urls_for_secrets on high-value .js URLs from crawling (API bundles, clientlibs) — complements nuclei for leaked credentials in static assets
3. Run nikto against the primary target
4. Analyze security headers on all live hosts
5. Analyze TLS certificates and grades
6. Check all subdomains for takeover risk
7. Analyze mail infrastructure for the root domain
8. Detect third-party vendors

When you have a comprehensive picture, hand off to the Exploit Agent with:
- List of nuclei high/critical findings
- Any parameterized URLs that should be tested for injection
- Whether WordPress or other CMS was detected
- Which hosts have poor TLS grades""",
        tool_names=VULN_TOOLS,
        handoffs=[exploit_agent],
        max_turns=25,
    )


def create_recon_agent() -> Agent:
    vuln_agent = create_vuln_agent()
    return Agent(
        name="recon_agent",
        instructions="""You are the Reconnaissance Agent. Your job is to map the
complete attack surface of the target.

Strategy (adapt based on what you find):
1. Start with fingerprint_tech and detect_waf on the target URL
2. Enumerate subdomains for the root domain
3. Resolve DNS for all discovered hosts
4. Probe for live HTTP services
5. Port scan the primary target (nmap for service detection)
6. Crawl the target for URLs and endpoints
7. Discover historical URLs
8. For discovered JavaScript bundles (e.g. .js under /static, /clientlibs), run scan_js_urls_for_secrets with those URLs to detect hardcoded keys/tokens
9. Fuzz for hidden directories/API paths
10. Discover parameters on interesting endpoints

ADAPT your approach:
- If WAF detected, note it for the vuln agent to adjust strategy
- If CMS detected (WordPress etc), flag for CMS-specific scanning
- If many subdomains found, prioritize live ones
- If interesting API endpoints found, discover their parameters

When you have a comprehensive attack surface map, hand off to the
Vulnerability Analysis Agent with your findings.""",
        tool_names=RECON_TOOLS,
        handoffs=[vuln_agent],
        max_turns=30,
    )


def create_orchestrator() -> Agent:
    """Create the top-level orchestrator that manages the full pipeline."""
    recon_agent = create_recon_agent()

    return Agent(
        name="orchestrator",
        instructions="""You are the NanoClaw Orchestrator. You coordinate autonomous
web application penetration testing.

When given a target:
1. Briefly acknowledge the target and scope
2. Immediately hand off to the Recon Agent to begin the assessment

The pipeline flows: Recon -> Vuln Analysis -> Exploit Validation -> Reporting
Each agent hands off to the next when its phase is complete.""",
        tool_names=[],
        handoffs=[recon_agent],
        max_turns=3,
    )


def build_agent_chain() -> dict:
    """Build the full multi-agent chain and return as a dict for AgentRunner.run_multi()."""
    report_agent = create_report_agent()
    exploit_agent = Agent(
        name="exploit_agent",
        instructions=create_exploit_agent().instructions,
        tool_names=EXPLOIT_TOOLS,
        handoffs=[report_agent],
        max_turns=20,
    )
    vuln_agent = Agent(
        name="vuln_agent",
        instructions=create_vuln_agent().instructions,
        tool_names=VULN_TOOLS,
        handoffs=[exploit_agent],
        max_turns=25,
    )
    recon_agent = Agent(
        name="recon_agent",
        instructions=create_recon_agent().instructions,
        tool_names=RECON_TOOLS,
        handoffs=[vuln_agent],
        max_turns=30,
    )
    orchestrator = Agent(
        name="orchestrator",
        instructions=create_orchestrator().instructions,
        tool_names=[],
        handoffs=[recon_agent],
        max_turns=3,
    )

    return {
        "orchestrator": orchestrator,
        "recon_agent": recon_agent,
        "vuln_agent": vuln_agent,
        "exploit_agent": exploit_agent,
        "report_agent": report_agent,
    }
