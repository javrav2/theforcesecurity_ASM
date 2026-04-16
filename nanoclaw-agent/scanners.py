#!/usr/bin/env python3
"""
ASM Scanner Wrappers

Wrappers around security scanning tools that parse output and feed
into the ASM Bridge for submission to the platform.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

from asm_bridge import ASMBridge, Finding

logger = logging.getLogger("asm_scanners")


def _run(cmd: List[str], timeout: int = 600) -> subprocess.CompletedProcess:
    logger.info(f"Running: {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# =========================================================================
# Subdomain Enumeration
# =========================================================================

def run_subfinder(domain: str, bridge: ASMBridge, timeout: int = 300) -> List[str]:
    """Passive subdomain enumeration via subfinder."""
    if not _tool_available("subfinder"):
        logger.error("subfinder not installed"); return []
    result = _run(["subfinder", "-d", domain, "-silent", "-json"], timeout=timeout)
    subdomains = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            host = data.get("host", line.strip())
        except json.JSONDecodeError:
            host = line.strip()
        if host and host != domain:
            subdomains.append(host)
            bridge.submit_subdomain(host, source="subfinder")
    bridge.flush()
    logger.info(f"subfinder: {len(subdomains)} subdomains for {domain}")
    return subdomains


def run_amass(domain: str, bridge: ASMBridge, timeout: int = 600) -> List[str]:
    """Subdomain enumeration via amass."""
    if not _tool_available("amass"):
        logger.error("amass not installed"); return []
    result = _run(["amass", "enum", "-passive", "-d", domain, "-json", "-silent"], timeout=timeout)
    subdomains = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            host = data.get("name", line.strip())
        except json.JSONDecodeError:
            host = line.strip()
        if host and host != domain:
            subdomains.append(host)
            bridge.submit_subdomain(host, source="amass")
    bridge.flush()
    logger.info(f"amass: {len(subdomains)} subdomains for {domain}")
    return subdomains


# =========================================================================
# DNS Resolution
# =========================================================================

def run_dnsx(hosts: List[str], bridge: ASMBridge, timeout: int = 300) -> Dict[str, str]:
    """Resolve hostnames to IPs via dnsx."""
    if not _tool_available("dnsx"):
        logger.error("dnsx not installed"); return {}
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        result = _run(["dnsx", "-l", hosts_file, "-a", "-resp", "-silent", "-json"], timeout=timeout)
        resolved = {}
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
                host = data.get("host", "")
                ips = data.get("a", [])
                if host and ips:
                    resolved[host] = ips[0]
                    bridge.submit_ip(ips[0], source="dnsx")
            except json.JSONDecodeError:
                continue
        bridge.flush()
        logger.info(f"dnsx: resolved {len(resolved)} hosts")
        return resolved
    finally:
        os.unlink(hosts_file)


# =========================================================================
# Port Scanning
# =========================================================================

def run_naabu(target: str, bridge: ASMBridge, ports: str = "top-1000",
              rate: int = 1000, timeout: int = 600) -> List[dict]:
    """Fast port scanning via naabu."""
    if not _tool_available("naabu"):
        logger.error("naabu not installed"); return []
    cmd = ["naabu", "-host", target, "-json", "-silent", "-rate", str(rate)]
    if ports == "top-1000":
        cmd.extend(["-top-ports", "1000"])
    elif ports == "full":
        cmd.extend(["-p", "-"])
    else:
        cmd.extend(["-p", ports])
    result = _run(cmd, timeout=timeout)
    findings = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            host = data.get("host", data.get("ip", target))
            port = data.get("port")
            if port:
                bridge.submit_port(host, port, source="naabu", ip=data.get("ip"))
                findings.append({"host": host, "port": port, "ip": data.get("ip")})
        except json.JSONDecodeError:
            continue
    bridge.flush()
    logger.info(f"naabu: {len(findings)} open ports on {target}")
    return findings


def run_nmap(target: str, bridge: ASMBridge, ports: str = "1-1000",
             args: str = "-sV -sC", timeout: int = 900) -> List[dict]:
    """Service detection and scripting via nmap."""
    if not _tool_available("nmap"):
        logger.error("nmap not installed"); return []
    cmd = ["nmap"] + args.split() + ["-p", ports, "-oX", "-", target]
    result = _run(cmd, timeout=timeout)
    findings = []
    # Parse XML output for port/service info
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(result.stdout)
        for host_el in root.findall(".//host"):
            ip_el = host_el.find("address[@addrtype='ipv4']")
            ip = ip_el.get("addr") if ip_el is not None else target
            for port_el in host_el.findall(".//port"):
                port_num = int(port_el.get("portid", 0))
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                service_el = port_el.find("service")
                svc_name = service_el.get("name") if service_el is not None else None
                svc_product = service_el.get("product") if service_el is not None else None
                svc_version = service_el.get("version") if service_el is not None else None
                if state == "open":
                    bridge.submit_port(target, port_num, protocol, source="nmap",
                                       service=svc_name, ip=ip,
                                       service_product=svc_product,
                                       service_version=svc_version)
                    findings.append({"host": target, "port": port_num, "service": svc_name,
                                     "product": svc_product, "version": svc_version})
    except ET.ParseError:
        logger.warning("Failed to parse nmap XML output")
    bridge.flush()
    logger.info(f"nmap: {len(findings)} services on {target}")
    return findings


def run_masscan(target: str, bridge: ASMBridge, ports: str = "1-65535",
                rate: int = 1000, timeout: int = 600) -> List[dict]:
    """Ultra-fast port scanning via masscan."""
    if not _tool_available("masscan"):
        logger.error("masscan not installed"); return []
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "-oJ", "-"]
    result = _run(cmd, timeout=timeout)
    findings = []
    for line in result.stdout.strip().splitlines():
        line = line.strip().rstrip(",")
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
            ip = data.get("ip", target)
            for port_info in data.get("ports", []):
                port = port_info.get("port")
                proto = port_info.get("proto", "tcp")
                if port:
                    bridge.submit_port(ip, port, proto, source="masscan", ip=ip)
                    findings.append({"ip": ip, "port": port, "proto": proto})
        except json.JSONDecodeError:
            continue
    bridge.flush()
    logger.info(f"masscan: {len(findings)} open ports on {target}")
    return findings


# =========================================================================
# Vulnerability Scanning
# =========================================================================

def run_nuclei(target: str, bridge: ASMBridge, templates: Optional[str] = None,
               severity: str = "low,medium,high,critical", rate_limit: int = 150,
               timeout: int = 900) -> List[dict]:
    """Vulnerability scanning via nuclei."""
    if not _tool_available("nuclei"):
        logger.error("nuclei not installed"); return []
    cmd = ["nuclei", "-target", target, "-json", "-silent",
           "-severity", severity, "-rate-limit", str(rate_limit)]
    if templates:
        cmd.extend(["-t", templates])
    result = _run(cmd, timeout=timeout)
    findings = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            info = data.get("info", {})
            classification = info.get("classification", {})
            cve_id = classification.get("cve-id")
            if isinstance(cve_id, list) and cve_id:
                cve_id = cve_id[0]
            bridge.submit_vulnerability(
                host=data.get("host", target),
                title=info.get("name", data.get("template-id", "Unknown")),
                severity=info.get("severity", "info"),
                source="nuclei",
                template_id=data.get("template-id"),
                cve_id=cve_id if isinstance(cve_id, str) else None,
                url=data.get("matched-at"),
                description=info.get("description"),
                tags=info.get("tags", []),
                references=info.get("reference", []),
                raw_data=data,
            )
            findings.append(data)
        except json.JSONDecodeError:
            continue
    bridge.flush()
    logger.info(f"nuclei: {len(findings)} vulnerabilities on {target}")
    return findings


def run_nikto(target: str, bridge: ASMBridge, timeout: int = 600) -> List[dict]:
    """Web server vulnerability scanning via nikto."""
    if not _tool_available("nikto"):
        logger.error("nikto not installed"); return []
    cmd = ["nikto", "-h", target, "-Format", "json", "-output", "-"]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for vuln in data.get("vulnerabilities", []):
            bridge.submit_vulnerability(
                host=target, title=vuln.get("msg", "Nikto Finding"),
                severity="medium", source="nikto",
                url=vuln.get("url"), description=vuln.get("msg"),
            )
            findings.append(vuln)
    except json.JSONDecodeError:
        for line in result.stdout.strip().splitlines():
            if "+ " in line:
                bridge.submit_vulnerability(
                    host=target, title=line.strip("+ ").strip(),
                    severity="info", source="nikto",
                )
                findings.append({"msg": line})
    bridge.flush()
    logger.info(f"nikto: {len(findings)} findings on {target}")
    return findings


def run_sqlmap(target_url: str, bridge: ASMBridge, timeout: int = 600) -> List[dict]:
    """SQL injection testing via sqlmap."""
    if not _tool_available("sqlmap"):
        logger.error("sqlmap not installed"); return []
    cmd = ["sqlmap", "-u", target_url, "--batch", "--level=2", "--risk=2",
           "--output-dir=/tmp/sqlmap_out", "--forms"]
    result = _run(cmd, timeout=timeout)
    findings = []
    output = result.stdout
    if "is vulnerable" in output or "injectable" in output.lower():
        bridge.submit_vulnerability(
            host=target_url, title="SQL Injection Detected",
            severity="critical", source="sqlmap",
            description=output[-2000:], url=target_url,
        )
        findings.append({"url": target_url, "vulnerable": True})
    bridge.flush()
    logger.info(f"sqlmap: {len(findings)} injection points on {target_url}")
    return findings


# =========================================================================
# Web Application Scanning
# =========================================================================

def run_httpx(hosts: List[str], bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """HTTP probing and technology detection via httpx."""
    if not _tool_available("httpx"):
        logger.error("httpx not installed"); return []
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        cmd = ["httpx", "-l", hosts_file, "-silent", "-json",
               "-title", "-tech-detect", "-status-code"]
        result = _run(cmd, timeout=timeout)
        live_hosts = []
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
                url = data.get("url", "")
                if url:
                    techs = data.get("tech", [])
                    bridge.submit_url(url, source="httpx", technologies=techs)
                    live_hosts.append(data)
            except json.JSONDecodeError:
                continue
        bridge.flush()
        logger.info(f"httpx: {len(live_hosts)} live hosts")
        return live_hosts
    finally:
        os.unlink(hosts_file)


def run_whatweb(target: str, bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """Technology fingerprinting via WhatWeb."""
    if not _tool_available("whatweb"):
        logger.error("whatweb not installed"); return []
    cmd = ["whatweb", target, "--log-json=-", "-q"]
    result = _run(cmd, timeout=timeout)
    findings = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            plugins = data.get("plugins", {})
            techs = [k for k in plugins.keys() if k not in ("HttpOnly", "IP", "Country")]
            bridge.submit_url(data.get("target", target), source="whatweb", technologies=techs)
            findings.append(data)
        except json.JSONDecodeError:
            continue
    bridge.flush()
    logger.info(f"whatweb: {len(findings)} results for {target}")
    return findings


def run_wafw00f(target: str, bridge: ASMBridge, timeout: int = 120) -> Optional[str]:
    """WAF detection via wafw00f."""
    if not _tool_available("wafw00f"):
        logger.error("wafw00f not installed"); return None
    cmd = ["wafw00f", target, "-o", "-"]
    result = _run(cmd, timeout=timeout)
    waf = None
    output = result.stdout
    if "is behind" in output:
        for line in output.splitlines():
            if "is behind" in line:
                waf = line.split("is behind")[-1].strip().rstrip(".")
                bridge.submit_finding(Finding(
                    type="technology", source="wafw00f", target=target,
                    host=target, title=f"WAF Detected: {waf}",
                    technologies=[waf], severity="info",
                ))
    bridge.flush()
    logger.info(f"wafw00f: {'WAF=' + waf if waf else 'No WAF'} on {target}")
    return waf


# =========================================================================
# SSL/TLS Testing
# =========================================================================

def run_testssl(target: str, bridge: ASMBridge, timeout: int = 600) -> List[dict]:
    """SSL/TLS testing via testssl.sh."""
    if not _tool_available("testssl") and not _tool_available("testssl.sh"):
        logger.error("testssl not installed"); return []
    binary = "testssl.sh" if _tool_available("testssl.sh") else "testssl"
    cmd = [binary, "--json", "-", target]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for item in data if isinstance(data, list) else data.get("scanResult", []):
            sev = item.get("severity", "INFO").lower()
            if sev in ("critical", "high", "medium", "warn"):
                bridge.submit_vulnerability(
                    host=target, title=item.get("id", "SSL Issue"),
                    severity="medium" if sev == "warn" else sev,
                    source="testssl", description=item.get("finding", ""),
                )
                findings.append(item)
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"testssl: {len(findings)} issues on {target}")
    return findings


def run_sslyze(target: str, bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """SSL/TLS analysis via sslyze."""
    if not _tool_available("sslyze"):
        logger.error("sslyze not installed"); return []
    cmd = ["sslyze", "--json_out=-", target]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for server in data.get("server_scan_results", []):
            scan = server.get("scan_result", {})
            cert_info = scan.get("certificate_info", {})
            if cert_info.get("result", {}).get("certificate_deployments"):
                for dep in cert_info["result"]["certificate_deployments"]:
                    if not dep.get("leaf_certificate_subject_matches_hostname", True):
                        bridge.submit_vulnerability(
                            host=target, title="SSL Certificate Hostname Mismatch",
                            severity="medium", source="sslyze",
                        )
                        findings.append({"type": "cert_mismatch"})
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"sslyze: {len(findings)} issues on {target}")
    return findings


# =========================================================================
# Web Crawling & URL Discovery
# =========================================================================

# Aligns with ProjectDiscovery README: -d 5 -jc -fx -ef woff,css,...
_KATANA_EF_PIPELINE = "woff,css,png,svg,jpg,woff2,jpeg,gif"


def run_katana(target: str, bridge: ASMBridge, depth: int = 5,
               timeout: int = 600) -> List[str]:
    """Web crawling via katana (JS crawl, form extraction, extension noise filter)."""
    if not _tool_available("katana"):
        logger.error("katana not installed"); return []
    cmd = [
        "katana", "-u", target,
        "-silent", "-json", "-nc",
        "-d", str(depth),
        "-jc", "-fx",
        "-ef", _KATANA_EF_PIPELINE,
    ]
    result = _run(cmd, timeout=timeout)
    urls = []
    for line in result.stdout.strip().splitlines():
        try:
            data = json.loads(line)
            url = data.get("request", {}).get("endpoint", line.strip())
        except json.JSONDecodeError:
            url = line.strip()
        if url and url.startswith("http"):
            urls.append(url)
            bridge.submit_url(url, source="katana")
    bridge.flush()
    logger.info(f"katana: {len(urls)} URLs on {target}")
    return urls


def run_waybackurls(domain: str, bridge: ASMBridge, timeout: int = 300) -> List[str]:
    """Historical URL discovery via waybackurls."""
    if not _tool_available("waybackurls"):
        logger.error("waybackurls not installed"); return []
    result = _run(["bash", "-c", f"echo {domain} | waybackurls"], timeout=timeout)
    urls = [u.strip() for u in result.stdout.strip().splitlines() if u.strip().startswith("http")]
    for url in urls:
        bridge.submit_url(url, source="waybackurls")
    bridge.flush()
    logger.info(f"waybackurls: {len(urls)} URLs for {domain}")
    return urls


def run_gau(domain: str, bridge: ASMBridge, timeout: int = 300) -> List[str]:
    """URL discovery via gau (GetAllURLs)."""
    if not _tool_available("gau"):
        logger.error("gau not installed"); return []
    result = _run(["bash", "-c", f"echo {domain} | gau --subs"], timeout=timeout)
    urls = [u.strip() for u in result.stdout.strip().splitlines() if u.strip().startswith("http")]
    for url in urls:
        bridge.submit_url(url, source="gau")
    bridge.flush()
    logger.info(f"gau: {len(urls)} URLs for {domain}")
    return urls


# =========================================================================
# Directory & API Fuzzing
# =========================================================================

def run_ffuf(target_url: str, bridge: ASMBridge, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
             timeout: int = 600) -> List[dict]:
    """Directory/API fuzzing via ffuf."""
    if not _tool_available("ffuf"):
        logger.error("ffuf not installed"); return []
    fuzz_url = target_url.rstrip("/") + "/FUZZ"
    cmd = ["ffuf", "-u", fuzz_url, "-w", wordlist, "-o", "-", "-of", "json",
           "-mc", "200,201,301,302,403", "-s"]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for r in data.get("results", []):
            url = r.get("url", "")
            bridge.submit_url(url, source="ffuf")
            findings.append(r)
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"ffuf: {len(findings)} paths on {target_url}")
    return findings


def run_arjun(target_url: str, bridge: ASMBridge, timeout: int = 300) -> List[str]:
    """HTTP parameter discovery via arjun."""
    if not _tool_available("arjun"):
        logger.error("arjun not installed"); return []
    cmd = ["arjun", "-u", target_url, "--stable", "-oJ", "-"]
    result = _run(cmd, timeout=timeout)
    params = []
    try:
        data = json.loads(result.stdout)
        for url, p_list in data.items():
            params.extend(p_list)
            bridge.submit_url(url, source="arjun",
                              raw_data={"parameters": p_list})
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"arjun: {len(params)} parameters on {target_url}")
    return params


# =========================================================================
# Secret & Code Scanning
# =========================================================================

def run_gitleaks(repo_path: str, bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """Secret scanning via gitleaks."""
    if not _tool_available("gitleaks"):
        logger.error("gitleaks not installed"); return []
    cmd = ["gitleaks", "detect", "--source", repo_path, "--report-format", "json", "--no-banner"]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        if isinstance(data, list):
            for leak in data:
                bridge.submit_vulnerability(
                    host=repo_path, title=f"Secret: {leak.get('RuleID', 'unknown')}",
                    severity="high", source="gitleaks",
                    description=f"File: {leak.get('File', '')} Line: {leak.get('StartLine', '')}",
                )
                findings.append(leak)
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"gitleaks: {len(findings)} secrets in {repo_path}")
    return findings


def _parse_js_secret_urls(urls: str) -> List[str]:
    if not urls or not str(urls).strip():
        return []
    out: List[str] = []
    for line in str(urls).replace(",", "\n").split("\n"):
        u = line.strip()
        if u.startswith("http://") or u.startswith("https://"):
            out.append(u)
    seen = set()
    uniq: List[str] = []
    for u in out:
        if u not in seen:
            seen.add(u)
            uniq.append(u)
    return uniq


def _js_filename(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()[:20] + ".js"


def _regex_js_hints(js_content: str) -> Dict[str, List[str]]:
    """Lightweight patterns aligned with ASM KatanaService.extract_secrets_from_js."""
    hints: Dict[str, List[str]] = {
        "api_keys": [], "tokens": [], "passwords": [], "urls": [], "emails": [],
    }
    api_patterns = [
        r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']?apikey["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
        r'Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)',
    ]
    for pattern in api_patterns:
        for match in re.findall(pattern, js_content, re.IGNORECASE):
            if len(match) > 8:
                hints["api_keys"].append(match)
    url_pattern = r'https?://[^\s"\'<>]+(?:/[^\s"\'<>]*)?'
    hints["urls"] = list(set(re.findall(url_pattern, js_content)))[:100]
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    hints["emails"] = list(set(re.findall(email_pattern, js_content)))[:50]
    return {k: v for k, v in hints.items() if v}


def run_js_url_secret_scan(
    urls: str,
    bridge: ASMBridge,
    max_urls: int = 30,
    max_bytes: int = 2 * 1024 * 1024,
    fetch_timeout: float = 35.0,
) -> Dict[str, Any]:
    """
    Download http(s) assets (typically .js from Katana), run gitleaks --no-git, regex hints.
    Submits gitleaks hits to the platform as vulnerabilities.
    """
    import httpx

    parsed = _parse_js_secret_urls(urls)[: max(1, min(int(max_urls), 100))]
    if not parsed:
        return {"success": False, "error": "No valid http(s) URLs", "urls_scanned": 0}

    if not _tool_available("gitleaks"):
        logger.error("gitleaks not installed")
        return {"success": False, "error": "gitleaks not installed", "urls_scanned": 0}

    downloads: List[Dict[str, Any]] = []
    regex_hints: List[Dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="js_secrets_") as tmp:
        files_dir = os.path.join(tmp, "files")
        os.makedirs(files_dir, exist_ok=True)
        name_to_url: Dict[str, str] = {}

        with httpx.Client(headers={"User-Agent": "NanoClaw-JS-Secrets/1.0"}) as client:
            for url in parsed:
                try:
                    with client.stream("GET", url, follow_redirects=True, timeout=fetch_timeout) as resp:
                        if resp.status_code != 200:
                            downloads.append({"url": url, "ok": False, "error": f"HTTP {resp.status_code}"})
                            continue
                        buf = bytearray()
                        for chunk in resp.iter_bytes():
                            buf.extend(chunk)
                            if len(buf) > max_bytes:
                                downloads.append({"url": url, "ok": False, "error": "content too large"})
                                break
                        else:
                            body = bytes(buf)
                            fname = _js_filename(url)
                            path = os.path.join(files_dir, fname)
                            with open(path, "wb") as f:
                                f.write(body)
                            name_to_url[fname] = url
                            text = body.decode("utf-8", errors="replace")
                            h = _regex_js_hints(text)
                            if h:
                                regex_hints.append({"url": url, "hints": h})
                            downloads.append({"url": url, "ok": True, "bytes": len(body), "file": fname})
                except Exception as e:
                    downloads.append({"url": url, "ok": False, "error": str(e)})

        gl_cmd = [
            "gitleaks", "detect",
            "--source", files_dir,
            "--no-git",
            "--report-format", "json",
            "--exit-code", "0",
            "--redact",
        ]
        proc = subprocess.run(gl_cmd, capture_output=True, text=True, timeout=300)
        raw = (proc.stdout or "").strip()
        gl_findings: List[dict] = []
        if raw:
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    gl_findings = data
                elif isinstance(data, dict):
                    gl_findings = [data]
            except json.JSONDecodeError:
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        gl_findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        for finding in gl_findings:
            fn = (finding.get("File") or finding.get("file") or "").split("/")[-1]
            src = name_to_url.get(fn)
            if src:
                finding["source_url"] = src
            host = urlparse(src or "").hostname or (finding.get("source_url") or "unknown")
            rule = finding.get("RuleID") or finding.get("rule_id") or "secret"
            bridge.submit_vulnerability(
                host=host,
                title=f"JS secret ({rule})",
                severity="high",
                source="js_secrets",
                url=src or finding.get("source_url"),
                description=json.dumps({k: finding.get(k) for k in ("RuleID", "Secret", "Match", "StartLine", "EndLine") if finding.get(k)}, default=str),
                tags=["javascript", "secret", "gitleaks"],
            )
        bridge.flush()

    return {
        "success": True,
        "urls_requested": len(parsed),
        "urls_scanned": sum(1 for d in downloads if d.get("ok")),
        "downloads": downloads,
        "gitleaks_findings": gl_findings,
        "regex_hints": regex_hints,
    }


# =========================================================================
# CMS Detection
# =========================================================================

def run_cmseek(target: str, bridge: ASMBridge, timeout: int = 300) -> Optional[str]:
    """CMS detection via CMSeeK."""
    if not _tool_available("cmseek") and not os.path.exists("/opt/cmseek/cmseek.py"):
        logger.error("cmseek not installed"); return None
    binary = "cmseek" if _tool_available("cmseek") else "python3 /opt/cmseek/cmseek.py"
    cmd = ["bash", "-c", f"{binary} -u {target} --batch"]
    result = _run(cmd, timeout=timeout)
    cms = None
    for line in result.stdout.splitlines():
        if "CMS:" in line or "Detected CMS" in line:
            cms = line.split(":")[-1].strip()
            bridge.submit_finding(Finding(
                type="technology", source="cmseek", target=target,
                host=target, title=f"CMS Detected: {cms}",
                technologies=[cms], severity="info",
            ))
    bridge.flush()
    logger.info(f"cmseek: {'CMS=' + cms if cms else 'No CMS'} on {target}")
    return cms


def run_wpscan(target: str, bridge: ASMBridge, timeout: int = 600) -> List[dict]:
    """WordPress vulnerability scanning via wpscan."""
    if not _tool_available("wpscan"):
        logger.error("wpscan not installed"); return []
    cmd = ["wpscan", "--url", target, "--format", "json", "--no-banner"]
    result = _run(cmd, timeout=timeout)
    findings = []
    try:
        data = json.loads(result.stdout)
        for vuln in data.get("interesting_findings", []):
            bridge.submit_vulnerability(
                host=target, title=vuln.get("type", "WPScan Finding"),
                severity="medium", source="wpscan",
                url=vuln.get("url"), description=str(vuln.get("references", "")),
            )
            findings.append(vuln)
    except json.JSONDecodeError:
        pass
    bridge.flush()
    logger.info(f"wpscan: {len(findings)} findings on {target}")
    return findings


def run_xsstrike(target_url: str, bridge: ASMBridge, timeout: int = 300) -> List[dict]:
    """XSS detection via XSStrike."""
    xsstrike_path = "/opt/xsstrike/xsstrike.py"
    if not os.path.exists(xsstrike_path):
        logger.error("xsstrike not installed"); return []
    cmd = ["python3", xsstrike_path, "-u", target_url, "--skip"]
    result = _run(cmd, timeout=timeout)
    findings = []
    output = result.stdout
    if "Vulnerable" in output or "XSS" in output:
        bridge.submit_vulnerability(
            host=target_url, title="Reflected XSS Detected",
            severity="high", source="xsstrike",
            url=target_url, description=output[-2000:],
        )
        findings.append({"url": target_url, "type": "xss"})
    bridge.flush()
    logger.info(f"xsstrike: {len(findings)} XSS on {target_url}")
    return findings


# =========================================================================
# Subdomain Takeover Detection
# =========================================================================

TAKEOVER_FINGERPRINTS = {
    "github.io": ("GitHub Pages", "There isn't a GitHub Pages site here"),
    "herokuapp.com": ("Heroku", "No such app"),
    "pantheonsite.io": ("Pantheon", "404 error unknown site"),
    "ghost.io": ("Ghost", "The thing you were looking for is no longer here"),
    "myshopify.com": ("Shopify", "Sorry, this shop is currently unavailable"),
    "surge.sh": ("Surge.sh", "project not found"),
    "bitbucket.io": ("Bitbucket", "Repository not found"),
    "wordpress.com": ("WordPress.com", "Do you want to register"),
    "teamwork.com": ("Teamwork", "Oops - We didn't find your site"),
    "helpjuice.com": ("Helpjuice", "We could not find what you're looking for"),
    "helpscoutdocs.com": ("HelpScout", "No settings were found for this company"),
    "s3.amazonaws.com": ("AWS S3", "NoSuchBucket"),
    "cloudfront.net": ("CloudFront", "ERROR: The request could not be satisfied"),
    "elasticbeanstalk.com": ("AWS Elastic Beanstalk", ""),
    "azurewebsites.net": ("Azure", "404 Web Site not found"),
    "cloudapp.net": ("Azure", ""),
    "trafficmanager.net": ("Azure Traffic Manager", ""),
    "blob.core.windows.net": ("Azure Blob", "BlobNotFound"),
    "zendesk.com": ("Zendesk", "Help Center Closed"),
    "fastly.net": ("Fastly", "Fastly error: unknown domain"),
    "smugmug.com": ("SmugMug", ""),
    "strikingly.com": ("Strikingly", "page not found"),
    "webflow.io": ("Webflow", "The page you are looking for doesn't exist"),
    "creatorlink.net": ("CreatorLink", ""),
    "tave.com": ("Tave", ""),
    "wishpond.com": ("Wishpond", ""),
    "aftership.com": ("AfterShip", "Oops.</h2>"),
    "aha.io": ("Aha!", "There is no portal here"),
    "tictail.com": ("Tictail", "to target URL"),
    "campaignmonitor.com": ("Campaign Monitor", "Trying to access your account"),
    "cargocollective.com": ("Cargo", "If you're moving your domain away"),
    "statuspage.io": ("Statuspage", "You are being redirected"),
    "tumblr.com": ("Tumblr", "There's nothing here"),
    "feedpress.me": ("FeedPress", "The feed has not been found"),
    "readme.io": ("Readme.io", "Project doesnt exist"),
    "fly.io": ("Fly.io", "404 Not Found"),
    "netlify.app": ("Netlify", "Not Found"),
    "vercel.app": ("Vercel", "NOT_FOUND"),
    "firebaseapp.com": ("Firebase", "404. That's an error"),
    "gitbook.io": ("GitBook", ""),
    "ngrok.io": ("ngrok", "Tunnel not found"),
    "desk.com": ("Desk.com", "Please try again or try Desk.com free"),
    "freshdesk.com": ("Freshdesk", "May be this is still fresh"),
    "unbounce.com": ("Unbounce", "The requested URL was not found"),
    "launchrock.com": ("LaunchRock", "It looks like you may have taken a wrong turn"),
    "pingdom.com": ("Pingdom", "Public Report Not Activated"),
    "tilda.cc": ("Tilda", "Please renew your subscription"),
    "canny.io": ("Canny", "Company Not Found"),
    "getresponse.com": ("GetResponse", "With GetResponse Landing Pages"),
    "acquia-test.co": ("Acquia", "Web Site Not Found"),
    "proposify.biz": ("Proposify", "If you need immediate assistance"),
    "simplebooklet.com": ("Simplebooklet", "We can't find this SimpleBoo"),
    "agilecrm.com": ("Agile CRM", "Sorry, this page is no longer available"),
    "airee.ru": ("Airee.ru", "Ошибка 402. Оплата за хостинг сайта"),
}


def run_subdomain_takeover(
    hosts: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Check subdomains for potential takeover via dangling CNAME fingerprints."""
    import subprocess as sp

    findings = []
    for host in hosts:
        try:
            dig = sp.run(
                ["dig", "+short", "CNAME", host], capture_output=True, text=True, timeout=15,
            )
            cname = dig.stdout.strip().rstrip(".")
        except Exception:
            cname = ""

        if not cname:
            bridge.submit_takeover(host, status="safe", source="takeover-check")
            continue

        matched_service = None
        matched_fingerprint = None
        for pattern, (service, fingerprint) in TAKEOVER_FINGERPRINTS.items():
            if pattern in cname.lower():
                matched_service = service
                matched_fingerprint = fingerprint
                break

        if not matched_service:
            bridge.submit_takeover(host, status="safe", cname_target=cname, source="takeover-check")
            findings.append({"host": host, "cname": cname, "status": "safe"})
            continue

        status = "potential"
        if matched_fingerprint:
            try:
                import urllib.request
                req = urllib.request.Request(f"http://{host}", method="GET")
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read(8192).decode("utf-8", errors="ignore")
                if matched_fingerprint.lower() in body.lower():
                    status = "confirmed"
            except Exception:
                status = "potential"

        bridge.submit_takeover(
            host, status=status, service=matched_service,
            cname_target=cname, source="takeover-check",
        )
        findings.append({
            "host": host, "cname": cname, "service": matched_service, "status": status,
        })

    bridge.flush()
    confirmed = sum(1 for f in findings if f.get("status") == "confirmed")
    potential = sum(1 for f in findings if f.get("status") == "potential")
    logger.info(f"takeover: {confirmed} confirmed, {potential} potential across {len(hosts)} hosts")
    return findings


# =========================================================================
# TLS Deep Analysis (via tlsx)
# =========================================================================

def run_tlsx(
    hosts: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Deep TLS/SSL analysis via tlsx: cipher grading, cert scoring, key analysis."""
    if not _tool_available("tlsx"):
        logger.error("tlsx not installed"); return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        cmd = [
            "tlsx", "-l", hosts_file, "-silent", "-json",
            "-cipher", "-hash", "sha256",
            "-expired", "-self-signed", "-mismatched",
            "-san", "-so", "-tps",
        ]
        result = _run(cmd, timeout=timeout)
        findings = []
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host", "")
            if not host:
                continue

            tls_version = data.get("tls_version", data.get("version", ""))
            cipher = data.get("cipher", "")

            cert_score = _grade_cert(data)
            key_algo = data.get("public_key_algorithm", "")
            key_size = data.get("public_key_size", 0)
            ca_type = "self-signed" if data.get("self_signed") else "ca-signed"

            days_left = None
            not_after = data.get("not_after", "")
            if not_after:
                try:
                    from datetime import datetime, timezone
                    expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                    days_left = (expiry - datetime.now(timezone.utc)).days
                except Exception:
                    pass

            severity = "info"
            if cert_score in ("D", "F"):
                severity = "high"
            elif cert_score == "C":
                severity = "medium"
            elif data.get("expired") or data.get("self_signed") or data.get("mismatched"):
                severity = "high"

            bridge.submit_tls_analysis(
                host, source="tlsx",
                tls_version=tls_version,
                cipher_suite=cipher,
                cert_score=cert_score,
                key_algorithm=key_algo,
                key_size=key_size or None,
                ca_type=ca_type,
                cert_expiry_days=days_left,
                severity=severity,
                raw_data=data,
            )
            findings.append({
                "host": host, "grade": cert_score, "tls": tls_version,
                "cipher": cipher, "days_left": days_left,
            })
        bridge.flush()
        logger.info(f"tlsx: {len(findings)} hosts analyzed")
        return findings
    finally:
        os.unlink(hosts_file)


def _grade_cert(data: dict) -> str:
    """Heuristic A-F grade from tlsx output fields."""
    score = 100
    if data.get("expired"):
        score -= 50
    if data.get("self_signed"):
        score -= 40
    if data.get("mismatched"):
        score -= 30
    tls = data.get("tls_version", data.get("version", ""))
    if "1.0" in tls or "ssl" in tls.lower():
        score -= 30
    elif "1.1" in tls:
        score -= 15
    key_size = data.get("public_key_size", 0)
    if key_size and key_size < 2048:
        score -= 20
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


# =========================================================================
# Security Header Analysis
# =========================================================================

_REQUIRED_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def run_security_headers(
    hosts: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Analyze security headers and CORS policy for live HTTP hosts via httpx."""
    if not _tool_available("httpx"):
        logger.error("httpx (PD) not installed"); return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        cmd = [
            "httpx", "-l", hosts_file, "-silent", "-json",
            "-include-response-header",
        ]
        result = _run(cmd, timeout=timeout)
        findings = []
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            url = data.get("url", "")
            host = data.get("host", data.get("input", ""))
            raw_headers = data.get("header", {})

            headers_lower = {k.lower(): v for k, v in raw_headers.items()} if raw_headers else {}

            sec_headers = {}
            for hdr in _REQUIRED_HEADERS:
                val = headers_lower.get(hdr)
                sec_headers[hdr] = val if val else None

            cors_policy = {}
            acao = headers_lower.get("access-control-allow-origin")
            if acao:
                cors_policy["allow_origin"] = acao
                cors_policy["wildcard"] = (acao == "*")
                acac = headers_lower.get("access-control-allow-credentials")
                cors_policy["allow_credentials"] = (acac and "true" in str(acac).lower())
                if cors_policy["wildcard"] and cors_policy["allow_credentials"]:
                    cors_policy["risky"] = True

            bridge.submit_security_headers(
                host, url=url, source="httpx",
                security_headers=sec_headers,
                cors_policy=cors_policy or None,
            )
            findings.append({
                "host": host, "url": url,
                "missing": [h for h, v in sec_headers.items() if not v],
                "cors": cors_policy,
            })
        bridge.flush()
        logger.info(f"security_headers: {len(findings)} hosts analyzed")
        return findings
    finally:
        os.unlink(hosts_file)


# =========================================================================
# Mail Infrastructure Intelligence
# =========================================================================

def run_mail_intel(
    domains: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Map MX, SPF, DKIM, DMARC, BIMI, MTA-STS, DANE per domain via dig."""
    import subprocess as sp
    findings = []
    for domain in domains:
        records: Dict[str, Any] = {}

        for rtype, key in [("MX", "mx"), ("TXT", "txt")]:
            try:
                r = sp.run(["dig", "+short", rtype, domain], capture_output=True, text=True, timeout=15)
                records[key] = [l.strip() for l in r.stdout.strip().splitlines() if l.strip()]
            except Exception:
                records[key] = []

        txt_joined = " ".join(records.get("txt", []))
        records["spf"] = any("v=spf1" in t for t in records.get("txt", []))
        records["dmarc"] = False
        records["dkim"] = False
        records["bimi"] = False
        records["mta_sts"] = False
        records["dane"] = False

        for sub, key in [
            (f"_dmarc.{domain}", "dmarc"),
            (f"default._domainkey.{domain}", "dkim"),
            (f"default._bimi.{domain}", "bimi"),
            (f"_mta-sts.{domain}", "mta_sts"),
        ]:
            try:
                r = sp.run(["dig", "+short", "TXT", sub], capture_output=True, text=True, timeout=10)
                if r.stdout.strip():
                    records[key] = True
            except Exception:
                pass

        try:
            r = sp.run(["dig", "+short", "TLSA", f"_25._tcp.{domain}"], capture_output=True, text=True, timeout=10)
            if r.stdout.strip():
                records["dane"] = True
        except Exception:
            pass

        risk_score = _email_risk_score(records)
        provider = _detect_mail_provider(records.get("mx", []))

        bridge.submit_mail_intel(
            domain, source="dns-mail-intel",
            mail_records=records,
            mail_provider=provider,
            email_risk_score=risk_score,
        )
        findings.append({
            "domain": domain, "risk_score": risk_score,
            "provider": provider, "records": records,
        })
    bridge.flush()
    logger.info(f"mail_intel: {len(findings)} domains analyzed")
    return findings


def _email_risk_score(records: dict) -> int:
    """0-100 risk score: 0 = fully secured, 100 = no mail security at all."""
    score = 100
    if records.get("spf"):
        score -= 25
    if records.get("dkim"):
        score -= 25
    if records.get("dmarc"):
        score -= 25
    if records.get("bimi"):
        score -= 5
    if records.get("mta_sts"):
        score -= 10
    if records.get("dane"):
        score -= 10
    return max(0, score)


def _detect_mail_provider(mx_records: list) -> str:
    providers = {
        "google": "Google Workspace", "googlemail": "Google Workspace",
        "outlook": "Microsoft 365", "protection.outlook": "Microsoft 365",
        "pphosted": "Proofpoint", "mimecast": "Mimecast",
        "barracuda": "Barracuda", "messagelabs": "Symantec",
        "zoho": "Zoho Mail", "secureserver": "GoDaddy",
        "emailsrvr": "Rackspace", "postmarkapp": "Postmark",
        "mailgun": "Mailgun", "sendgrid": "SendGrid",
        "amazonaws": "Amazon SES", "forcepoint": "Forcepoint",
    }
    for mx in mx_records:
        for pattern, name in providers.items():
            if pattern in mx.lower():
                return name
    return "Unknown"


# =========================================================================
# Third-Party Vendor Intelligence
# =========================================================================

VENDOR_PATTERNS: Dict[str, Dict[str, str]] = {
    "google-analytics.com": {"name": "Google Analytics", "category": "analytics"},
    "googletagmanager.com": {"name": "Google Tag Manager", "category": "analytics"},
    "facebook.net": {"name": "Facebook Pixel", "category": "advertising"},
    "connect.facebook.net": {"name": "Facebook SDK", "category": "social"},
    "platform.twitter.com": {"name": "Twitter Widgets", "category": "social"},
    "cdn.linkedin.oribi.io": {"name": "LinkedIn Insight", "category": "analytics"},
    "snap.licdn.com": {"name": "LinkedIn", "category": "social"},
    "js.stripe.com": {"name": "Stripe", "category": "payment"},
    "js.braintreegateway.com": {"name": "Braintree", "category": "payment"},
    "www.paypal.com": {"name": "PayPal", "category": "payment"},
    "cdn.shopify.com": {"name": "Shopify", "category": "ecommerce"},
    "cdn.jsdelivr.net": {"name": "jsDelivr CDN", "category": "cdn"},
    "cdnjs.cloudflare.com": {"name": "Cloudflare CDN", "category": "cdn"},
    "unpkg.com": {"name": "unpkg", "category": "cdn"},
    "maxcdn.bootstrapcdn.com": {"name": "Bootstrap CDN", "category": "cdn"},
    "ajax.googleapis.com": {"name": "Google CDN", "category": "cdn"},
    "fonts.googleapis.com": {"name": "Google Fonts", "category": "fonts"},
    "use.typekit.net": {"name": "Adobe Fonts", "category": "fonts"},
    "sentry.io": {"name": "Sentry", "category": "monitoring"},
    "newrelic.com": {"name": "New Relic", "category": "monitoring"},
    "js.datadoghq.com": {"name": "Datadog RUM", "category": "monitoring"},
    "cdn.segment.com": {"name": "Segment", "category": "analytics"},
    "cdn.amplitude.com": {"name": "Amplitude", "category": "analytics"},
    "cdn.heapanalytics.com": {"name": "Heap", "category": "analytics"},
    "cdn.mxpnl.com": {"name": "Mixpanel", "category": "analytics"},
    "static.hotjar.com": {"name": "Hotjar", "category": "analytics"},
    "widget.intercom.io": {"name": "Intercom", "category": "support"},
    "js.hs-scripts.com": {"name": "HubSpot", "category": "marketing"},
    "static.zdassets.com": {"name": "Zendesk", "category": "support"},
    "embed.tawk.to": {"name": "Tawk.to", "category": "support"},
    "js.driftt.com": {"name": "Drift", "category": "support"},
    "recaptcha.net": {"name": "reCAPTCHA", "category": "security"},
    "challenges.cloudflare.com": {"name": "Cloudflare Turnstile", "category": "security"},
    "hcaptcha.com": {"name": "hCaptcha", "category": "security"},
    "optimize.google.com": {"name": "Google Optimize", "category": "testing"},
    "cdn.optimizely.com": {"name": "Optimizely", "category": "testing"},
    "js.chargebee.com": {"name": "Chargebee", "category": "billing"},
    "js.recurly.com": {"name": "Recurly", "category": "billing"},
    "maps.googleapis.com": {"name": "Google Maps", "category": "maps"},
    "api.mapbox.com": {"name": "Mapbox", "category": "maps"},
    "player.vimeo.com": {"name": "Vimeo", "category": "media"},
    "www.youtube.com": {"name": "YouTube", "category": "media"},
    "fast.wistia.com": {"name": "Wistia", "category": "media"},
    "sc-static.net": {"name": "Snapchat Pixel", "category": "advertising"},
    "analytics.tiktok.com": {"name": "TikTok Pixel", "category": "advertising"},
    "bat.bing.com": {"name": "Bing Ads", "category": "advertising"},
    "ads.linkedin.com": {"name": "LinkedIn Ads", "category": "advertising"},
    "ct.pinterest.com": {"name": "Pinterest Tag", "category": "advertising"},
    "akamaihd.net": {"name": "Akamai", "category": "cdn"},
    "cdn.cookielaw.org": {"name": "OneTrust", "category": "privacy"},
    "app.termly.io": {"name": "Termly", "category": "privacy"},
}


def run_third_party_intel(
    hosts: List[str], bridge: ASMBridge, timeout: int = 300,
) -> List[dict]:
    """Detect third-party vendors from response body, CSP headers, and JS sources."""
    if not _tool_available("httpx"):
        logger.error("httpx (PD) not installed"); return []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("\n".join(hosts)); hosts_file = f.name
    try:
        cmd = [
            "httpx", "-l", hosts_file, "-silent", "-json",
            "-include-response", "-include-response-header",
        ]
        result = _run(cmd, timeout=timeout)
        findings = []
        for line in result.stdout.strip().splitlines():
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            host = data.get("host", data.get("input", ""))
            body = data.get("body", data.get("response", ""))
            raw_headers = data.get("header", {})

            csp = ""
            if raw_headers:
                for k, v in raw_headers.items():
                    if k.lower() == "content-security-policy":
                        csp = str(v)
                        break

            searchable = f"{body} {csp}"
            detected: Dict[str, Dict[str, str]] = {}

            for pattern, info in VENDOR_PATTERNS.items():
                if pattern in searchable:
                    detected[info["name"]] = info

            for vendor_name, vinfo in detected.items():
                bridge.submit_vendor(
                    host, vendor_name=vendor_name,
                    vendor_category=vinfo["category"],
                    detection_source="response-body+csp",
                    source="vendor-intel",
                )
            findings.append({
                "host": host,
                "vendors": list(detected.keys()),
                "count": len(detected),
            })
        bridge.flush()
        total = sum(f["count"] for f in findings)
        logger.info(f"vendor_intel: {total} vendors across {len(findings)} hosts")
        return findings
    finally:
        os.unlink(hosts_file)


# =========================================================================
# Full Recon Pipeline (11-phase Frogy 2.0 methodology)
# =========================================================================

def run_full_recon(domain: str, bridge: ASMBridge) -> dict:
    """Complete 11-phase pipeline: discovery → DNS → HTTP → ports → vulns →
    crawl → takeover → TLS → headers → mail → vendors."""
    logger.info(f"=== Full recon for {domain} ===")
    results = {"domain": domain}

    # Phase 1: Subdomain discovery
    subs = run_subfinder(domain, bridge)
    results["subdomains"] = len(subs)

    all_hosts = [domain] + subs

    # Phase 2: DNS resolution
    resolved = run_dnsx(all_hosts, bridge)
    results["resolved_hosts"] = len(resolved)

    # Phase 3: HTTP probing
    live = run_httpx(all_hosts[:500], bridge)
    results["live_hosts"] = len(live)
    live_urls = [h.get("url", "") for h in live if h.get("url")]
    live_hostnames = list({h.get("host", h.get("input", "")) for h in live if h.get("host") or h.get("input")})

    # Phase 4: Port scanning
    ips = list(set(resolved.values()))
    port_findings = []
    for ip in ips[:50]:
        port_findings.extend(run_naabu(ip, bridge, ports="top-1000"))
    results["open_ports"] = len(port_findings)

    # Phase 5: Vulnerability scanning
    vuln_findings = []
    for url in live_urls[:100]:
        vuln_findings.extend(run_nuclei(url, bridge))
    results["vulnerabilities"] = len(vuln_findings)

    # Phase 6: Web crawling
    crawled = []
    for url in live_urls[:20]:
        crawled.extend(run_katana(url, bridge, depth=2))
    results["urls_discovered"] = len(crawled)

    # Phase 7: Subdomain takeover detection
    takeover_findings = run_subdomain_takeover(all_hosts[:200], bridge)
    results["takeover_candidates"] = sum(
        1 for f in takeover_findings if f.get("status") in ("confirmed", "potential")
    )

    # Phase 8: TLS deep analysis
    tls_findings = run_tlsx(live_hostnames[:200], bridge)
    results["tls_analyzed"] = len(tls_findings)
    results["tls_poor_grades"] = sum(
        1 for f in tls_findings if f.get("grade") in ("D", "F")
    )

    # Phase 9: Security header analysis
    header_findings = run_security_headers(live_hostnames[:200], bridge)
    results["headers_analyzed"] = len(header_findings)
    results["headers_missing_critical"] = sum(
        1 for f in header_findings if len(f.get("missing", [])) >= 3
    )

    # Phase 10: Mail infrastructure mapping
    root_domains = list({domain})
    mail_findings = run_mail_intel(root_domains, bridge)
    results["mail_analyzed"] = len(mail_findings)
    results["mail_avg_risk"] = (
        sum(f.get("risk_score", 0) for f in mail_findings) // max(len(mail_findings), 1)
    )

    # Phase 11: Third-party vendor intelligence
    vendor_findings = run_third_party_intel(live_hostnames[:50], bridge)
    results["vendors_detected"] = sum(f.get("count", 0) for f in vendor_findings)

    logger.info(f"=== Recon complete: {json.dumps(results, indent=2)} ===")
    return results
