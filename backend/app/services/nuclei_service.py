"""
Nuclei vulnerability scanner integration service.

Integrates with ProjectDiscovery's Nuclei scanner:
https://github.com/projectdiscovery/nuclei

Nuclei is a fast, customizable vulnerability scanner powered by the global 
security community and built on a simple YAML-based DSL.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
from typing import Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class NucleiResult:
    """Single Nuclei scan result."""
    template_id: str
    template_name: str
    severity: str
    host: str
    matched_at: str
    extracted_results: list[str] = field(default_factory=list)
    ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    matcher_name: Optional[str] = None
    matcher_status: bool = True
    description: Optional[str] = None
    reference: list[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    curl_command: Optional[str] = None
    
    @classmethod
    def from_json(cls, data: dict) -> "NucleiResult":
        """Create NucleiResult from Nuclei JSON output."""
        info = data.get("info", {})
        
        # Extract CVE from tags
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        
        cve_id = None
        for tag in tags:
            if tag.upper().startswith("CVE-"):
                cve_id = tag.upper()
                break
        
        # Extract CVSS score
        cvss_score = None
        classification = info.get("classification", {})
        if classification:
            cvss_metrics = classification.get("cvss-metrics", "")
            cvss_score_str = classification.get("cvss-score")
            if cvss_score_str:
                try:
                    cvss_score = float(cvss_score_str)
                except (ValueError, TypeError):
                    pass
        
        return cls(
            template_id=data.get("template-id", data.get("templateID", "")),
            template_name=info.get("name", ""),
            severity=info.get("severity", "unknown"),
            host=data.get("host", ""),
            matched_at=data.get("matched-at", data.get("matched", "")),
            extracted_results=data.get("extracted-results", []),
            ip=data.get("ip", ""),
            timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")) 
                if data.get("timestamp") else datetime.utcnow(),
            matcher_name=data.get("matcher-name", ""),
            matcher_status=data.get("matcher-status", True),
            description=info.get("description", ""),
            reference=info.get("reference", []),
            cvss_score=cvss_score,
            cve_id=cve_id or classification.get("cve-id", [None])[0] if classification else None,
            cwe_id=classification.get("cwe-id", [None])[0] if classification else None,
            tags=tags,
            curl_command=data.get("curl-command", ""),
        )


@dataclass 
class NucleiScanResult:
    """Complete Nuclei scan result."""
    success: bool
    targets_scanned: int = 0
    findings: list[NucleiResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0
    summary: dict = field(default_factory=dict)


class NucleiService:
    """
    Service for running Nuclei vulnerability scans.
    
    Nuclei is a fast, customizable vulnerability scanner powered by the global
    security community. This service wraps the Nuclei CLI tool to integrate
    it into the ASM platform.
    
    Reference: https://github.com/projectdiscovery/nuclei
    """
    
    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates_path: Optional[str] = None,
        output_dir: Optional[str] = None
    ):
        """
        Initialize Nuclei service.
        
        Args:
            nuclei_path: Path to nuclei binary (default assumes it's in PATH)
            templates_path: Custom path to nuclei-templates
            output_dir: Directory for scan outputs
        """
        self.nuclei_path = nuclei_path
        self.templates_path = templates_path
        self.output_dir = output_dir or tempfile.gettempdir()
        
    def check_installation(self) -> bool:
        """Check if Nuclei is installed and accessible."""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def update_templates(self) -> bool:
        """Update Nuclei templates to latest version."""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            logger.info("Nuclei templates updated")
            return result.returncode == 0
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to update templates: {e}")
            return False
    
    async def scan_targets(
        self,
        targets: list[str],
        severity: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        exclude_tags: Optional[list[str]] = None,
        templates: Optional[list[str]] = None,
        rate_limit: int = 150,
        bulk_size: int = 25,
        concurrency: int = 25,
        timeout: int = 10,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> NucleiScanResult:
        """
        Run Nuclei scan against targets.
        
        Args:
            targets: List of targets (URLs, IPs, domains)
            severity: Severity levels to scan for ["critical", "high", "medium", "low", "info"]
            tags: Template tags to include
            exclude_tags: Template tags to exclude
            templates: Specific template paths/IDs
            rate_limit: Max requests per second
            bulk_size: Number of hosts to scan in parallel
            concurrency: Number of templates to run in parallel
            timeout: Request timeout in seconds
            progress_callback: Optional callback for progress updates
            
        Returns:
            NucleiScanResult with all findings
        """
        result = NucleiScanResult(success=False)
        start_time = datetime.utcnow()
        
        # Create temporary files for input/output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(targets))
            targets_file_path = targets_file.name
        
        output_file_path = os.path.join(
            self.output_dir, 
            f"nuclei_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        )
        
        try:
            # Build command
            cmd = [
                self.nuclei_path,
                "-list", targets_file_path,
                "-json-export", output_file_path,
                "-rate-limit", str(rate_limit),
                "-bulk-size", str(bulk_size),
                "-concurrency", str(concurrency),
                "-timeout", str(timeout),
                "-silent",
                "-no-color",
            ]
            
            # Add severity filter
            if severity:
                cmd.extend(["-severity", ",".join(severity)])
            
            # Add tags
            if tags:
                cmd.extend(["-tags", ",".join(tags)])
            
            # Add exclude tags
            if exclude_tags:
                cmd.extend(["-exclude-tags", ",".join(exclude_tags)])
            
            # Add specific templates
            if templates:
                for template in templates:
                    cmd.extend(["-t", template])
            
            # Add custom templates path
            if self.templates_path:
                cmd.extend(["-t", self.templates_path])
            
            logger.info(f"Starting Nuclei scan on {len(targets)} targets")
            logger.debug(f"Command: {' '.join(cmd)}")
            
            # Run scan
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0 and stderr:
                error_msg = stderr.decode()
                if "no templates" not in error_msg.lower():
                    logger.warning(f"Nuclei stderr: {error_msg}")
                    result.errors.append(error_msg)
            
            # Parse results
            if os.path.exists(output_file_path):
                with open(output_file_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                finding_data = json.loads(line)
                                finding = NucleiResult.from_json(finding_data)
                                result.findings.append(finding)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Failed to parse finding: {e}")
            
            result.success = True
            result.targets_scanned = len(targets)
            
            # Generate summary
            result.summary = self._generate_summary(result.findings)
            
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            result.errors.append(str(e))
            
        finally:
            # Cleanup
            if os.path.exists(targets_file_path):
                os.unlink(targets_file_path)
            
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(
            f"Nuclei scan complete: {len(result.findings)} findings in "
            f"{result.duration_seconds:.2f}s"
        )
        
        return result
    
    async def scan_single_target(
        self,
        target: str,
        severity: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
        **kwargs
    ) -> NucleiScanResult:
        """Scan a single target."""
        return await self.scan_targets([target], severity, tags, **kwargs)
    
    def scan_targets_sync(
        self,
        targets: list[str],
        **kwargs
    ) -> NucleiScanResult:
        """Synchronous wrapper for scan_targets."""
        return asyncio.run(self.scan_targets(targets, **kwargs))
    
    def _generate_summary(self, findings: list[NucleiResult]) -> dict:
        """Generate summary statistics from findings."""
        by_severity = {}
        by_template = {}
        by_host = {}
        cves_found = set()
        
        for finding in findings:
            # By severity
            sev = finding.severity.lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1
            
            # By template
            tid = finding.template_id
            by_template[tid] = by_template.get(tid, 0) + 1
            
            # By host
            host = finding.host
            by_host[host] = by_host.get(host, 0) + 1
            
            # CVEs
            if finding.cve_id:
                cves_found.add(finding.cve_id)
        
        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "unique_templates": len(by_template),
            "unique_hosts": len(by_host),
            "cves_found": list(cves_found),
            "critical_count": by_severity.get("critical", 0),
            "high_count": by_severity.get("high", 0),
            "medium_count": by_severity.get("medium", 0),
            "low_count": by_severity.get("low", 0),
            "info_count": by_severity.get("info", 0),
        }
    
    def get_available_tags(self) -> list[str]:
        """Get list of available Nuclei template tags."""
        # Common Nuclei tags
        return [
            # Vulnerability types
            "cve", "rce", "sqli", "xss", "ssrf", "lfi", "rfi", "xxe", "ssti",
            "idor", "csrf", "auth-bypass", "injection",
            # Technology/Service
            "tech", "apache", "nginx", "iis", "tomcat", "wordpress", "joomla",
            "drupal", "magento", "jenkins", "gitlab", "aws", "azure", "gcp",
            # Severity/Impact  
            "critical", "high", "medium", "low", "info",
            # Discovery type
            "exposure", "misconfig", "default-login", "unauth", "takeover",
            "creds-exposure", "token", "backup", "debug",
            # Protocol
            "http", "https", "ftp", "ssh", "dns", "smtp", "ssl",
            # Categories
            "cisa-kev", "oast", "headless", "fuzzing", "dos",
        ]
    
    def get_severity_levels(self) -> list[str]:
        """Get available severity levels."""
        return ["critical", "high", "medium", "low", "info"]


# Severity to risk score mapping
SEVERITY_RISK_SCORES = {
    "critical": 95,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
    "unknown": 0,
}




