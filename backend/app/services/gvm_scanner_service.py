"""
GVM (Greenbone Vulnerability Management) Scanner Service

Integrates with GVM/OpenVAS for deep authenticated vulnerability scanning
with 170,000+ Network Vulnerability Tests (NVTs).
"""

import logging
import time
from typing import Optional, List, Dict, Any
from datetime import datetime
from xml.etree import ElementTree as ET

from app.core.config import settings
from app.db.database import SessionLocal
from app.models.vulnerability import Vulnerability, Severity, VulnerabilityStatus
from app.models.asset import Asset, AssetType

logger = logging.getLogger(__name__)


# Severity mapping from GVM to our model
GVM_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,  # 9.0 - 10.0
    "high": Severity.HIGH,          # 7.0 - 8.9
    "medium": Severity.MEDIUM,      # 4.0 - 6.9
    "low": Severity.LOW,            # 0.1 - 3.9
    "log": Severity.INFO,           # 0.0
}


def cvss_to_severity(cvss_score: float) -> str:
    """Convert CVSS score to severity level."""
    if cvss_score >= 9.0:
        return "critical"
    elif cvss_score >= 7.0:
        return "high"
    elif cvss_score >= 4.0:
        return "medium"
    elif cvss_score >= 0.1:
        return "low"
    return "log"


class GVMScannerService:
    """
    Service for GVM vulnerability scanning.
    
    Requires GVM to be running and accessible via the configured socket.
    """
    
    def __init__(self):
        self.enabled = settings.GVM_ENABLED
        self.socket_path = settings.GVM_SOCKET_PATH
        self.username = settings.GVM_USERNAME
        self.password = settings.GVM_PASSWORD
        self.scan_config = settings.GVM_SCAN_CONFIG
        self._connected = False
        self._gmp = None
    
    def is_available(self) -> bool:
        """Check if GVM is available."""
        if not self.enabled:
            return False
        
        try:
            return self.connect()
        except Exception:
            return False
    
    def connect(self) -> bool:
        """Connect to GVM via Unix socket."""
        if self._connected:
            return True
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                self._gmp = gmp
                self._connected = True
                logger.info("Connected to GVM")
                return True
        
        except ImportError:
            logger.warning("python-gvm not installed - GVM integration unavailable")
            return False
        except FileNotFoundError:
            logger.warning(f"GVM socket not found at {self.socket_path}")
            return False
        except Exception as e:
            logger.error(f"GVM connection failed: {e}")
            return False
    
    def get_scan_configs(self) -> List[Dict[str, str]]:
        """Get available scan configurations."""
        if not self.connect():
            return []
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                response = gmp.get_scan_configs()
                configs = []
                
                for config in response.findall('.//config'):
                    configs.append({
                        "id": config.get("id"),
                        "name": config.findtext("name", ""),
                    })
                
                return configs
        
        except Exception as e:
            logger.error(f"Error getting scan configs: {e}")
            return []
    
    def get_port_lists(self) -> List[Dict[str, str]]:
        """Get available port lists."""
        if not self.connect():
            return []
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                response = gmp.get_port_lists()
                port_lists = []
                
                for pl in response.findall('.//port_list'):
                    port_lists.append({
                        "id": pl.get("id"),
                        "name": pl.findtext("name", ""),
                    })
                
                return port_lists
        
        except Exception as e:
            logger.error(f"Error getting port lists: {e}")
            return []
    
    def create_target(
        self,
        name: str,
        hosts: List[str],
        port_list_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Create a scan target.
        
        Args:
            name: Target name
            hosts: List of IP addresses or hostnames
            port_list_id: Optional port list ID
        
        Returns:
            Target ID if successful
        """
        if not self.connect():
            return None
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Get default port list if not specified
                if not port_list_id:
                    port_lists = self.get_port_lists()
                    for pl in port_lists:
                        if "All IANA assigned TCP" in pl["name"]:
                            port_list_id = pl["id"]
                            break
                
                response = gmp.create_target(
                    name=name,
                    hosts=hosts,
                    port_list_id=port_list_id
                )
                
                target_id = response.get("id")
                logger.info(f"Created target: {target_id}")
                return target_id
        
        except Exception as e:
            logger.error(f"Error creating target: {e}")
            return None
    
    def create_task(
        self,
        name: str,
        target_id: str,
        config_name: Optional[str] = None
    ) -> Optional[str]:
        """
        Create a scan task.
        
        Args:
            name: Task name
            target_id: Target ID
            config_name: Scan configuration name
        
        Returns:
            Task ID if successful
        """
        if not self.connect():
            return None
        
        config_name = config_name or self.scan_config
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Get config ID
                configs = self.get_scan_configs()
                config_id = None
                for config in configs:
                    if config["name"] == config_name:
                        config_id = config["id"]
                        break
                
                if not config_id:
                    logger.error(f"Scan config '{config_name}' not found")
                    return None
                
                # Get default scanner
                scanners = gmp.get_scanners()
                scanner_id = None
                for scanner in scanners.findall('.//scanner'):
                    if "OpenVAS" in scanner.findtext("name", ""):
                        scanner_id = scanner.get("id")
                        break
                
                response = gmp.create_task(
                    name=name,
                    config_id=config_id,
                    target_id=target_id,
                    scanner_id=scanner_id
                )
                
                task_id = response.get("id")
                logger.info(f"Created task: {task_id}")
                return task_id
        
        except Exception as e:
            logger.error(f"Error creating task: {e}")
            return None
    
    def start_task(self, task_id: str) -> Optional[str]:
        """
        Start a scan task.
        
        Args:
            task_id: Task ID
        
        Returns:
            Report ID if successful
        """
        if not self.connect():
            return None
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                response = gmp.start_task(task_id)
                report_id = response.findtext('.//report_id')
                logger.info(f"Started task {task_id}, report: {report_id}")
                return report_id
        
        except Exception as e:
            logger.error(f"Error starting task: {e}")
            return None
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Get task status.
        
        Args:
            task_id: Task ID
        
        Returns:
            Dict with status and progress
        """
        if not self.connect():
            return {"status": "error", "progress": 0}
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                response = gmp.get_task(task_id)
                task = response.find('.//task')
                
                if task is None:
                    return {"status": "not_found", "progress": 0}
                
                status = task.findtext('status', 'unknown')
                progress = int(task.findtext('progress', '0'))
                
                return {
                    "status": status.lower(),
                    "progress": progress,
                }
        
        except Exception as e:
            logger.error(f"Error getting task status: {e}")
            return {"status": "error", "progress": 0}
    
    def wait_for_task(
        self,
        task_id: str,
        timeout: int = 7200,
        poll_interval: int = 30
    ) -> tuple:
        """
        Wait for a task to complete.
        
        Args:
            task_id: Task ID
            timeout: Maximum wait time in seconds
            poll_interval: Seconds between status checks
        
        Returns:
            Tuple of (status, report_id or None)
        """
        start_time = time.time()
        report_id = None
        
        while time.time() - start_time < timeout:
            status_info = self.get_task_status(task_id)
            status = status_info.get("status", "unknown")
            progress = status_info.get("progress", 0)
            
            logger.info(f"Task {task_id}: {status} ({progress}%)")
            
            if status == "done":
                # Get report ID
                try:
                    from gvm.connections import UnixSocketConnection
                    from gvm.protocols.gmp import Gmp
                    from gvm.transforms import EtreeTransform
                    
                    connection = UnixSocketConnection(path=self.socket_path)
                    transform = EtreeTransform()
                    
                    with Gmp(connection=connection, transform=transform) as gmp:
                        gmp.authenticate(self.username, self.password)
                        task = gmp.get_task(task_id).find('.//task')
                        if task is not None:
                            report = task.find('.//report')
                            if report is not None:
                                report_id = report.get("id")
                
                except Exception as e:
                    logger.error(f"Error getting report ID: {e}")
                
                return ("done", report_id)
            
            elif status in ["stopped", "stop requested"]:
                return ("stopped", None)
            
            elif status == "error":
                return ("error", None)
            
            time.sleep(poll_interval)
        
        return ("timeout", None)
    
    def get_report(self, report_id: str) -> List[Dict[str, Any]]:
        """
        Get scan results from a report.
        
        Args:
            report_id: Report ID
        
        Returns:
            List of vulnerability findings
        """
        if not self.connect():
            return []
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                response = gmp.get_report(report_id)
                
                findings = []
                for result in response.findall('.//result'):
                    severity = float(result.findtext('severity', '0'))
                    
                    finding = {
                        "name": result.findtext('name', 'Unknown'),
                        "oid": result.findtext('nvt/oid', ''),
                        "severity": cvss_to_severity(severity),
                        "cvss_score": severity,
                        "host": result.findtext('host', ''),
                        "port": result.findtext('port', ''),
                        "description": result.findtext('description', ''),
                        "solution": result.findtext('nvt/solution', ''),
                        "cve": [],
                        "references": [],
                    }
                    
                    # Extract CVEs
                    for ref in result.findall('.//nvt/refs/ref'):
                        ref_type = ref.get("type", "")
                        ref_id = ref.get("id", "")
                        if ref_type == "cve":
                            finding["cve"].append(ref_id)
                        if ref.text:
                            finding["references"].append(ref.text)
                    
                    findings.append(finding)
                
                return findings
        
        except Exception as e:
            logger.error(f"Error getting report: {e}")
            return []
    
    def scan(
        self,
        targets: List[str],
        organization_id: int,
        scan_name: Optional[str] = None,
        wait: bool = True,
        timeout: int = 7200
    ) -> Dict[str, Any]:
        """
        Run a complete vulnerability scan.
        
        Args:
            targets: List of IP addresses or hostnames to scan
            organization_id: Organization ID for storing results
            scan_name: Optional name for the scan
            wait: Whether to wait for completion
            timeout: Maximum wait time if waiting
        
        Returns:
            Scan results summary
        """
        if not self.is_available():
            return {
                "error": "GVM not available",
                "status": "failed",
            }
        
        scan_name = scan_name or f"ASM_Scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        # Create target
        target_id = self.create_target(
            name=f"{scan_name}_target",
            hosts=targets
        )
        
        if not target_id:
            return {
                "error": "Failed to create target",
                "status": "failed",
            }
        
        # Create task
        task_id = self.create_task(
            name=scan_name,
            target_id=target_id
        )
        
        if not task_id:
            return {
                "error": "Failed to create task",
                "status": "failed",
            }
        
        # Start task
        report_id = self.start_task(task_id)
        
        if not report_id:
            return {
                "error": "Failed to start task",
                "status": "failed",
            }
        
        if not wait:
            return {
                "status": "started",
                "task_id": task_id,
                "report_id": report_id,
            }
        
        # Wait for completion
        status, final_report_id = self.wait_for_task(task_id, timeout)
        
        if status != "done":
            return {
                "error": f"Scan {status}",
                "status": status,
                "task_id": task_id,
            }
        
        # Get results
        findings = self.get_report(final_report_id or report_id)
        
        # Store findings
        stored = self._store_findings(findings, targets, organization_id)
        
        # Summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "log": 0}
        for f in findings:
            sev = f.get("severity", "log")
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        return {
            "status": "completed",
            "task_id": task_id,
            "report_id": final_report_id or report_id,
            "targets_scanned": len(targets),
            "vulnerabilities_found": len(findings),
            "vulnerabilities_stored": stored,
            "severity_breakdown": severity_counts,
        }
    
    def _store_findings(
        self,
        findings: List[Dict[str, Any]],
        targets: List[str],
        organization_id: int
    ) -> int:
        """Store GVM findings as vulnerabilities."""
        db = SessionLocal()
        stored = 0
        
        try:
            for finding in findings:
                host = finding.get("host", "")
                
                # Find or create asset for the host
                asset = db.query(Asset).filter(
                    Asset.value == host,
                    Asset.organization_id == organization_id
                ).first()
                
                if not asset:
                    # Try to find by target
                    for target in targets:
                        asset = db.query(Asset).filter(
                            Asset.value == target,
                            Asset.organization_id == organization_id
                        ).first()
                        if asset:
                            break
                
                if not asset:
                    # Create new asset
                    asset = Asset(
                        value=host or targets[0] if targets else "unknown",
                        asset_type=AssetType.IP_ADDRESS,
                        organization_id=organization_id,
                        is_active=True,
                        first_seen=datetime.utcnow(),
                    )
                    db.add(asset)
                    db.commit()
                    db.refresh(asset)
                
                # Create vulnerability
                severity = GVM_SEVERITY_MAP.get(
                    finding.get("severity", "log"),
                    Severity.INFO
                )
                
                vuln = Vulnerability(
                    title=finding.get("name", "Unknown Vulnerability"),
                    description=finding.get("description", ""),
                    severity=severity,
                    cvss_score=finding.get("cvss_score"),
                    cve_id=finding.get("cve", [None])[0] if finding.get("cve") else None,
                    asset_id=asset.id,
                    detected_by="gvm_openvas",
                    status=VulnerabilityStatus.OPEN,
                    remediation=finding.get("solution", ""),
                    first_detected=datetime.utcnow(),
                    last_detected=datetime.utcnow(),
                    references=finding.get("references", []),
                    metadata_={
                        "oid": finding.get("oid"),
                        "port": finding.get("port"),
                        "host": finding.get("host"),
                        "all_cves": finding.get("cve", []),
                    },
                )
                db.add(vuln)
                stored += 1
            
            db.commit()
            logger.info(f"Stored {stored} GVM findings")
        
        except Exception as e:
            logger.error(f"Error storing findings: {e}")
            db.rollback()
        finally:
            db.close()
        
        return stored
    
    def cleanup(self, task_id: str, target_id: str):
        """Clean up task and target after scan."""
        if not self.connect():
            return
        
        try:
            from gvm.connections import UnixSocketConnection
            from gvm.protocols.gmp import Gmp
            from gvm.transforms import EtreeTransform
            
            connection = UnixSocketConnection(path=self.socket_path)
            transform = EtreeTransform()
            
            with Gmp(connection=connection, transform=transform) as gmp:
                gmp.authenticate(self.username, self.password)
                
                # Delete task
                try:
                    gmp.delete_task(task_id)
                    logger.info(f"Deleted task: {task_id}")
                except Exception as e:
                    logger.debug(f"Could not delete task: {e}")
                
                # Delete target
                try:
                    gmp.delete_target(target_id)
                    logger.info(f"Deleted target: {target_id}")
                except Exception as e:
                    logger.debug(f"Could not delete target: {e}")
        
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


# Global service instance
_gvm_service: Optional[GVMScannerService] = None


def get_gvm_service() -> GVMScannerService:
    """Get or create the global GVM service."""
    global _gvm_service
    if _gvm_service is None:
        _gvm_service = GVMScannerService()
    return _gvm_service
