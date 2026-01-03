"""
Unified port scanner service integrating multiple scanning tools.

Supports:
- Naabu: Fast port scanner from ProjectDiscovery (https://github.com/projectdiscovery/naabu)
- Masscan: Mass IP port scanner
- Nmap: Network exploration and security auditing

All results are normalized to a common format for storage in the PortService model.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
import re
import xml.etree.ElementTree as ET
from typing import Optional, List, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType
from app.models.port_service import (
    PortService, Protocol, PortState, 
    RISKY_PORTS, SERVICE_NAMES
)

logger = logging.getLogger(__name__)


class ScannerType(str, Enum):
    """Available port scanner types."""
    NAABU = "naabu"
    MASSCAN = "masscan"
    NMAP = "nmap"


@dataclass
class PortResult:
    """Normalized port scan result."""
    host: str
    ip: str
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    service_extra_info: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    reason: Optional[str] = None
    scanner: str = "unknown"
    
    def to_port_service_dict(self, asset_id: int) -> dict:
        """Convert to PortService creation dict."""
        # Auto-detect service name from port if not provided
        service = self.service_name
        if not service and self.port in SERVICE_NAMES:
            service = SERVICE_NAMES[self.port]
        
        # Determine if risky
        is_risky = self.port in RISKY_PORTS
        risk_reason = RISKY_PORTS.get(self.port) if is_risky else None
        
        # Map state
        state_map = {
            "open": PortState.OPEN,
            "closed": PortState.CLOSED,
            "filtered": PortState.FILTERED,
            "open|filtered": PortState.OPEN_FILTERED,
            "closed|filtered": PortState.CLOSED_FILTERED,
        }
        
        return {
            "asset_id": asset_id,
            "port": self.port,
            "protocol": Protocol(self.protocol.lower()),
            "service_name": service,
            "service_product": self.service_product,
            "service_version": self.service_version,
            "service_extra_info": self.service_extra_info,
            "banner": self.banner,
            "cpe": self.cpe,
            "state": state_map.get(self.state.lower(), PortState.OPEN),
            "reason": self.reason,
            "discovered_by": self.scanner,
            "is_risky": is_risky,
            "risk_reason": risk_reason,
        }


@dataclass
class ScanResult:
    """Complete scan result from any scanner."""
    success: bool
    scanner: ScannerType
    targets_scanned: int = 0
    ports_found: List[PortResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0
    raw_output: Optional[str] = None


class PortScannerService:
    """
    Unified service for running port scans with multiple tools.
    
    Supports Naabu, Masscan, and Nmap with normalized output format.
    """
    
    def __init__(
        self,
        naabu_path: str = "naabu",
        masscan_path: str = "masscan",
        nmap_path: str = "nmap"
    ):
        """Initialize port scanner service."""
        self.naabu_path = naabu_path
        self.masscan_path = masscan_path
        self.nmap_path = nmap_path
    
    def check_tools(self) -> dict[str, bool]:
        """Check which scanning tools are available."""
        tools = {
            "naabu": self.naabu_path,
            "masscan": self.masscan_path,
            "nmap": self.nmap_path,
        }
        
        status = {}
        for name, path in tools.items():
            try:
                result = subprocess.run(
                    [path, "--version" if name != "naabu" else "-version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                status[name] = result.returncode == 0
            except (subprocess.SubprocessError, FileNotFoundError):
                status[name] = False
        
        return status
    
    # ==================== NAABU ====================
    
    async def scan_with_naabu(
        self,
        targets: List[str],
        ports: Optional[str] = None,
        top_ports: int = 100,
        rate: int = 1000,
        timeout: int = 10,
        exclude_cdn: bool = True
    ) -> ScanResult:
        """
        Run port scan using Naabu.
        
        Naabu is a fast port scanner from ProjectDiscovery designed for
        reliability and simplicity. Supports SYN/CONNECT scans.
        
        Reference: https://github.com/projectdiscovery/naabu
        
        Args:
            targets: List of targets (IPs, domains, CIDRs)
            ports: Port specification (e.g., "80,443,8080" or "1-1000" or "-" for all)
            top_ports: Scan top N ports if ports not specified
            rate: Packets per second
            timeout: Timeout in seconds
            exclude_cdn: Exclude CDN IPs (only scan 80,443)
        """
        result = ScanResult(success=False, scanner=ScannerType.NAABU)
        start_time = datetime.utcnow()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.naabu_path,
                "-list", targets_path,
                "-json",
                "-o", output_path,
                "-silent",
                "-rate", str(rate),
                "-timeout", str(timeout),
                "-c",  # Use CONNECT scan (doesn't require root privileges)
            ]
            
            # Handle port specification
            if ports:
                if ports == "-" or ports == "all":
                    # Naabu uses "-" for all ports
                    cmd.extend(["-p", "-"])
                else:
                    cmd.extend(["-p", ports])
            else:
                cmd.extend(["-top-ports", str(top_ports)])
            
            if exclude_cdn:
                cmd.append("-exclude-cdn")
            
            logger.info(f"Running naabu scan on {len(targets)} targets")
            logger.debug(f"Naabu command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Log any errors from naabu
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else f"Exit code: {process.returncode}"
                logger.error(f"Naabu scan failed: {error_msg}")
                result.errors.append(error_msg)
            
            if stderr:
                stderr_text = stderr.decode()
                if "error" in stderr_text.lower() or "failed" in stderr_text.lower():
                    logger.warning(f"Naabu stderr: {stderr_text}")
                    result.errors.append(stderr_text)
                else:
                    logger.info(f"Naabu output: {stderr_text}")
            
            # Parse JSON output
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                # Naabu JSON format: {"host":"example.com","ip":"1.2.3.4","port":80}
                                result.ports_found.append(PortResult(
                                    host=data.get("host", ""),
                                    ip=data.get("ip", data.get("host", "")),
                                    port=data.get("port", 0),
                                    protocol=data.get("protocol", "tcp"),
                                    state="open",
                                    scanner="naabu"
                                ))
                            except json.JSONDecodeError:
                                pass
            
            result.success = True
            result.targets_scanned = len(targets)
            
        except Exception as e:
            logger.error(f"Naabu scan failed: {e}")
            result.errors.append(str(e))
        
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
            
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"Naabu found {len(result.ports_found)} open ports")
        return result
    
    # ==================== MASSCAN ====================
    
    async def scan_with_masscan(
        self,
        targets: List[str],
        ports: str = "1-65535",
        rate: int = 10000,
        timeout: int = 30,
        banner_grab: bool = True,
        one_port_at_a_time: bool = False
    ) -> ScanResult:
        """
        Run port scan using Masscan.
        
        Masscan is the fastest port scanner, capable of scanning the
        entire internet in under 6 minutes. Supports CIDR notation
        (e.g., 205.175.240.0/24) directly in targets.
        
        NOTE: Masscan requires root privileges for raw socket access.
        In Docker, the container needs CAP_NET_RAW + CAP_NET_ADMIN and run as root.
        
        Args:
            targets: List of targets (IPs, CIDRs like 205.175.240.0/24)
            ports: Port specification (e.g., "80,443", "1-1000", "1-65535")
            rate: Packets per second (default 10000, reduce for stealth)
            timeout: Wait time after scan completes
            banner_grab: Enable banner grabbing for service detection
            one_port_at_a_time: Scan each port separately (slower but avoids cloud blocks)
        """
        result = ScanResult(success=False, scanner=ScannerType.MASSCAN)
        start_time = datetime.utcnow()
        
        # Handle special port notation
        if ports == "-" or ports == "all":
            ports = "0-65535"
        elif not ports:
            ports = "1-65535"
        
        # If one_port_at_a_time mode, scan each port separately (ASM Recon approach)
        # This is slower but less likely to be blocked by cloud providers
        if one_port_at_a_time:
            return await self._scan_masscan_per_port(
                targets, ports, rate, timeout, banner_grab
            )
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            # Masscan natively supports CIDR notation in input files
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.masscan_path,
                "-iL", targets_path,
                "-p", ports,
                "--rate", str(rate),
                "--wait", str(timeout),
                "-oJ", output_path,
            ]
            
            # Add banner grabbing for service detection
            if banner_grab:
                cmd.append("--banner")
            
            logger.info(f"Running masscan on {len(targets)} targets with ports={ports}")
            logger.debug(f"Masscan command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Log any errors from masscan
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else f"Exit code: {process.returncode}"
                logger.error(f"Masscan failed: {error_msg}")
                result.errors.append(error_msg)
                
                # Check for common issues
                if "permission denied" in error_msg.lower() or "operation not permitted" in error_msg.lower():
                    result.errors.append("Masscan requires root privileges. Run container with --privileged or use naabu instead.")
                elif "libpcap" in error_msg.lower():
                    result.errors.append("Masscan requires libpcap. Install with: apt-get install libpcap-dev")
            
            if stderr and process.returncode == 0:
                logger.info(f"Masscan output: {stderr.decode()}")
            
            # Parse JSON output
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    content = f.read().strip()
                    if content:
                        try:
                            # Masscan JSON is an array
                            data = json.loads(content)
                            for entry in data:
                                ip = entry.get("ip", "")
                                for port_info in entry.get("ports", []):
                                    result.ports_found.append(PortResult(
                                        host=ip,
                                        ip=ip,
                                        port=port_info.get("port", 0),
                                        protocol=port_info.get("proto", "tcp"),
                                        state=port_info.get("status", "open"),
                                        reason=port_info.get("reason", ""),
                                        banner=port_info.get("service", {}).get("banner", ""),
                                        scanner="masscan"
                                    ))
                        except json.JSONDecodeError:
                            # Try line-by-line parsing
                            for line in content.split("\n"):
                                line = line.strip().rstrip(",")
                                if line and line.startswith("{"):
                                    try:
                                        entry = json.loads(line)
                                        ip = entry.get("ip", "")
                                        for port_info in entry.get("ports", []):
                                            result.ports_found.append(PortResult(
                                                host=ip,
                                                ip=ip,
                                                port=port_info.get("port", 0),
                                                protocol=port_info.get("proto", "tcp"),
                                                state="open",
                                                scanner="masscan"
                                            ))
                                    except json.JSONDecodeError:
                                        pass
            
            result.success = True
            result.targets_scanned = len(targets)
            
        except Exception as e:
            logger.error(f"Masscan scan failed: {e}")
            result.errors.append(str(e))
        
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
            
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"Masscan found {len(result.ports_found)} open ports")
        return result
    
    async def _scan_masscan_per_port(
        self,
        targets: List[str],
        ports: str,
        rate: int,
        timeout: int,
        banner_grab: bool
    ) -> ScanResult:
        """
        Scan one port at a time across all targets (ASM Recon approach).
        
        This is slower but less likely to trigger cloud provider blocks.
        Based on ASM Recon get_masscan script approach.
        """
        result = ScanResult(success=False, scanner=ScannerType.MASSCAN)
        start_time = datetime.utcnow()
        
        # Parse port range
        port_list = self._parse_port_spec(ports)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name
        
        try:
            logger.info(f"Running masscan per-port mode on {len(targets)} targets, {len(port_list)} ports")
            
            for port in port_list:
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
                    output_path = output_file.name
                
                try:
                    cmd = [
                        self.masscan_path,
                        "-iL", targets_path,
                        "-p", str(port),
                        "--rate", str(rate),
                        "--wait", str(min(timeout, 5)),  # Shorter wait per port
                        "-oJ", output_path,
                    ]
                    
                    if banner_grab:
                        cmd.append("--banner")
                    
                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    await process.communicate()
                    
                    # Parse output for this port
                    if os.path.exists(output_path):
                        with open(output_path, 'r') as f:
                            content = f.read().strip()
                            if content:
                                self._parse_masscan_json(content, result.ports_found)
                    
                finally:
                    if os.path.exists(output_path):
                        os.unlink(output_path)
            
            result.success = True
            result.targets_scanned = len(targets)
            
        except Exception as e:
            logger.error(f"Masscan per-port scan failed: {e}")
            result.errors.append(str(e))
        
        finally:
            if os.path.exists(targets_path):
                os.unlink(targets_path)
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"Masscan per-port found {len(result.ports_found)} open ports")
        return result
    
    def _parse_port_spec(self, ports: str) -> List[int]:
        """Parse port specification into list of ports."""
        port_list = []
        
        for part in ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
        
        return port_list
    
    def _parse_masscan_json(self, content: str, results: List[PortResult]):
        """Parse masscan JSON output and append to results list."""
        try:
            data = json.loads(content)
            for entry in data:
                ip = entry.get("ip", "")
                for port_info in entry.get("ports", []):
                    # Extract banner/service info if available
                    service_info = port_info.get("service", {})
                    banner = service_info.get("banner", "")
                    
                    results.append(PortResult(
                        host=ip,
                        ip=ip,
                        port=port_info.get("port", 0),
                        protocol=port_info.get("proto", "tcp"),
                        state=port_info.get("status", "open"),
                        reason=port_info.get("reason", ""),
                        banner=banner,
                        scanner="masscan"
                    ))
        except json.JSONDecodeError:
            # Try line-by-line parsing for partial JSON
            for line in content.split("\n"):
                line = line.strip().rstrip(",")
                if line and line.startswith("{"):
                    try:
                        entry = json.loads(line)
                        ip = entry.get("ip", "")
                        for port_info in entry.get("ports", []):
                            results.append(PortResult(
                                host=ip,
                                ip=ip,
                                port=port_info.get("port", 0),
                                protocol=port_info.get("proto", "tcp"),
                                state="open",
                                scanner="masscan"
                            ))
                    except json.JSONDecodeError:
                        pass
    
    # ==================== NMAP ====================
    
    async def scan_with_nmap(
        self,
        targets: List[str],
        ports: Optional[str] = None,
        scan_type: str = "-sT",  # TCP connect scan (doesn't require root)
        service_detection: bool = True,
        os_detection: bool = False,
        timing: int = 4,  # T4 aggressive timing
        scripts: Optional[List[str]] = None
    ) -> ScanResult:
        """
        Run port scan using Nmap.
        
        Nmap is the most feature-rich scanner with service detection,
        OS fingerprinting, and scripting capabilities.
        
        NOTE: Uses -sT (connect scan) by default which doesn't require root.
        SYN scan (-sS) is faster but requires root privileges.
        
        Args:
            targets: List of targets
            ports: Port specification (None = top 1000, "-" = all ports)
            scan_type: Nmap scan type (-sS, -sT, -sU, etc.)
            service_detection: Enable service/version detection (-sV)
            os_detection: Enable OS detection (-O)
            timing: Timing template (0-5, higher = faster)
            scripts: NSE scripts to run
        """
        result = ScanResult(success=False, scanner=ScannerType.NMAP)
        start_time = datetime.utcnow()
        
        # Handle special port notation
        if ports == "-" or ports == "all":
            ports = "1-65535"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.nmap_path,
                "-iL", targets_path,
                "-oX", output_path,
                scan_type,
                f"-T{timing}",
                "-Pn",  # Skip host discovery, scan all hosts
            ]
            
            if ports:
                cmd.extend(["-p", ports])
            
            if service_detection:
                cmd.append("-sV")
            
            if os_detection:
                cmd.append("-O")
            
            if scripts:
                cmd.extend(["--script", ",".join(scripts)])
            
            logger.info(f"Running nmap scan on {len(targets)} targets with ports={ports}")
            logger.debug(f"Nmap command: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Log any errors from nmap
            if process.returncode != 0:
                error_msg = stderr.decode() if stderr else f"Exit code: {process.returncode}"
                logger.error(f"Nmap scan failed: {error_msg}")
                result.errors.append(error_msg)
                
                # Check for common issues
                if "requires root" in error_msg.lower() or "operation not permitted" in error_msg.lower():
                    result.errors.append("Nmap SYN scan requires root. Using -sT (connect scan) instead.")
            
            if stderr:
                stderr_text = stderr.decode()
                logger.info(f"Nmap stderr: {stderr_text}")
            
            # Parse XML output
            if os.path.exists(output_path):
                result.ports_found = self._parse_nmap_xml(output_path)
                logger.info(f"Parsed {len(result.ports_found)} ports from nmap XML output")
            else:
                logger.warning(f"Nmap output file not found: {output_path}")
                result.errors.append("Nmap did not produce output file")
            
            result.success = True
            result.targets_scanned = len(targets)
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            result.errors.append(str(e))
        
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
            
            result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        logger.info(f"Nmap found {len(result.ports_found)} open ports")
        return result
    
    def _parse_nmap_xml(self, xml_path: str) -> List[PortResult]:
        """Parse Nmap XML output."""
        results = []
        
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            
            for host in root.findall(".//host"):
                # Get IP address
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find("address[@addrtype='ipv6']")
                if addr_elem is None:
                    continue
                
                ip = addr_elem.get("addr", "")
                
                # Get hostname if available
                hostname = ip
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hostname_elem = hostnames.find("hostname")
                    if hostname_elem is not None:
                        hostname = hostname_elem.get("name", ip)
                
                # Get ports
                ports = host.find("ports")
                if ports is None:
                    continue
                
                for port in ports.findall("port"):
                    port_id = int(port.get("portid", 0))
                    protocol = port.get("protocol", "tcp")
                    
                    # State
                    state_elem = port.find("state")
                    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
                    reason = state_elem.get("reason", "") if state_elem is not None else ""
                    
                    # Service info
                    service_elem = port.find("service")
                    service_name = None
                    service_product = None
                    service_version = None
                    service_extra = None
                    cpe = None
                    
                    if service_elem is not None:
                        service_name = service_elem.get("name")
                        service_product = service_elem.get("product")
                        service_version = service_elem.get("version")
                        service_extra = service_elem.get("extrainfo")
                        
                        # Get CPE
                        cpe_elem = service_elem.find("cpe")
                        if cpe_elem is not None:
                            cpe = cpe_elem.text
                    
                    results.append(PortResult(
                        host=hostname,
                        ip=ip,
                        port=port_id,
                        protocol=protocol,
                        state=state,
                        service_name=service_name,
                        service_product=service_product,
                        service_version=service_version,
                        service_extra_info=service_extra,
                        cpe=cpe,
                        reason=reason,
                        scanner="nmap"
                    ))
        
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
        
        return results
    
    # ==================== UNIFIED SCAN ====================
    
    async def scan(
        self,
        targets: List[str],
        scanner: ScannerType = ScannerType.NAABU,
        ports: Optional[str] = None,
        **kwargs
    ) -> ScanResult:
        """
        Run a port scan using the specified scanner.
        
        Args:
            targets: List of targets (IPs, domains, CIDRs like 205.175.240.0/24)
            scanner: Scanner to use (naabu, masscan, nmap)
            ports: Port specification (e.g., "80,443", "1-1000", "-" for all)
            **kwargs: Additional scanner-specific options:
                - For masscan: banner_grab=True, one_port_at_a_time=False
                - For naabu: top_ports=100, rate=1000, exclude_cdn=True
                - For nmap: service_detection=True, os_detection=False
        """
        if scanner == ScannerType.NAABU:
            return await self.scan_with_naabu(targets, ports=ports, **kwargs)
        elif scanner == ScannerType.MASSCAN:
            return await self.scan_with_masscan(targets, ports=ports or "1-65535", **kwargs)
        elif scanner == ScannerType.NMAP:
            return await self.scan_with_nmap(targets, ports=ports, **kwargs)
        else:
            raise ValueError(f"Unknown scanner: {scanner}")
    
    # ==================== IMPORT TO DATABASE ====================
    
    def import_results_to_assets(
        self,
        db: Session,
        scan_result: ScanResult,
        organization_id: int,
        create_assets: bool = True
    ) -> dict:
        """
        Import scan results into the database, associating with assets.
        
        Args:
            db: Database session
            scan_result: Scan results to import
            organization_id: Organization ID
            create_assets: Create assets if they don't exist
            
        Returns:
            Summary of import results
        """
        summary = {
            "ports_imported": 0,
            "ports_updated": 0,
            "assets_created": 0,
            "errors": []
        }
        
        # Group results by host/IP
        by_host = {}
        for port_result in scan_result.ports_found:
            key = port_result.ip or port_result.host
            if key not in by_host:
                by_host[key] = []
            by_host[key].append(port_result)
        
        for host, ports in by_host.items():
            # Find or create asset
            asset = db.query(Asset).filter(
                Asset.organization_id == organization_id,
                Asset.value == host
            ).first()
            
            if not asset and create_assets:
                # Determine asset type
                asset_type = AssetType.IP_ADDRESS
                if not self._is_ip(host):
                    asset_type = AssetType.DOMAIN
                
                asset = Asset(
                    organization_id=organization_id,
                    name=host,
                    value=host,
                    asset_type=asset_type,
                    discovery_source=scan_result.scanner.value
                )
                db.add(asset)
                db.flush()
                summary["assets_created"] += 1
            
            if not asset:
                summary["errors"].append(f"No asset found for {host}")
                continue
            
            # Import ports
            for port_result in ports:
                try:
                    # Check for existing port
                    existing = db.query(PortService).filter(
                        PortService.asset_id == asset.id,
                        PortService.port == port_result.port,
                        PortService.protocol == Protocol(port_result.protocol.lower())
                    ).first()
                    
                    if existing:
                        # Update existing
                        existing.last_seen = datetime.utcnow()
                        existing.state = PortState.OPEN
                        if port_result.service_name:
                            existing.service_name = port_result.service_name
                        if port_result.service_product:
                            existing.service_product = port_result.service_product
                        if port_result.service_version:
                            existing.service_version = port_result.service_version
                        if port_result.banner:
                            existing.banner = port_result.banner
                        if port_result.cpe:
                            existing.cpe = port_result.cpe
                        summary["ports_updated"] += 1
                    else:
                        # Create new
                        port_data = port_result.to_port_service_dict(asset.id)
                        port_service = PortService(**port_data)
                        db.add(port_service)
                        summary["ports_imported"] += 1
                        
                except Exception as e:
                    summary["errors"].append(f"Error importing {host}:{port_result.port}: {e}")
        
        db.commit()
        return summary
    
    def _is_ip(self, value: str) -> bool:
        """Check if value is an IP address."""
        import re
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        return bool(re.match(ipv4_pattern, value) or re.match(ipv6_pattern, value))
    
    # ==================== PARSE EXISTING OUTPUT ====================
    
    def parse_naabu_output(self, output: str) -> List[PortResult]:
        """Parse Naabu JSON output from string."""
        results = []
        for line in output.strip().split("\n"):
            line = line.strip()
            if line:
                try:
                    data = json.loads(line)
                    results.append(PortResult(
                        host=data.get("host", ""),
                        ip=data.get("ip", data.get("host", "")),
                        port=data.get("port", 0),
                        protocol=data.get("protocol", "tcp"),
                        state="open",
                        scanner="naabu"
                    ))
                except json.JSONDecodeError:
                    pass
        return results
    
    def parse_masscan_output(self, output: str) -> List[PortResult]:
        """Parse Masscan JSON output from string."""
        results = []
        try:
            data = json.loads(output)
            for entry in data:
                ip = entry.get("ip", "")
                for port_info in entry.get("ports", []):
                    results.append(PortResult(
                        host=ip,
                        ip=ip,
                        port=port_info.get("port", 0),
                        protocol=port_info.get("proto", "tcp"),
                        state=port_info.get("status", "open"),
                        scanner="masscan"
                    ))
        except json.JSONDecodeError:
            pass
        return results
    
    def parse_nmap_output(self, xml_content: str) -> List[PortResult]:
        """Parse Nmap XML output from string."""
        results = []
        try:
            root = ET.fromstring(xml_content)
            
            for host in root.findall(".//host"):
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find("address[@addrtype='ipv6']")
                if addr_elem is None:
                    continue
                
                ip = addr_elem.get("addr", "")
                hostname = ip
                
                hostnames = host.find("hostnames")
                if hostnames is not None:
                    hostname_elem = hostnames.find("hostname")
                    if hostname_elem is not None:
                        hostname = hostname_elem.get("name", ip)
                
                ports = host.find("ports")
                if ports is None:
                    continue
                
                for port in ports.findall("port"):
                    state_elem = port.find("state")
                    service_elem = port.find("service")
                    
                    results.append(PortResult(
                        host=hostname,
                        ip=ip,
                        port=int(port.get("portid", 0)),
                        protocol=port.get("protocol", "tcp"),
                        state=state_elem.get("state", "unknown") if state_elem is not None else "unknown",
                        service_name=service_elem.get("name") if service_elem is not None else None,
                        service_product=service_elem.get("product") if service_elem is not None else None,
                        service_version=service_elem.get("version") if service_elem is not None else None,
                        reason=state_elem.get("reason", "") if state_elem is not None else "",
                        scanner="nmap"
                    ))
        except ET.ParseError:
            pass
        return results
    
    # ==================== SYNC WRAPPERS ====================
    
    def scan_sync(self, targets: List[str], scanner: ScannerType = ScannerType.NAABU, **kwargs) -> ScanResult:
        """Synchronous wrapper for scan."""
        return asyncio.run(self.scan(targets, scanner, **kwargs))

















