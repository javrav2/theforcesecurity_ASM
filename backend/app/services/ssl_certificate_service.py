"""
SSL Certificate extraction service.

Extracts SSL/TLS certificates from IP addresses and domains to discover:
- Hosted domains (from CN and SANs)
- Certificate details (issuer, expiry, etc.)
- Related infrastructure

This helps with:
- Finding domains hosted on IP addresses
- Discovering subdomains from certificate SANs
- Identifying certificate misconfigurations
"""

import asyncio
import json
import logging
import ssl
import socket
import subprocess
import tempfile
import os
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    """SSL Certificate information."""
    ip: str
    port: int = 443
    common_name: Optional[str] = None
    subject_alt_names: List[str] = field(default_factory=list)
    issuer: Optional[str] = None
    issuer_org: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    serial_number: Optional[str] = None
    signature_algorithm: Optional[str] = None
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False
    domains_found: List[str] = field(default_factory=list)
    raw_subject: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "ip": self.ip,
            "port": self.port,
            "common_name": self.common_name,
            "subject_alt_names": self.subject_alt_names,
            "issuer": self.issuer,
            "issuer_org": self.issuer_org,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "serial_number": self.serial_number,
            "signature_algorithm": self.signature_algorithm,
            "is_self_signed": self.is_self_signed,
            "is_expired": self.is_expired,
            "is_wildcard": self.is_wildcard,
            "domains_found": self.domains_found,
            "error": self.error,
        }


class SSLCertificateService:
    """Service for extracting SSL certificates from hosts."""
    
    def __init__(self, timeout: int = 10, max_workers: int = 20):
        """
        Initialize the SSL certificate service.
        
        Args:
            timeout: Connection timeout in seconds
            max_workers: Max concurrent connections
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.tlsx_path = "tlsx"  # ProjectDiscovery's TLS scanner
    
    def extract_certificate(self, host: str, port: int = 443) -> CertificateInfo:
        """
        Extract SSL certificate from a host.
        
        Args:
            host: IP address or hostname
            port: Port to connect to (default 443)
            
        Returns:
            CertificateInfo object with certificate details
        """
        result = CertificateInfo(ip=host, port=port)
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # We want to get the cert even if invalid
            
            # Connect and get certificate
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_binary = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        # Extract subject
                        subject = dict(x[0] for x in cert.get('subject', []))
                        result.common_name = subject.get('commonName', '')
                        result.raw_subject = str(cert.get('subject', ''))
                        
                        # Extract issuer
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        result.issuer = issuer.get('commonName', '')
                        result.issuer_org = issuer.get('organizationName', '')
                        
                        # Check if self-signed
                        result.is_self_signed = (subject == issuer)
                        
                        # Extract SANs
                        for san_type, san_value in cert.get('subjectAltName', []):
                            if san_type == 'DNS':
                                result.subject_alt_names.append(san_value)
                        
                        # Parse dates
                        if cert.get('notBefore'):
                            try:
                                result.not_before = datetime.strptime(
                                    cert['notBefore'], '%b %d %H:%M:%S %Y %Z'
                                )
                            except ValueError:
                                pass
                        
                        if cert.get('notAfter'):
                            try:
                                result.not_after = datetime.strptime(
                                    cert['notAfter'], '%b %d %H:%M:%S %Y %Z'
                                )
                                result.is_expired = result.not_after < datetime.utcnow()
                            except ValueError:
                                pass
                        
                        # Serial number
                        result.serial_number = str(cert.get('serialNumber', ''))
                        
                        # Collect all domains found
                        domains = set()
                        if result.common_name:
                            domains.add(result.common_name)
                            if result.common_name.startswith('*.'):
                                result.is_wildcard = True
                        
                        for san in result.subject_alt_names:
                            domains.add(san)
                            if san.startswith('*.'):
                                result.is_wildcard = True
                        
                        result.domains_found = sorted(list(domains))
                    
        except ssl.SSLError as e:
            result.error = f"SSL Error: {str(e)}"
        except socket.timeout:
            result.error = "Connection timeout"
        except socket.error as e:
            result.error = f"Socket error: {str(e)}"
        except Exception as e:
            result.error = f"Error: {str(e)}"
        
        return result
    
    async def extract_certificates_async(
        self, 
        hosts: List[str], 
        port: int = 443,
        progress_callback: Optional[callable] = None
    ) -> List[CertificateInfo]:
        """
        Extract certificates from multiple hosts concurrently.
        
        Args:
            hosts: List of IP addresses or hostnames
            port: Port to connect to
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of CertificateInfo objects
        """
        results = []
        total = len(hosts)
        completed = 0
        
        def extract_with_progress(host: str) -> CertificateInfo:
            nonlocal completed
            result = self.extract_certificate(host, port)
            completed += 1
            if progress_callback:
                progress_callback(completed, total, host)
            return result
        
        # Use thread pool for concurrent extraction
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [
                loop.run_in_executor(executor, extract_with_progress, host)
                for host in hosts
            ]
            results = await asyncio.gather(*futures)
        
        return results
    
    def extract_certificates_sync(
        self, 
        hosts: List[str], 
        port: int = 443
    ) -> List[CertificateInfo]:
        """Synchronous wrapper for extract_certificates_async."""
        return asyncio.run(self.extract_certificates_async(hosts, port))
    
    async def scan_with_tlsx(
        self,
        hosts: List[str],
        ports: List[int] = None,
        san: bool = True,
        cn: bool = True,
        so: bool = True,  # Subject organization
        expired: bool = True,
        self_signed: bool = True,
        mismatched: bool = True
    ) -> List[CertificateInfo]:
        """
        Use ProjectDiscovery's tlsx for faster SSL scanning.
        
        Args:
            hosts: List of hosts to scan
            ports: Ports to scan (default: 443)
            san: Extract Subject Alternative Names
            cn: Extract Common Name
            so: Extract Subject Organization
            expired: Check for expired certificates
            self_signed: Check for self-signed certificates
            mismatched: Check for hostname mismatches
            
        Returns:
            List of CertificateInfo objects
        """
        if not ports:
            ports = [443]
        
        results = []
        
        # Write hosts to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('\n'.join(hosts))
            hosts_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        
        try:
            cmd = [
                self.tlsx_path,
                "-l", hosts_file,
                "-json",
                "-o", output_file,
                "-silent",
                "-p", ",".join(map(str, ports)),
            ]
            
            if san:
                cmd.append("-san")
            if cn:
                cmd.append("-cn")
            if so:
                cmd.append("-so")
            if expired:
                cmd.append("-expired")
            if self_signed:
                cmd.append("-self-signed")
            if mismatched:
                cmd.append("-mismatched")
            
            logger.info(f"Running tlsx on {len(hosts)} hosts")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.warning(f"tlsx returned {process.returncode}: {stderr.decode()}")
            
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                cert_info = CertificateInfo(
                                    ip=data.get('host', data.get('ip', '')),
                                    port=data.get('port', 443),
                                    common_name=data.get('subject_cn', ''),
                                    subject_alt_names=data.get('subject_an', []),
                                    issuer=data.get('issuer_cn', ''),
                                    issuer_org=data.get('issuer_org', ''),
                                    is_expired=data.get('expired', False),
                                    is_self_signed=data.get('self_signed', False),
                                    is_wildcard=data.get('wildcard', False),
                                )
                                
                                # Collect all domains
                                domains = set()
                                if cert_info.common_name:
                                    domains.add(cert_info.common_name)
                                for san in cert_info.subject_alt_names:
                                    domains.add(san)
                                cert_info.domains_found = sorted(list(domains))
                                
                                results.append(cert_info)
                                
                            except json.JSONDecodeError:
                                continue
            
        except FileNotFoundError:
            logger.warning("tlsx not found, falling back to Python SSL extraction")
            results = await self.extract_certificates_async(hosts, ports[0] if ports else 443)
        
        finally:
            for path in [hosts_file, output_file]:
                if os.path.exists(path):
                    os.unlink(path)
        
        logger.info(f"SSL scan complete: {len(results)} certificates extracted")
        return results
    
    def discover_domains_from_ips(
        self,
        ips: List[str],
        ports: List[int] = None
    ) -> Dict[str, List[str]]:
        """
        Discover domains hosted on IP addresses by extracting SSL certificates.
        
        Args:
            ips: List of IP addresses
            ports: Ports to check (default: 443, 8443)
            
        Returns:
            Dictionary mapping IP -> list of domains found
        """
        if not ports:
            ports = [443, 8443]
        
        ip_to_domains = {}
        
        for ip in ips:
            domains = set()
            
            for port in ports:
                cert = self.extract_certificate(ip, port)
                if not cert.error:
                    for domain in cert.domains_found:
                        # Skip wildcard domains (they're patterns, not real domains)
                        if not domain.startswith('*.'):
                            domains.add(domain)
            
            if domains:
                ip_to_domains[ip] = sorted(list(domains))
        
        return ip_to_domains


# Singleton instance
_ssl_service = None

def get_ssl_certificate_service() -> SSLCertificateService:
    """Get or create the SSL certificate service singleton."""
    global _ssl_service
    if _ssl_service is None:
        _ssl_service = SSLCertificateService()
    return _ssl_service

