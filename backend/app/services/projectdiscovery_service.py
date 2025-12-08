"""
ProjectDiscovery tools integration service.

Integrates with ProjectDiscovery's suite of security tools:
- subfinder: Subdomain discovery
- httpx: HTTP probing toolkit  
- dnsx: DNS toolkit
- naabu: Port scanner
- katana: Web crawler

Reference: https://github.com/projectdiscovery
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

logger = logging.getLogger(__name__)


@dataclass
class SubfinderResult:
    """Result from subfinder scan."""
    subdomains: list[str] = field(default_factory=list)
    sources: dict = field(default_factory=dict)  # subdomain -> source


@dataclass
class HttpxResult:
    """Result from httpx probe."""
    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    webserver: Optional[str] = None
    technologies: list[str] = field(default_factory=list)
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    cname: Optional[str] = None
    cdn: Optional[str] = None
    response_time: Optional[str] = None
    tls_version: Optional[str] = None
    tls_cipher: Optional[str] = None
    hash_body: Optional[str] = None
    
    @classmethod
    def from_json(cls, data: dict) -> "HttpxResult":
        """Create HttpxResult from httpx JSON output."""
        return cls(
            url=data.get("url", ""),
            status_code=data.get("status_code") or data.get("status-code"),
            title=data.get("title", ""),
            webserver=data.get("webserver", ""),
            technologies=data.get("tech", []) or data.get("technologies", []),
            content_length=data.get("content_length") or data.get("content-length"),
            content_type=data.get("content_type") or data.get("content-type"),
            host=data.get("host", ""),
            ip=data.get("a", [""])[0] if data.get("a") else data.get("ip", ""),
            cname=data.get("cname", [""])[0] if data.get("cname") else "",
            cdn=data.get("cdn_name") or data.get("cdn-name", ""),
            response_time=data.get("time", ""),
            tls_version=data.get("tls", {}).get("version", "") if isinstance(data.get("tls"), dict) else "",
            tls_cipher=data.get("tls", {}).get("cipher", "") if isinstance(data.get("tls"), dict) else "",
            hash_body=data.get("body_sha256") or data.get("body-sha256", ""),
        )


@dataclass
class DnsxResult:
    """Result from dnsx scan."""
    host: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    soa_records: list[str] = field(default_factory=list)
    ptr_records: list[str] = field(default_factory=list)
    
    @classmethod
    def from_json(cls, data: dict) -> "DnsxResult":
        """Create DnsxResult from dnsx JSON output."""
        return cls(
            host=data.get("host", ""),
            a_records=data.get("a", []),
            aaaa_records=data.get("aaaa", []),
            cname_records=data.get("cname", []),
            mx_records=data.get("mx", []),
            ns_records=data.get("ns", []),
            txt_records=data.get("txt", []),
            soa_records=data.get("soa", []),
            ptr_records=data.get("ptr", []),
        )


@dataclass
class NaabuResult:
    """Result from naabu port scan."""
    host: str
    ip: str
    port: int
    protocol: str = "tcp"


@dataclass
class KatanaResult:
    """Result from katana web crawler."""
    url: str
    method: str = "GET"
    source: Optional[str] = None  # js, form, etc.
    tag: Optional[str] = None
    attribute: Optional[str] = None


class ProjectDiscoveryService:
    """
    Service for running ProjectDiscovery tools.
    
    This service wraps the CLI tools from ProjectDiscovery's suite:
    - subfinder: Fast passive subdomain enumeration
    - httpx: Fast and multi-purpose HTTP toolkit
    - dnsx: Fast and multi-purpose DNS toolkit
    - naabu: Fast port scanner
    - katana: A next-generation crawling and spidering framework
    
    Reference: https://github.com/projectdiscovery
    """
    
    def __init__(
        self,
        subfinder_path: str = "subfinder",
        httpx_path: str = "httpx",
        dnsx_path: str = "dnsx",
        naabu_path: str = "naabu",
        katana_path: str = "katana"
    ):
        """
        Initialize ProjectDiscovery service.
        
        Args:
            subfinder_path: Path to subfinder binary
            httpx_path: Path to httpx binary
            dnsx_path: Path to dnsx binary
            naabu_path: Path to naabu binary
            katana_path: Path to katana binary
        """
        self.subfinder_path = subfinder_path
        self.httpx_path = httpx_path
        self.dnsx_path = dnsx_path
        self.naabu_path = naabu_path
        self.katana_path = katana_path
    
    def check_tools(self) -> dict[str, bool]:
        """Check which tools are installed."""
        tools = {
            "subfinder": self.subfinder_path,
            "httpx": self.httpx_path,
            "dnsx": self.dnsx_path,
            "naabu": self.naabu_path,
            "katana": self.katana_path,
        }
        
        status = {}
        for name, path in tools.items():
            try:
                result = subprocess.run(
                    [path, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                status[name] = result.returncode == 0
            except (subprocess.SubprocessError, FileNotFoundError):
                status[name] = False
        
        return status
    
    # ==================== SUBFINDER ====================
    
    async def run_subfinder(
        self,
        domain: str,
        sources: Optional[list[str]] = None,
        recursive: bool = False,
        timeout: int = 30,
        rate_limit: int = 0
    ) -> SubfinderResult:
        """
        Run subfinder for subdomain enumeration.
        
        Args:
            domain: Target domain
            sources: Specific sources to use (default: all)
            recursive: Enable recursive subdomain enumeration
            timeout: Timeout in seconds
            rate_limit: Rate limit for requests
            
        Returns:
            SubfinderResult with discovered subdomains
        """
        result = SubfinderResult()
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.subfinder_path,
                "-d", domain,
                "-json",
                "-o", output_path,
                "-silent",
                "-timeout", str(timeout),
            ]
            
            if sources:
                cmd.extend(["-sources", ",".join(sources)])
            
            if recursive:
                cmd.append("-recursive")
            
            if rate_limit > 0:
                cmd.extend(["-rate-limit", str(rate_limit)])
            
            logger.info(f"Running subfinder for {domain}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                subdomain = data.get("host", "")
                                source = data.get("source", "unknown")
                                if subdomain:
                                    result.subdomains.append(subdomain)
                                    result.sources[subdomain] = source
                            except json.JSONDecodeError:
                                # Plain text output
                                result.subdomains.append(line)
            
            logger.info(f"Subfinder found {len(result.subdomains)} subdomains for {domain}")
            
        except Exception as e:
            logger.error(f"Subfinder failed: {e}")
            
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)
        
        return result
    
    # ==================== HTTPX ====================
    
    async def run_httpx(
        self,
        targets: list[str],
        ports: Optional[list[int]] = None,
        threads: int = 50,
        timeout: int = 10,
        follow_redirects: bool = True,
        tech_detect: bool = True,
        status_code: bool = True,
        title: bool = True,
        web_server: bool = True,
        ip: bool = True,
        cname: bool = True,
        cdn: bool = True
    ) -> list[HttpxResult]:
        """
        Run httpx for HTTP probing.
        
        Args:
            targets: List of targets (domains, IPs, URLs)
            ports: Specific ports to probe
            threads: Number of threads
            timeout: Request timeout
            follow_redirects: Follow HTTP redirects
            tech_detect: Enable technology detection
            status_code: Include status code
            title: Include page title
            web_server: Include web server header
            ip: Include IP address
            cname: Include CNAME records
            cdn: Detect CDN
            
        Returns:
            List of HttpxResult objects
        """
        results = []
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.httpx_path,
                "-l", targets_path,
                "-json",
                "-o", output_path,
                "-silent",
                "-threads", str(threads),
                "-timeout", str(timeout),
            ]
            
            if ports:
                cmd.extend(["-ports", ",".join(map(str, ports))])
            
            if follow_redirects:
                cmd.append("-follow-redirects")
            
            if tech_detect:
                cmd.append("-tech-detect")
            
            if status_code:
                cmd.append("-status-code")
            
            if title:
                cmd.append("-title")
            
            if web_server:
                cmd.append("-web-server")
            
            if ip:
                cmd.append("-ip")
            
            if cname:
                cmd.append("-cname")
            
            if cdn:
                cmd.append("-cdn")
            
            logger.info(f"Running httpx on {len(targets)} targets")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                results.append(HttpxResult.from_json(data))
                            except json.JSONDecodeError:
                                pass
            
            logger.info(f"httpx found {len(results)} live hosts")
            
        except Exception as e:
            logger.error(f"httpx failed: {e}")
            
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
        
        return results
    
    # ==================== DNSX ====================
    
    async def run_dnsx(
        self,
        targets: list[str],
        record_types: Optional[list[str]] = None,
        threads: int = 100,
        retry: int = 2,
        resolvers: Optional[list[str]] = None
    ) -> list[DnsxResult]:
        """
        Run dnsx for DNS enumeration.
        
        Args:
            targets: List of domains/hosts
            record_types: DNS record types to query (a, aaaa, cname, mx, ns, txt, soa, ptr)
            threads: Number of threads
            retry: Number of retries
            resolvers: Custom DNS resolvers
            
        Returns:
            List of DnsxResult objects
        """
        results = []
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.dnsx_path,
                "-l", targets_path,
                "-json",
                "-o", output_path,
                "-silent",
                "-threads", str(threads),
                "-retry", str(retry),
            ]
            
            # Add record types
            if record_types:
                for rt in record_types:
                    cmd.append(f"-{rt.lower()}")
            else:
                # Default: all common record types
                cmd.extend(["-a", "-aaaa", "-cname", "-mx", "-ns", "-txt"])
            
            if resolvers:
                cmd.extend(["-resolver", ",".join(resolvers)])
            
            logger.info(f"Running dnsx on {len(targets)} targets")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                results.append(DnsxResult.from_json(data))
                            except json.JSONDecodeError:
                                pass
            
            logger.info(f"dnsx resolved {len(results)} hosts")
            
        except Exception as e:
            logger.error(f"dnsx failed: {e}")
            
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
        
        return results
    
    # ==================== NAABU ====================
    
    async def run_naabu(
        self,
        targets: list[str],
        ports: Optional[str] = None,
        top_ports: int = 100,
        rate: int = 1000,
        timeout: int = 10,
        retries: int = 1
    ) -> list[NaabuResult]:
        """
        Run naabu for port scanning.
        
        Args:
            targets: List of targets (IPs, domains, CIDRs)
            ports: Port specification (e.g., "80,443,8080" or "1-1000")
            top_ports: Scan top N ports (if ports not specified)
            rate: Packets per second rate
            timeout: Timeout in seconds
            retries: Number of retries
            
        Returns:
            List of NaabuResult objects
        """
        results = []
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.naabu_path,
                "-l", targets_path,
                "-json",
                "-o", output_path,
                "-silent",
                "-rate", str(rate),
                "-timeout", str(timeout),
                "-retries", str(retries),
            ]
            
            if ports:
                cmd.extend(["-p", ports])
            else:
                cmd.extend(["-top-ports", str(top_ports)])
            
            logger.info(f"Running naabu on {len(targets)} targets")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                results.append(NaabuResult(
                                    host=data.get("host", ""),
                                    ip=data.get("ip", ""),
                                    port=data.get("port", 0),
                                    protocol=data.get("protocol", "tcp"),
                                ))
                            except json.JSONDecodeError:
                                pass
            
            logger.info(f"naabu found {len(results)} open ports")
            
        except Exception as e:
            logger.error(f"naabu failed: {e}")
            
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
        
        return results
    
    # ==================== KATANA ====================
    
    async def run_katana(
        self,
        targets: list[str],
        depth: int = 2,
        js_crawl: bool = True,
        timeout: int = 10,
        concurrency: int = 10,
        parallelism: int = 10,
        form_fill: bool = False
    ) -> list[KatanaResult]:
        """
        Run katana for web crawling.
        
        Args:
            targets: List of target URLs
            depth: Crawl depth
            js_crawl: Enable JavaScript crawling
            timeout: Request timeout
            concurrency: Number of concurrent fetchers
            parallelism: Number of parallel workers
            form_fill: Fill forms during crawling
            
        Returns:
            List of KatanaResult objects
        """
        results = []
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write("\n".join(targets))
            targets_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                self.katana_path,
                "-list", targets_path,
                "-json",
                "-o", output_path,
                "-silent",
                "-depth", str(depth),
                "-timeout", str(timeout),
                "-concurrency", str(concurrency),
                "-parallelism", str(parallelism),
            ]
            
            if js_crawl:
                cmd.append("-js-crawl")
            
            if form_fill:
                cmd.append("-form-fill")
            
            logger.info(f"Running katana on {len(targets)} targets")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            # Parse results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                results.append(KatanaResult(
                                    url=data.get("request", {}).get("endpoint", ""),
                                    method=data.get("request", {}).get("method", "GET"),
                                    source=data.get("request", {}).get("source", ""),
                                    tag=data.get("request", {}).get("tag", ""),
                                    attribute=data.get("request", {}).get("attribute", ""),
                                ))
                            except json.JSONDecodeError:
                                pass
            
            logger.info(f"katana found {len(results)} URLs")
            
        except Exception as e:
            logger.error(f"katana failed: {e}")
            
        finally:
            for path in [targets_path, output_path]:
                if os.path.exists(path):
                    os.unlink(path)
        
        return results
    
    # ==================== SYNC WRAPPERS ====================
    
    def run_subfinder_sync(self, domain: str, **kwargs) -> SubfinderResult:
        """Synchronous wrapper for run_subfinder."""
        return asyncio.run(self.run_subfinder(domain, **kwargs))
    
    def run_httpx_sync(self, targets: list[str], **kwargs) -> list[HttpxResult]:
        """Synchronous wrapper for run_httpx."""
        return asyncio.run(self.run_httpx(targets, **kwargs))
    
    def run_dnsx_sync(self, targets: list[str], **kwargs) -> list[DnsxResult]:
        """Synchronous wrapper for run_dnsx."""
        return asyncio.run(self.run_dnsx(targets, **kwargs))
    
    def run_naabu_sync(self, targets: list[str], **kwargs) -> list[NaabuResult]:
        """Synchronous wrapper for run_naabu."""
        return asyncio.run(self.run_naabu(targets, **kwargs))
    
    def run_katana_sync(self, targets: list[str], **kwargs) -> list[KatanaResult]:
        """Synchronous wrapper for run_katana."""
        return asyncio.run(self.run_katana(targets, **kwargs))






