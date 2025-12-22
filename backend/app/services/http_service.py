"""HTTP service for web asset probing and analysis."""

import asyncio
import logging
import ssl
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


@dataclass
class HTTPProbeResult:
    """Result of HTTP probe."""
    url: str
    is_alive: bool = False
    status_code: Optional[int] = None
    title: Optional[str] = None
    headers: dict = field(default_factory=dict)
    redirect_url: Optional[str] = None
    response_time_ms: Optional[float] = None
    content_length: Optional[int] = None
    server: Optional[str] = None
    technologies_hints: list[str] = field(default_factory=list)


@dataclass
class SSLInfo:
    """SSL/TLS certificate information."""
    is_valid: bool = False
    issuer: Optional[str] = None
    subject: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    serial_number: Optional[str] = None
    version: Optional[int] = None
    san: list[str] = field(default_factory=list)  # Subject Alternative Names
    signature_algorithm: Optional[str] = None
    error: Optional[str] = None


class HTTPService:
    """Service for HTTP probing and web analysis."""
    
    def __init__(
        self,
        timeout: float = 10.0,
        max_concurrent: int = 20,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    ):
        """
        Initialize HTTP service.
        
        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
            user_agent: User agent string for requests
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
    
    async def probe_url(self, url: str) -> HTTPProbeResult:
        """
        Probe a URL for HTTP response.
        
        Args:
            url: URL to probe
            
        Returns:
            HTTPProbeResult with response details
        """
        result = HTTPProbeResult(url=url)
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False  # Allow self-signed certs for discovery
            ) as client:
                start_time = asyncio.get_event_loop().time()
                
                response = await client.get(
                    url,
                    headers={"User-Agent": self.user_agent}
                )
                
                end_time = asyncio.get_event_loop().time()
                
                result.is_alive = True
                result.status_code = response.status_code
                result.headers = dict(response.headers)
                result.response_time_ms = (end_time - start_time) * 1000
                result.content_length = len(response.content)
                
                # Check for redirect
                if response.history:
                    result.redirect_url = str(response.url)
                
                # Extract server header
                result.server = response.headers.get("server")
                
                # Extract title from HTML
                if "text/html" in response.headers.get("content-type", ""):
                    result.title = self._extract_title(response.text)
                
                # Extract technology hints from headers
                result.technologies_hints = self._extract_tech_hints(response.headers)
                
        except httpx.ConnectTimeout:
            logger.debug(f"Connection timeout for {url}")
        except httpx.ConnectError as e:
            logger.debug(f"Connection error for {url}: {e}")
        except Exception as e:
            logger.debug(f"Error probing {url}: {e}")
        
        return result
    
    async def probe_host(self, host: str) -> list[HTTPProbeResult]:
        """
        Probe a host on common HTTP/HTTPS ports.
        
        Args:
            host: Hostname or IP to probe
            
        Returns:
            List of HTTPProbeResults for each successful probe
        """
        urls = [
            f"https://{host}",
            f"http://{host}",
            f"https://{host}:8443",
            f"http://{host}:8080",
            f"http://{host}:8000",
            f"http://{host}:3000",
        ]
        
        results = []
        for url in urls:
            result = await self.probe_url(url)
            if result.is_alive:
                results.append(result)
        
        return results
    
    async def probe_hosts(
        self,
        hosts: list[str],
        include_http: bool = True,
        include_https: bool = True
    ) -> list[HTTPProbeResult]:
        """
        Probe multiple hosts concurrently.
        
        Args:
            hosts: List of hostnames/IPs to probe
            include_http: Include HTTP probes
            include_https: Include HTTPS probes
            
        Returns:
            List of successful probe results
        """
        urls = []
        for host in hosts:
            if include_https:
                urls.append(f"https://{host}")
            if include_http:
                urls.append(f"http://{host}")
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def probe_with_limit(url: str):
            async with semaphore:
                return await self.probe_url(url)
        
        tasks = [probe_with_limit(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return [r for r in results if isinstance(r, HTTPProbeResult) and r.is_alive]
    
    async def get_ssl_info(self, host: str, port: int = 443) -> SSLInfo:
        """
        Get SSL/TLS certificate information.
        
        Args:
            host: Hostname to check
            port: Port number (default 443)
            
        Returns:
            SSLInfo with certificate details
        """
        info = SSLInfo()
        
        try:
            # Create SSL context that doesn't verify (for info gathering)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            loop = asyncio.get_event_loop()
            
            def get_cert():
                import socket
                with socket.create_connection((host, port), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        return ssock.getpeercert(binary_form=True)
            
            cert_der = await loop.run_in_executor(None, get_cert)
            
            # Parse certificate
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            info.is_valid = True
            info.subject = cert.subject.rfc4514_string()
            info.issuer = cert.issuer.rfc4514_string()
            info.not_before = cert.not_valid_before_utc
            info.not_after = cert.not_valid_after_utc
            info.serial_number = format(cert.serial_number, 'x')
            info.version = cert.version.value
            
            # Calculate days until expiry
            now = datetime.utcnow()
            if cert.not_valid_after_utc.replace(tzinfo=None) > now:
                info.days_until_expiry = (cert.not_valid_after_utc.replace(tzinfo=None) - now).days
            else:
                info.days_until_expiry = 0
            
            # Get signature algorithm
            info.signature_algorithm = cert.signature_algorithm_oid._name
            
            # Get Subject Alternative Names
            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                info.san = [str(name.value) for name in san_ext.value]
            except x509.ExtensionNotFound:
                pass
            
        except Exception as e:
            info.error = str(e)
            logger.debug(f"SSL info error for {host}:{port}: {e}")
        
        return info
    
    def _extract_title(self, html: str) -> Optional[str]:
        """Extract title from HTML."""
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, 'lxml')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.get_text().strip()[:500]  # Limit length
        except Exception:
            pass
        return None
    
    def _extract_tech_hints(self, headers: httpx.Headers) -> list[str]:
        """Extract technology hints from HTTP headers."""
        hints = []
        
        # Server header
        server = headers.get("server", "")
        if server:
            hints.append(f"Server: {server}")
        
        # X-Powered-By
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            hints.append(f"X-Powered-By: {powered_by}")
        
        # X-AspNet-Version
        aspnet = headers.get("x-aspnet-version", "")
        if aspnet:
            hints.append(f"ASP.NET: {aspnet}")
        
        # X-Generator
        generator = headers.get("x-generator", "")
        if generator:
            hints.append(f"Generator: {generator}")
        
        return hints
















