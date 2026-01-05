"""
ffuf Service for web fuzzing and endpoint discovery.

ffuf (Fuzz Faster U Fool) is a fast web fuzzer written in Go that can be used
for directory/file discovery, vhost discovery, and parameter fuzzing.

Installation: go install github.com/ffuf/ffuf/v2@latest
GitHub: https://github.com/ffuf/ffuf
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)

# Common wordlists bundled with SecLists or custom
DEFAULT_WORDLIST_PATHS = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/app/wordlists/common-endpoints.txt",
]

# Built-in minimal wordlist for quick scans
QUICK_WORDLIST = [
    "admin", "administrator", "api", "app", "assets", "auth", "backup",
    "bin", "cache", "cgi-bin", "config", "console", "css", "dashboard",
    "data", "db", "debug", "dev", "docs", "download", "downloads",
    "error", "files", "fonts", "graphql", "health", "healthcheck", "help",
    "home", "images", "img", "include", "index", "info", "js", "json",
    "lib", "log", "login", "logout", "logs", "mail", "media", "metrics",
    "mobile", "new", "old", "panel", "php", "portal", "private", "public",
    "register", "reset", "robots.txt", "rss", "search", "secure", "server",
    "server-status", "service", "services", "settings", "setup", "signin",
    "signout", "signup", "sitemap", "sitemap.xml", "static", "stats",
    "status", "storage", "swagger", "swagger-ui", "swagger.json", "system",
    "temp", "test", "tmp", "upload", "uploads", "user", "users", "v1", "v2",
    "vendor", "version", "web", "webmail", "wp-admin", "wp-content", "wp-includes",
    "wp-json", "xml", ".env", ".git", ".git/config", ".htaccess", ".svn",
    "api/v1", "api/v2", "api/docs", "api/swagger", "api/health",
    "actuator", "actuator/health", "actuator/info", "actuator/env",
    "graphql/playground", ".well-known/security.txt", "openapi.json",
]


@dataclass
class FfufResult:
    """Result from a single ffuf match."""
    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: Optional[str] = None
    redirect_location: Optional[str] = None
    input_value: str = ""  # The FUZZ value that matched


@dataclass
class FfufScanResult:
    """Complete result from ffuf scan."""
    target: str
    results: List[FfufResult] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    status_codes: Dict[int, int] = field(default_factory=dict)
    success: bool = False
    error: Optional[str] = None
    elapsed_time: float = 0.0
    words_tested: int = 0


def _check_ffuf_available() -> bool:
    """Check if ffuf is installed."""
    return shutil.which("ffuf") is not None


def _get_wordlist_path() -> Optional[str]:
    """Find an available wordlist."""
    for path in DEFAULT_WORDLIST_PATHS:
        if os.path.exists(path):
            return path
    return None


class FfufService:
    """
    Service for web fuzzing using ffuf.
    
    Supports:
    - Directory/file discovery
    - Endpoint enumeration
    - VHost discovery
    - Parameter fuzzing
    """
    
    def __init__(
        self,
        wordlist_path: Optional[str] = None,
        threads: int = 40,
        rate_limit: int = 0,  # 0 = no limit
    ):
        """
        Initialize ffuf service.
        
        Args:
            wordlist_path: Path to wordlist file
            threads: Number of concurrent threads
            rate_limit: Requests per second (0 = unlimited)
        """
        self.ffuf_path = shutil.which("ffuf")
        self.wordlist_path = wordlist_path or _get_wordlist_path()
        self.threads = threads
        self.rate_limit = rate_limit
        self._temp_wordlist = None
        
    def is_available(self) -> bool:
        """Check if ffuf is available."""
        return self.ffuf_path is not None
    
    def _create_quick_wordlist(self) -> str:
        """Create a temporary wordlist with common endpoints."""
        fd, path = tempfile.mkstemp(suffix=".txt", prefix="ffuf_wordlist_")
        with os.fdopen(fd, 'w') as f:
            f.write('\n'.join(QUICK_WORDLIST))
        self._temp_wordlist = path
        return path
    
    async def scan_directory(
        self,
        url: str,
        wordlist: Optional[str] = None,
        extensions: Optional[List[str]] = None,
        match_codes: Optional[List[int]] = None,
        filter_codes: Optional[List[int]] = None,
        filter_size: Optional[int] = None,
        follow_redirects: bool = True,
        timeout: int = 300,
        use_quick_wordlist: bool = False,
    ) -> FfufScanResult:
        """
        Run ffuf directory/file discovery scan.
        
        Args:
            url: Target URL with FUZZ keyword (e.g., https://example.com/FUZZ)
            wordlist: Path to wordlist file
            extensions: File extensions to append (e.g., ["php", "html"])
            match_codes: HTTP status codes to match (default: 200-299,301,302,307,401,403,405)
            filter_codes: HTTP status codes to filter out
            filter_size: Filter responses by size
            follow_redirects: Follow HTTP redirects
            timeout: Command timeout in seconds
            use_quick_wordlist: Use built-in quick wordlist if no wordlist provided
            
        Returns:
            FfufScanResult with discovered endpoints
        """
        result = FfufScanResult(target=url)
        start_time = datetime.utcnow()
        
        if not self.is_available():
            result.error = "ffuf not installed. Run: go install github.com/ffuf/ffuf/v2@latest"
            return result
        
        # Ensure URL has FUZZ keyword
        if "FUZZ" not in url:
            url = url.rstrip('/') + "/FUZZ"
        
        # Get wordlist
        wl_path = wordlist or self.wordlist_path
        if not wl_path:
            if use_quick_wordlist:
                wl_path = self._create_quick_wordlist()
            else:
                result.error = "No wordlist available. Set wordlist_path or use use_quick_wordlist=True"
                return result
        
        if not os.path.exists(wl_path):
            result.error = f"Wordlist not found: {wl_path}"
            return result
        
        # Create output file
        output_file = tempfile.mktemp(suffix=".json", prefix="ffuf_")
        
        try:
            # Build command
            cmd = [
                self.ffuf_path,
                "-u", url,
                "-w", wl_path,
                "-o", output_file,
                "-of", "json",
                "-t", str(self.threads),
                "-timeout", "10",
                "-ac",  # Auto-calibrate filtering
                "-s",   # Silent mode
            ]
            
            if self.rate_limit > 0:
                cmd.extend(["-rate", str(self.rate_limit)])
            
            if extensions:
                cmd.extend(["-e", ",".join(extensions)])
            
            if match_codes:
                cmd.extend(["-mc", ",".join(str(c) for c in match_codes)])
            
            if filter_codes:
                cmd.extend(["-fc", ",".join(str(c) for c in filter_codes)])
            
            if filter_size is not None:
                cmd.extend(["-fs", str(filter_size)])
            
            if not follow_redirects:
                cmd.append("-r")
            
            logger.info(f"Running ffuf on {url}")
            
            # Run ffuf
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                result.error = f"ffuf timed out after {timeout}s"
                return result
            
            # Count words tested
            with open(wl_path, 'r') as f:
                result.words_tested = sum(1 for _ in f)
            
            # Parse JSON results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    try:
                        data = json.load(f)
                        
                        for item in data.get("results", []):
                            ffuf_result = FfufResult(
                                url=item.get("url", ""),
                                status=item.get("status", 0),
                                length=item.get("length", 0),
                                words=item.get("words", 0),
                                lines=item.get("lines", 0),
                                content_type=item.get("content-type"),
                                redirect_location=item.get("redirectlocation"),
                                input_value=item.get("input", {}).get("FUZZ", ""),
                            )
                            result.results.append(ffuf_result)
                            
                            # Track status codes
                            result.status_codes[ffuf_result.status] = \
                                result.status_codes.get(ffuf_result.status, 0) + 1
                            
                            # Extract endpoint path
                            if ffuf_result.url:
                                from urllib.parse import urlparse
                                parsed = urlparse(ffuf_result.url)
                                if parsed.path:
                                    result.endpoints.append(parsed.path)
                    except json.JSONDecodeError:
                        pass
            
            result.success = True
            logger.info(f"ffuf found {len(result.endpoints)} endpoints on {url}")
            
        except Exception as e:
            logger.error(f"ffuf error for {url}: {e}")
            result.error = str(e)
        finally:
            # Cleanup
            if os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except:
                    pass
            if self._temp_wordlist and os.path.exists(self._temp_wordlist):
                try:
                    os.remove(self._temp_wordlist)
                except:
                    pass
                self._temp_wordlist = None
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def scan_host(
        self,
        host: str,
        **kwargs
    ) -> FfufScanResult:
        """
        Scan a host for directories/endpoints.
        
        Args:
            host: Hostname or domain (e.g., example.com)
            **kwargs: Additional arguments for scan_directory
            
        Returns:
            FfufScanResult
        """
        # Try HTTPS first, then HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}/FUZZ"
            result = await self.scan_directory(url, **kwargs)
            if result.success and result.endpoints:
                return result
            if result.success:
                return result  # No endpoints but scan worked
        
        return result  # Return last result (even if failed)
    
    async def scan_multiple_hosts(
        self,
        hosts: List[str],
        max_concurrent: int = 5,
        **kwargs
    ) -> List[FfufScanResult]:
        """
        Scan multiple hosts concurrently.
        
        Args:
            hosts: List of hosts to scan
            max_concurrent: Maximum concurrent scans
            **kwargs: Additional arguments for scan_host
            
        Returns:
            List of FfufScanResult
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_limit(host: str) -> FfufScanResult:
            async with semaphore:
                return await self.scan_host(host, **kwargs)
        
        tasks = [scan_with_limit(h) for h in hosts]
        return await asyncio.gather(*tasks)


# Convenience function
async def discover_endpoints(host: str, use_quick_wordlist: bool = True) -> FfufScanResult:
    """Quick function to discover endpoints on a host."""
    service = FfufService()
    return await service.scan_host(host, use_quick_wordlist=use_quick_wordlist)

