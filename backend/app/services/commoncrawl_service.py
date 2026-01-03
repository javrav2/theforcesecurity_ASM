"""
Common Crawl Service for subdomain discovery.

Common Crawl maintains a massive web crawl archive. This service queries
the CC Index API to find subdomains and URLs for a given domain.

Two modes:
1. API Mode: Query CC Index Server API (slower but no setup)
2. Local Index Mode: Use pre-downloaded index for fast lookups (ASM Recon approach)

API Reference: https://index.commoncrawl.org/
"""

import asyncio
import logging
import os
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Common Crawl Index API endpoint
CC_INDEX_API = "https://index.commoncrawl.org/CC-MAIN-2024-10-index"  # Recent index


@dataclass
class CommonCrawlResult:
    """Result from Common Crawl lookup."""
    domain: str
    subdomains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    source: str = "commoncrawl"
    elapsed_time: float = 0.0
    error: Optional[str] = None


class CommonCrawlService:
    """
    Service for discovering subdomains from Common Crawl data.
    
    Usage:
        # API mode (no setup required)
        cc = CommonCrawlService()
        result = await cc.search_domain("rockwellautomation.com")
        
        # Local index mode (faster, requires pre-downloaded index)
        cc = CommonCrawlService(local_index_path="/data/commoncrawl/commoncrawl.txt")
        result = await cc.search_domain_local("rockwellautomation.com")
    """
    
    def __init__(
        self,
        index_api: str = CC_INDEX_API,
        local_index_path: Optional[str] = None,
        timeout: float = 60.0,
        max_results: int = 10000
    ):
        """
        Initialize Common Crawl service.
        
        Args:
            index_api: CC Index API endpoint (uses latest by default)
            local_index_path: Path to pre-downloaded local index file
            timeout: HTTP request timeout
            max_results: Maximum results to return from API
        """
        self.index_api = index_api
        self.local_index_path = local_index_path
        self.timeout = timeout
        self.max_results = max_results
    
    async def search_domain(self, domain: str) -> CommonCrawlResult:
        """
        Search Common Crawl for subdomains of a domain via the Index API.
        
        Example: search_domain("rockwellautomation.com") will find:
        - www.rockwellautomation.com
        - support.rockwellautomation.com
        - downloads.rockwellautomation.com
        - etc.
        
        Args:
            domain: Base domain to search (e.g., rockwellautomation.com)
            
        Returns:
            CommonCrawlResult with discovered subdomains
        """
        result = CommonCrawlResult(domain=domain)
        start_time = datetime.utcnow()
        
        try:
            # CC Index uses URL search - match any subdomain
            search_url = f"*.{domain}/*"
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.index_api,
                    params={
                        "url": search_url,
                        "output": "json",
                        "limit": self.max_results
                    }
                )
                
                if response.status_code != 200:
                    result.error = f"CC Index API returned {response.status_code}"
                    return result
                
                # Parse NDJSON response (one JSON object per line)
                subdomains: Set[str] = set()
                urls: Set[str] = set()
                
                for line in response.text.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        import json
                        record = json.loads(line)
                        url = record.get("url", "")
                        
                        if url:
                            parsed = urlparse(url)
                            hostname = parsed.netloc.lower()
                            
                            # Remove port if present
                            if ":" in hostname:
                                hostname = hostname.split(":")[0]
                            
                            # Verify it's a subdomain of our target
                            if hostname.endswith(f".{domain}") or hostname == domain:
                                if hostname != domain:
                                    subdomains.add(hostname)
                                urls.add(url)
                    except Exception:
                        continue
                
                result.subdomains = sorted(list(subdomains))
                result.urls = list(urls)[:1000]  # Limit URLs for response size
                
                logger.info(f"Common Crawl found {len(result.subdomains)} subdomains for {domain}")
                
        except httpx.TimeoutException:
            result.error = "Request timed out - Common Crawl API can be slow"
            logger.warning(f"Common Crawl timeout for {domain}")
        except Exception as e:
            result.error = str(e)
            logger.error(f"Common Crawl error for {domain}: {e}")
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def search_domain_local(self, domain: str) -> CommonCrawlResult:
        """
        Search for subdomains using pre-downloaded local index (ASM Recon approach).
        
        This is much faster for repeated queries but requires:
        1. Pre-downloaded CC domain index file
        2. File sorted with reversed domain parts (e.g., "com,rockwellautomation,www")
        3. `sgrep` tool installed for sorted file searching
        
        Args:
            domain: Base domain to search
            
        Returns:
            CommonCrawlResult with discovered subdomains
        """
        result = CommonCrawlResult(domain=domain)
        start_time = datetime.utcnow()
        
        if not self.local_index_path or not os.path.exists(self.local_index_path):
            result.error = f"Local index not found: {self.local_index_path}"
            return result
        
        try:
            # Reverse domain for Common Crawl format (com,rockwellautomation)
            reversed_domain = self._reverse_domain(domain)
            # Add comma to match only subdomains
            search_pattern = f"{reversed_domain},"
            
            # Use sgrep for fast sorted file search
            # Falls back to grep if sgrep not available
            if self._command_exists("sgrep"):
                cmd = f"sgrep '{search_pattern}' '{self.local_index_path}'"
            else:
                cmd = f"grep '^{search_pattern}' '{self.local_index_path}'"
            
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            subdomains: Set[str] = set()
            for line in stdout.decode().strip().split("\n"):
                line = line.strip()
                if not line:
                    continue
                
                # Unreverse the domain
                subdomain = self._unreverse_domain(line)
                if subdomain and subdomain.endswith(f".{domain}"):
                    subdomains.add(subdomain)
            
            result.subdomains = sorted(list(subdomains))
            logger.info(f"Common Crawl (local) found {len(result.subdomains)} subdomains for {domain}")
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Common Crawl local search error: {e}")
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    def _reverse_domain(self, domain: str) -> str:
        """
        Reverse domain parts for CC index format.
        
        Example: www.rockwellautomation.com -> com,rockwellautomation,www
        """
        parts = domain.split(".")
        return ",".join(reversed(parts))
    
    def _unreverse_domain(self, reversed_domain: str) -> str:
        """
        Convert CC index format back to normal domain.
        
        Example: com,rockwellautomation,www -> www.rockwellautomation.com
        """
        parts = reversed_domain.split(",")
        return ".".join(reversed(parts))
    
    def _command_exists(self, cmd: str) -> bool:
        """Check if a command exists in PATH."""
        try:
            subprocess.run(
                ["which", cmd],
                capture_output=True,
                check=True
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    async def get_available_indexes(self) -> List[str]:
        """
        Get list of available CC index collections.
        
        Returns:
            List of index names (e.g., ["CC-MAIN-2024-10", "CC-MAIN-2024-05", ...])
        """
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get("https://index.commoncrawl.org/collinfo.json")
                if response.status_code == 200:
                    import json
                    data = response.json()
                    return [idx["id"] for idx in data]
        except Exception as e:
            logger.error(f"Failed to get CC indexes: {e}")
        return []


# Convenience function for one-off searches
async def search_commoncrawl(domain: str, timeout: float = 60.0) -> CommonCrawlResult:
    """
    Quick search for subdomains in Common Crawl.
    
    Args:
        domain: Domain to search (e.g., rockwellautomation.com)
        timeout: Request timeout
        
    Returns:
        CommonCrawlResult with subdomains
    """
    service = CommonCrawlService(timeout=timeout)
    return await service.search_domain(domain)

