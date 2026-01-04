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
    domains: List[str] = field(default_factory=list)  # New domains discovered (different TLDs, keyword matches)
    urls: List[str] = field(default_factory=list)
    source: str = "commoncrawl"
    success: bool = True
    elapsed_time: float = 0.0
    error: Optional[str] = None


# Common TLDs to search for org name variations
COMMON_TLDS = [
    "com", "net", "org", "io", "co", "info", "biz", "us", "eu", "uk", "de", 
    "ca", "au", "fr", "jp", "cn", "in", "br", "mx", "es", "it", "nl", "ru",
    "cloud", "app", "dev", "tech", "ai", "solutions", "systems", "services",
    "global", "world", "online", "digital", "group", "inc", "corp", "ltd"
]


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
    
    async def search_by_keyword(self, keyword: str, max_results: int = 5000) -> CommonCrawlResult:
        """
        Search Common Crawl for domains containing a keyword.
        
        Example: search_by_keyword("rockwell") will find:
        - rockwellautomation.com
        - rockwell.com
        - rockwellcollins.com
        - rockwell-software.com
        - mycompany-rockwell.net
        - etc.
        
        Args:
            keyword: Keyword to search for in domain names (e.g., "rockwell")
            max_results: Maximum results to fetch
            
        Returns:
            CommonCrawlResult with discovered domains
        """
        result = CommonCrawlResult(domain=keyword)
        start_time = datetime.utcnow()
        
        try:
            # CC Index wildcard search: *keyword*
            search_url = f"*{keyword}*"
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.index_api,
                    params={
                        "url": search_url,
                        "output": "json",
                        "limit": max_results
                    }
                )
                
                if response.status_code != 200:
                    result.error = f"CC Index API returned {response.status_code}"
                    return result
                
                # Parse NDJSON response
                import json
                domains: Set[str] = set()
                
                for line in response.text.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        url = record.get("url", "")
                        
                        if url:
                            parsed = urlparse(url)
                            hostname = parsed.netloc.lower()
                            
                            # Remove port and www prefix for cleaner results
                            if ":" in hostname:
                                hostname = hostname.split(":")[0]
                            
                            # Extract root domain (ignore subdomains for this search)
                            parts = hostname.split(".")
                            if len(parts) >= 2:
                                # Get root domain (e.g., rockwellautomation.com)
                                root = ".".join(parts[-2:]) if len(parts[-1]) <= 3 else ".".join(parts[-2:])
                                if keyword.lower() in root.lower():
                                    domains.add(root)
                                # Also add full hostname if it contains keyword
                                if keyword.lower() in hostname.lower():
                                    domains.add(hostname)
                    except Exception:
                        continue
                
                result.domains = sorted(list(domains))
                logger.info(f"Common Crawl keyword search '{keyword}' found {len(result.domains)} domains")
                
        except httpx.TimeoutException:
            result.error = "Request timed out"
            logger.warning(f"Common Crawl timeout for keyword '{keyword}'")
        except Exception as e:
            result.error = str(e)
            logger.error(f"Common Crawl keyword search error: {e}")
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def search_org_all_tlds(
        self, 
        org_name: str, 
        tlds: Optional[List[str]] = None
    ) -> CommonCrawlResult:
        """
        Search for an organization name across multiple TLDs.
        
        Example: search_org_all_tlds("rockwellautomation") will find:
        - rockwellautomation.com
        - rockwellautomation.net
        - rockwellautomation.org
        - rockwellautomation.io
        - rockwellautomation.cloud
        - etc.
        
        Args:
            org_name: Organization/brand name (e.g., "rockwellautomation")
            tlds: List of TLDs to check (defaults to COMMON_TLDS)
            
        Returns:
            CommonCrawlResult with discovered domains
        """
        result = CommonCrawlResult(domain=org_name)
        start_time = datetime.utcnow()
        tlds = tlds or COMMON_TLDS
        
        try:
            domains: Set[str] = set()
            
            # Search for org_name.* pattern
            search_url = f"{org_name}.*"
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.index_api,
                    params={
                        "url": search_url,
                        "output": "json",
                        "limit": self.max_results
                    }
                )
                
                if response.status_code == 200:
                    import json
                    for line in response.text.strip().split("\n"):
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            url = record.get("url", "")
                            if url:
                                parsed = urlparse(url)
                                hostname = parsed.netloc.lower()
                                if ":" in hostname:
                                    hostname = hostname.split(":")[0]
                                
                                # Check if it matches org_name.tld pattern
                                parts = hostname.split(".")
                                if len(parts) >= 2:
                                    name_part = parts[0] if parts[0] != "www" else (parts[1] if len(parts) > 1 else parts[0])
                                    if name_part.lower() == org_name.lower():
                                        domains.add(hostname)
                        except Exception:
                            continue
            
            result.domains = sorted(list(domains))
            logger.info(f"Common Crawl TLD search for '{org_name}' found {len(result.domains)} domains")
            
        except httpx.TimeoutException:
            result.error = "Request timed out"
        except Exception as e:
            result.error = str(e)
            logger.error(f"Common Crawl TLD search error: {e}")
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def comprehensive_org_search(
        self,
        org_name: str,
        keywords: Optional[List[str]] = None,
        primary_domain: Optional[str] = None
    ) -> CommonCrawlResult:
        """
        Comprehensive organization search combining multiple strategies.
        
        Searches for:
        1. org_name.* (all TLDs)
        2. *org_name* (keyword anywhere in domain)
        3. Additional keywords if provided
        4. Subdomains of primary domain if provided
        
        Example: comprehensive_org_search("rockwellautomation", keywords=["rockwell"], primary_domain="rockwellautomation.com")
        
        Args:
            org_name: Organization name (e.g., "rockwellautomation")
            keywords: Additional keywords to search (e.g., ["rockwell"])
            primary_domain: Primary domain to find subdomains for
            
        Returns:
            CommonCrawlResult with all discovered domains and subdomains
        """
        result = CommonCrawlResult(domain=org_name)
        start_time = datetime.utcnow()
        
        all_domains: Set[str] = set()
        all_subdomains: Set[str] = set()
        
        try:
            # 1. Search org_name across all TLDs
            logger.info(f"CC: Searching for {org_name}.* across TLDs")
            tld_result = await self.search_org_all_tlds(org_name)
            if tld_result.domains:
                all_domains.update(tld_result.domains)
            
            # 2. Search *org_name* keyword pattern
            logger.info(f"CC: Searching for *{org_name}* keyword pattern")
            keyword_result = await self.search_by_keyword(org_name)
            if keyword_result.domains:
                all_domains.update(keyword_result.domains)
            
            # 3. Search additional keywords
            if keywords:
                for keyword in keywords:
                    logger.info(f"CC: Searching for *{keyword}* keyword pattern")
                    kw_result = await self.search_by_keyword(keyword)
                    if kw_result.domains:
                        all_domains.update(kw_result.domains)
            
            # 4. Search subdomains of primary domain
            if primary_domain:
                logger.info(f"CC: Searching for subdomains of {primary_domain}")
                sub_result = await self.search_domain(primary_domain)
                if sub_result.subdomains:
                    all_subdomains.update(sub_result.subdomains)
            
            result.domains = sorted(list(all_domains))
            result.subdomains = sorted(list(all_subdomains))
            result.success = True
            
            logger.info(f"CC comprehensive search: {len(result.domains)} domains, {len(result.subdomains)} subdomains")
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"Common Crawl comprehensive search error: {e}")
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result


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


async def search_commoncrawl_comprehensive(
    org_name: str,
    keywords: Optional[List[str]] = None,
    primary_domain: Optional[str] = None,
    timeout: float = 120.0
) -> CommonCrawlResult:
    """
    Comprehensive Common Crawl search for an organization.
    
    Args:
        org_name: Organization name (e.g., "rockwellautomation")
        keywords: Additional keywords (e.g., ["rockwell"])
        primary_domain: Primary domain (e.g., "rockwellautomation.com")
        timeout: Request timeout
        
    Returns:
        CommonCrawlResult with domains and subdomains
    """
    service = CommonCrawlService(timeout=timeout)
    return await service.comprehensive_org_search(org_name, keywords, primary_domain)

