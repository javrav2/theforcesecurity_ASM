"""
WaybackURLs Service

Fetches historical URLs from the Wayback Machine for domains and subdomains.
Uses the tomnomnom/waybackurls Go tool: https://github.com/tomnomnom/waybackurls

This is useful for:
- Finding old/forgotten endpoints
- Discovering API endpoints
- Finding sensitive files that may have been exposed
- Understanding the attack surface over time
"""

import asyncio
import logging
import re
import subprocess
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetType

logger = logging.getLogger(__name__)


@dataclass
class WaybackResult:
    """Result from waybackurls scan."""
    domain: str
    success: bool
    urls: List[str] = field(default_factory=list)
    unique_paths: List[str] = field(default_factory=list)
    file_extensions: dict = field(default_factory=dict)
    interesting_urls: List[str] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_time: float = 0.0


class WaybackURLsService:
    """
    Service for fetching historical URLs using waybackurls.
    """
    
    # Interesting file extensions to highlight
    INTERESTING_EXTENSIONS = {
        '.sql', '.bak', '.backup', '.old', '.conf', '.config', '.cfg',
        '.env', '.git', '.svn', '.htaccess', '.htpasswd', '.log',
        '.json', '.xml', '.yaml', '.yml', '.csv', '.xlsx', '.xls',
        '.zip', '.tar', '.gz', '.rar', '.7z',
        '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
        '.key', '.pem', '.crt', '.cer', '.der', '.p12', '.pfx',
        '.db', '.sqlite', '.mdb', '.sql',
        '.txt', '.md', '.doc', '.docx', '.pdf',
    }
    
    # Patterns that indicate potentially interesting URLs
    INTERESTING_PATTERNS = [
        r'/admin', r'/api/', r'/backup', r'/config', r'/debug',
        r'/login', r'/auth', r'/oauth', r'/token', r'/jwt',
        r'/upload', r'/download', r'/file', r'/export', r'/import',
        r'/swagger', r'/graphql', r'/graphiql', r'/playground',
        r'/phpinfo', r'/info\.php', r'/test', r'/dev', r'/staging',
        r'\.git/', r'\.svn/', r'\.env', r'/\.', 
        r'/wp-admin', r'/wp-content', r'/wp-includes',
        r'/cgi-bin', r'/scripts', r'/includes',
        r'password', r'passwd', r'secret', r'token', r'api_key',
        r'\?.*=', # URLs with query parameters
    ]
    
    def __init__(self, db: Optional[Session] = None):
        """
        Initialize the waybackurls service.
        
        Args:
            db: Optional database session for storing results
        """
        self.db = db
        self._check_tool_installed()
    
    def _check_tool_installed(self) -> bool:
        """Check if waybackurls is installed."""
        return shutil.which('waybackurls') is not None
    
    async def fetch_urls(
        self,
        domain: str,
        no_subs: bool = False,
        timeout: int = 120
    ) -> WaybackResult:
        """
        Fetch historical URLs for a domain using waybackurls.
        
        Args:
            domain: Domain to fetch URLs for
            no_subs: If True, only fetch URLs for exact domain (no subdomains)
            timeout: Timeout in seconds
            
        Returns:
            WaybackResult with discovered URLs
        """
        import time
        start_time = time.time()
        
        result = WaybackResult(domain=domain, success=False)
        
        if not self._check_tool_installed():
            result.error = "waybackurls tool not installed"
            return result
        
        try:
            # Build command
            cmd = ['waybackurls']
            if no_subs:
                cmd.append('-no-subs')
            
            # Run waybackurls with domain as stdin
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input=f"{domain}\n".encode()),
                timeout=timeout
            )
            
            if process.returncode != 0 and stderr:
                logger.warning(f"waybackurls stderr for {domain}: {stderr.decode()}")
            
            # Parse output
            urls = set()
            for line in stdout.decode().strip().split('\n'):
                line = line.strip()
                if line and line.startswith('http'):
                    urls.add(line)
            
            result.urls = sorted(list(urls))
            result.success = True
            
            # Analyze URLs
            result.unique_paths = self._extract_unique_paths(result.urls)
            result.file_extensions = self._count_extensions(result.urls)
            result.interesting_urls = self._find_interesting_urls(result.urls)
            
        except asyncio.TimeoutError:
            result.error = f"Timeout after {timeout} seconds"
        except Exception as e:
            result.error = str(e)
            logger.error(f"waybackurls error for {domain}: {e}")
        
        result.elapsed_time = time.time() - start_time
        return result
    
    async def fetch_urls_batch(
        self,
        domains: List[str],
        no_subs: bool = False,
        timeout: int = 120,
        max_concurrent: int = 5
    ) -> List[WaybackResult]:
        """
        Fetch URLs for multiple domains concurrently.
        
        Args:
            domains: List of domains to fetch
            no_subs: If True, only fetch URLs for exact domains
            timeout: Timeout per domain in seconds
            max_concurrent: Maximum concurrent requests
            
        Returns:
            List of WaybackResult objects
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def fetch_with_semaphore(domain: str) -> WaybackResult:
            async with semaphore:
                return await self.fetch_urls(domain, no_subs, timeout)
        
        tasks = [fetch_with_semaphore(d) for d in domains]
        return await asyncio.gather(*tasks)
    
    def _extract_unique_paths(self, urls: List[str]) -> List[str]:
        """Extract unique paths from URLs."""
        paths = set()
        for url in urls:
            try:
                parsed = urlparse(url)
                # Get path without query string and normalize
                path = parsed.path.rstrip('/')
                if path:
                    paths.add(path)
            except:
                continue
        return sorted(list(paths))
    
    def _count_extensions(self, urls: List[str]) -> dict:
        """Count file extensions in URLs."""
        extensions = {}
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path.lower()
                # Find extension
                for ext in self.INTERESTING_EXTENSIONS:
                    if path.endswith(ext) or ext in path:
                        extensions[ext] = extensions.get(ext, 0) + 1
            except:
                continue
        return dict(sorted(extensions.items(), key=lambda x: x[1], reverse=True))
    
    def _find_interesting_urls(self, urls: List[str]) -> List[str]:
        """Find potentially interesting URLs."""
        interesting = set()
        for url in urls:
            url_lower = url.lower()
            for pattern in self.INTERESTING_PATTERNS:
                if re.search(pattern, url_lower):
                    interesting.add(url)
                    break
            # Also check for interesting extensions
            for ext in self.INTERESTING_EXTENSIONS:
                if ext in url_lower:
                    interesting.add(url)
                    break
        return sorted(list(interesting))
    
    async def fetch_for_organization(
        self,
        organization_id: int,
        include_subdomains: bool = True,
        timeout_per_domain: int = 120,
        max_concurrent: int = 3
    ) -> dict:
        """
        Fetch wayback URLs for all domains/subdomains in an organization.
        
        Args:
            organization_id: Organization ID
            include_subdomains: Whether to include subdomains
            timeout_per_domain: Timeout per domain
            max_concurrent: Maximum concurrent requests
            
        Returns:
            Dictionary with results
        """
        if not self.db:
            return {"error": "Database session required"}
        
        # Get domains and subdomains
        asset_types = [AssetType.DOMAIN]
        if include_subdomains:
            asset_types.append(AssetType.SUBDOMAIN)
        
        assets = self.db.query(Asset).filter(
            Asset.organization_id == organization_id,
            Asset.asset_type.in_(asset_types)
        ).all()
        
        domains = [asset.value for asset in assets if asset.value]
        
        if not domains:
            return {"error": "No domains found for organization"}
        
        # Fetch URLs
        results = await self.fetch_urls_batch(
            domains,
            no_subs=not include_subdomains,
            timeout=timeout_per_domain,
            max_concurrent=max_concurrent
        )
        
        # Aggregate results
        all_urls = set()
        all_interesting = set()
        all_extensions = {}
        domain_results = []
        
        for result in results:
            if result.success:
                all_urls.update(result.urls)
                all_interesting.update(result.interesting_urls)
                for ext, count in result.file_extensions.items():
                    all_extensions[ext] = all_extensions.get(ext, 0) + count
            
            domain_results.append({
                "domain": result.domain,
                "success": result.success,
                "url_count": len(result.urls),
                "interesting_count": len(result.interesting_urls),
                "elapsed_time": result.elapsed_time,
                "error": result.error
            })
        
        return {
            "organization_id": organization_id,
            "domains_scanned": len(domains),
            "total_urls": len(all_urls),
            "total_interesting": len(all_interesting),
            "file_extensions": dict(sorted(all_extensions.items(), key=lambda x: x[1], reverse=True)),
            "domain_results": domain_results,
            "all_urls": sorted(list(all_urls)),
            "interesting_urls": sorted(list(all_interesting))
        }



