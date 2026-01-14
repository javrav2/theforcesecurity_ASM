"""
Katana Service for deep web crawling and JS discovery.

Katana (https://github.com/projectdiscovery/katana) is a fast crawler 
for discovering endpoints, JS files, and parameters from web applications.

Features:
- Deep recursive crawling
- JavaScript parsing and endpoint extraction
- Form and link discovery
- Automatic deduplication
"""

import asyncio
import logging
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set, Dict, Any
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class KatanaResult:
    """Result from Katana crawl."""
    target: str
    success: bool
    urls: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    forms: List[str] = field(default_factory=list)
    error: Optional[str] = None
    elapsed_time: float = 0.0
    
    # Breakdown by type
    api_endpoints: List[str] = field(default_factory=list)
    static_files: List[str] = field(default_factory=list)


# File extensions to exclude from crawling
EXCLUDED_EXTENSIONS = [
    "woff", "woff2", "ttf", "eot", "otf",  # Fonts
    "css", "scss", "less",                   # Styles
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp",  # Images
    "mp4", "mp3", "avi", "mov", "wmv", "flv", "webm",  # Media
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",  # Documents
]

# Patterns for identifying interesting endpoints
API_PATTERNS = [
    r'/api/', r'/v\d+/', r'/graphql', r'/rest/',
    r'/json', r'/xml', r'/rpc', r'/soap',
]

# Patterns for potentially sensitive endpoints
SENSITIVE_PATTERNS = [
    r'/admin', r'/login', r'/auth', r'/oauth',
    r'/config', r'/settings', r'/debug', r'/test',
    r'/backup', r'/dump', r'/export', r'/import',
    r'/upload', r'/download', r'/file',
    r'\.env', r'\.git', r'\.svn',
    r'/phpinfo', r'/wp-admin', r'/wp-content',
]


class KatanaService:
    """
    Service for deep web crawling using Katana.
    
    Discovers:
    - All reachable URLs
    - JavaScript files (for secret scanning)
    - API endpoints
    - Form actions
    - URL parameters
    """
    
    def __init__(self):
        """Initialize the Katana service."""
        self.katana_path = shutil.which('katana')
        
    def is_available(self) -> bool:
        """Check if Katana is installed."""
        return self.katana_path is not None
    
    async def crawl(
        self,
        target: str,
        depth: int = 5,
        js_crawl: bool = True,
        form_extraction: bool = True,
        timeout: int = 600,
        rate_limit: int = 150,
        concurrency: int = 10,
        headless: bool = False,
    ) -> KatanaResult:
        """
        Crawl a target URL/domain with Katana.
        
        Args:
            target: URL or domain to crawl
            depth: Crawl depth (default 5)
            js_crawl: Parse JavaScript for endpoints
            form_extraction: Extract form actions
            timeout: Total timeout in seconds
            rate_limit: Requests per second
            concurrency: Concurrent requests
            headless: Use headless browser for JS rendering
            
        Returns:
            KatanaResult with discovered URLs, endpoints, and parameters
        """
        result = KatanaResult(target=target, success=False)
        start_time = datetime.utcnow()
        
        if not self.is_available():
            result.error = "Katana not installed. Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
            return result
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            # Build Katana command
            cmd = [
                self.katana_path,
                '-u', target,
                '-d', str(depth),
                '-silent',
                '-nc',  # No color
                '-rl', str(rate_limit),
                '-c', str(concurrency),
                '-timeout', str(min(timeout // 60, 10)),  # Per-request timeout in minutes
                '-ef', ','.join(EXCLUDED_EXTENSIONS),  # Exclude extensions
            ]
            
            # JavaScript crawling
            if js_crawl:
                cmd.extend(['-jc', '-kf'])  # JS crawl + known files
            
            # Form extraction
            if form_extraction:
                cmd.append('-fx')  # Form extraction
            
            # Headless mode for JS-heavy sites
            if headless:
                cmd.append('-hl')
            
            logger.info(f"Running Katana on {target} with depth={depth}")
            
            # Run Katana
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
                result.error = f"Katana timed out after {timeout}s"
                result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
                return result
            
            if stderr:
                stderr_text = stderr.decode().strip()
                if 'error' in stderr_text.lower():
                    logger.warning(f"Katana stderr for {target}: {stderr_text[:200]}")
            
            # Parse output
            all_urls: Set[str] = set()
            all_endpoints: Set[str] = set()
            all_params: Set[str] = set()
            all_js: Set[str] = set()
            all_forms: Set[str] = set()
            all_api: Set[str] = set()
            
            for line in stdout.decode().strip().split('\n'):
                url = line.strip()
                if not url or not url.startswith('http'):
                    continue
                
                all_urls.add(url)
                
                # Parse the URL
                try:
                    parsed = urlparse(url)
                    path = parsed.path.rstrip('/')
                    
                    # Extract endpoint (path without query)
                    if path and path != '/':
                        all_endpoints.add(path)
                    
                    # Check for JS files
                    if path.endswith('.js') or '/js/' in path:
                        all_js.add(url)
                    
                    # Extract parameters
                    if parsed.query:
                        params = parse_qs(parsed.query)
                        for param_name in params.keys():
                            all_params.add(param_name)
                    
                    # Identify API endpoints
                    url_lower = url.lower()
                    for pattern in API_PATTERNS:
                        if re.search(pattern, url_lower):
                            all_api.add(url)
                            break
                    
                    # Check for form actions
                    if 'action=' in url_lower or 'submit' in url_lower:
                        all_forms.add(url)
                        
                except Exception:
                    continue
            
            result.urls = sorted(list(all_urls))
            result.endpoints = sorted(list(all_endpoints))
            result.parameters = sorted(list(all_params))
            result.js_files = sorted(list(all_js))
            result.forms = sorted(list(all_forms))
            result.api_endpoints = sorted(list(all_api))
            result.success = True
            
            logger.info(
                f"Katana crawl of {target}: {len(result.urls)} URLs, "
                f"{len(result.endpoints)} endpoints, {len(result.parameters)} params, "
                f"{len(result.js_files)} JS files"
            )
            
        except Exception as e:
            logger.error(f"Katana error for {target}: {e}")
            result.error = str(e)
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def crawl_multiple(
        self,
        targets: List[str],
        max_concurrent: int = 3,
        **kwargs
    ) -> List[KatanaResult]:
        """
        Crawl multiple targets concurrently.
        
        Args:
            targets: List of URLs/domains to crawl
            max_concurrent: Maximum concurrent crawls
            **kwargs: Additional arguments for crawl()
            
        Returns:
            List of KatanaResult objects
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def crawl_with_limit(target: str) -> KatanaResult:
            async with semaphore:
                return await self.crawl(target, **kwargs)
        
        tasks = [crawl_with_limit(t) for t in targets]
        return await asyncio.gather(*tasks)
    
    async def crawl_from_file(
        self,
        file_path: str,
        **kwargs
    ) -> List[KatanaResult]:
        """
        Crawl targets from a file (one per line).
        
        Args:
            file_path: Path to file with targets
            **kwargs: Additional arguments for crawl_multiple()
            
        Returns:
            List of KatanaResult objects
        """
        with open(file_path, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        return await self.crawl_multiple(targets, **kwargs)
    
    def extract_secrets_from_js(self, js_content: str) -> Dict[str, List[str]]:
        """
        Extract potential secrets from JavaScript content.
        
        Args:
            js_content: JavaScript file content
            
        Returns:
            Dictionary with potential secrets by type
        """
        secrets = {
            'api_keys': [],
            'tokens': [],
            'passwords': [],
            'urls': [],
            'emails': [],
        }
        
        # API key patterns
        api_patterns = [
            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?apikey["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'["\']?auth[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)',  # JWT
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if len(match) > 8:  # Filter short strings
                    secrets['api_keys'].append(match)
        
        # URL patterns
        url_pattern = r'https?://[^\s"\'<>]+(?:/[^\s"\'<>]*)?'
        urls = re.findall(url_pattern, js_content)
        secrets['urls'] = list(set(urls))[:100]  # Limit
        
        # Email patterns
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, js_content)
        secrets['emails'] = list(set(emails))[:50]
        
        return secrets


# Convenience function
async def deep_crawl(target: str, depth: int = 5) -> KatanaResult:
    """Quick function to deep crawl a target."""
    service = KatanaService()
    return await service.crawl(target, depth=depth)
