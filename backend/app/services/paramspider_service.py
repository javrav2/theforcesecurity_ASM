"""
ParamSpider Service for URL parameter discovery.

ParamSpider mines parameters from web archives (Wayback Machine, Common Crawl)
to discover URL parameters that may be vulnerable to testing.

Installation: pip install paramspider
GitHub: https://github.com/devanshbatham/ParamSpider
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class ParamSpiderResult:
    """Result from ParamSpider scan."""
    domain: str
    urls: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    success: bool = False
    error: Optional[str] = None
    elapsed_time: float = 0.0


def _check_paramspider_available() -> bool:
    """Check if paramspider is installed."""
    return shutil.which("paramspider") is not None


class ParamSpiderService:
    """
    Service for discovering URL parameters using ParamSpider.
    
    ParamSpider finds parameters by mining web archives for a domain,
    extracting unique parameters that may be vulnerable to XSS, SQLi, etc.
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        Initialize ParamSpider service.
        
        Args:
            output_dir: Directory to store output files (temp dir if None)
        """
        self.paramspider_path = shutil.which("paramspider")
        self.output_dir = output_dir or tempfile.gettempdir()
        
    def is_available(self) -> bool:
        """Check if ParamSpider is available."""
        return self.paramspider_path is not None
    
    async def scan_domain(
        self,
        domain: str,
        level: str = "high",
        exclude_extensions: Optional[List[str]] = None,
        timeout: int = 300,
    ) -> ParamSpiderResult:
        """
        Run ParamSpider on a domain to discover parameters.
        
        Args:
            domain: Domain to scan (e.g., example.com)
            level: Unused (kept for API compat); ParamSpider has no level flag
            exclude_extensions: Unused (kept for API compat); ParamSpider uses hardcoded extensions
            timeout: Command timeout in seconds
            
        Returns:
            ParamSpiderResult with discovered parameters
        """
        result = ParamSpiderResult(domain=domain)
        start_time = datetime.utcnow()
        
        if not self.is_available():
            result.error = "ParamSpider not installed. Run: pip install paramspider"
            return result
        
        work_dir = tempfile.mkdtemp(prefix="paramspider_")
        
        try:
            cmd = [
                self.paramspider_path,
                "-d", domain,
                "-s",
            ]
            
            logger.info(f"Running ParamSpider on {domain}: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_dir,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=timeout
                )
            except asyncio.TimeoutError:
                process.kill()
                result.error = f"ParamSpider timed out after {timeout}s"
                return result
            
            if process.returncode not in (0, None):
                stderr_text = stderr.decode('utf-8', errors='ignore').strip() if stderr else ''
                logger.warning(f"ParamSpider exited {process.returncode} for {domain}: {stderr_text}")
            
            all_urls: Set[str] = set()
            all_params: Set[str] = set()
            all_endpoints: Set[str] = set()
            all_js_files: Set[str] = set()
            
            # ParamSpider writes output to results/{domain}.txt in its cwd
            output_file = os.path.join(work_dir, "results", f"{domain}.txt")
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url and not url.startswith('#'):
                            all_urls.add(url)
            
            # Also capture URLs from stdout (-s stream mode)
            if stdout:
                for line in stdout.decode('utf-8', errors='ignore').splitlines():
                    url = line.strip()
                    if url and url.startswith(('http://', 'https://')) and '?' in url:
                        all_urls.add(url)
            
            for url in all_urls:
                parsed = urlparse(url)
                if parsed.path and parsed.path != '/':
                    all_endpoints.add(parsed.path)
                if parsed.path.endswith('.js'):
                    all_js_files.add(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param_name in params.keys():
                        all_params.add(param_name)
            
            result.urls = sorted(list(all_urls))
            result.parameters = sorted(list(all_params))
            result.endpoints = sorted(list(all_endpoints))
            result.js_files = sorted(list(all_js_files))
            result.success = True
            
            logger.info(
                f"ParamSpider found {len(result.urls)} URLs, "
                f"{len(result.parameters)} parameters, "
                f"{len(result.endpoints)} endpoints for {domain}"
            )
            
        except Exception as e:
            logger.error(f"ParamSpider error for {domain}: {e}")
            result.error = str(e)
        finally:
            try:
                shutil.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def scan_multiple_domains(
        self,
        domains: List[str],
        max_concurrent: int = 5,
        **kwargs
    ) -> List[ParamSpiderResult]:
        """
        Scan multiple domains concurrently.
        
        Args:
            domains: List of domains to scan
            max_concurrent: Maximum concurrent scans
            **kwargs: Additional arguments for scan_domain
            
        Returns:
            List of ParamSpiderResult
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_limit(domain: str) -> ParamSpiderResult:
            async with semaphore:
                return await self.scan_domain(domain, **kwargs)
        
        tasks = [scan_with_limit(d) for d in domains]
        return await asyncio.gather(*tasks)


# Convenience function
async def discover_parameters(domain: str) -> ParamSpiderResult:
    """Quick function to discover parameters for a domain."""
    service = ParamSpiderService()
    return await service.scan_domain(domain)

