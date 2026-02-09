"""
TLDFinder service for improved TLD and domain discovery.

Uses ProjectDiscovery's tldfinder to discover subdomains and domains
from multiple sources (Wayback, whoisxmlapi, etc.). Ideal for
keyword-driven discovery (e.g. "Rockwell Automation" → run against
org root domains) and private TLD enumeration.

Ref: https://github.com/projectdiscovery/tldfinder
Install: go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest
"""

import asyncio
import json
import logging
import shutil
import time
from dataclasses import dataclass, field
from typing import List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class TLDFinderResult:
    """Result from tldfinder run."""
    domains: List[str] = field(default_factory=list)
    sources: dict = field(default_factory=dict)  # domain -> source if available
    success: bool = False
    error: Optional[str] = None
    elapsed_seconds: float = 0.0
    raw_output: str = ""


def _check_tldfinder_available() -> bool:
    """Check if tldfinder binary is available."""
    return shutil.which("tldfinder") is not None


TLDFINDER_AVAILABLE = _check_tldfinder_available()


class TLDFinderService:
    """
    Service for running tldfinder to discover domains/subdomains.
    
    Use for:
    - Running against a root domain (e.g. rockwellautomation.com) to get more subdomains
    - Keyword-driven discovery: pass org's root domain(s) from organization.domain or keywords
    """

    def __init__(self, timeout: int = 600):
        self.timeout = timeout
        self.binary = shutil.which("tldfinder")

    def is_available(self) -> bool:
        return self.binary is not None

    async def run(
        self,
        domains: List[str],
        discovery_mode: str = "domain",
        json_output: bool = True,
        rate_limit: Optional[int] = None,
        exclude_sources: Optional[List[str]] = None,
        max_time_minutes: int = 10,
    ) -> TLDFinderResult:
        """
        Run tldfinder for the given domain(s).
        
        Args:
            domains: List of domains or private TLDs (e.g. ["rockwellautomation.com"] or ["google"])
            discovery_mode: dns | tld | domain (default domain for subdomain discovery)
            json_output: Request JSONL output for parsing
            rate_limit: Max HTTP requests per second (global)
            exclude_sources: Sources to exclude
            max_time_minutes: Max time to wait for enumeration
            
        Returns:
            TLDFinderResult with discovered domains
        """
        if not self.binary:
            return TLDFinderResult(success=False, error="tldfinder binary not found. Install: go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest")
        if not domains:
            return TLDFinderResult(success=False, error="No domains provided")

        start = time.monotonic()
        cmd = [
            self.binary,
            "-d", ",".join(domains),
            "-dm", discovery_mode,
            "-max-time", str(max_time_minutes),
        ]
        if json_output:
            cmd.append("-oJ")
        if rate_limit is not None:
            cmd.extend(["-rl", str(rate_limit)])
        if exclude_sources:
            cmd.extend(["-es", ",".join(exclude_sources)])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout,
            )
            elapsed = time.monotonic() - start
            out = stdout.decode("utf-8", errors="ignore")
            err = stderr.decode("utf-8", errors="ignore")

            collected: Set[str] = set()
            sources: dict = {}

            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        # JSONL object: may have "host", "domain", or similar
                        d = obj.get("host") or obj.get("domain") or obj.get("name") or ""
                        if d:
                            collected.add(d)
                            if "source" in obj:
                                sources[d] = obj.get("source", "")
                    elif isinstance(obj, str):
                        collected.add(obj)
                except json.JSONDecodeError:
                    # Plain text line: treat as domain
                    if line and not line.startswith("["):
                        collected.add(line)

            return TLDFinderResult(
                domains=sorted(collected),
                sources=sources,
                success=process.returncode == 0,
                error=err if process.returncode != 0 else None,
                elapsed_seconds=elapsed,
                raw_output=out[:5000] if out else "",
            )
        except asyncio.TimeoutError:
            return TLDFinderResult(
                success=False,
                error=f"tldfinder timed out after {self.timeout}s",
                elapsed_seconds=self.timeout,
            )
        except Exception as e:
            logger.exception("tldfinder run failed")
            return TLDFinderResult(success=False, error=str(e))

    def run_sync(
        self,
        domains: List[str],
        discovery_mode: str = "domain",
        **kwargs,
    ) -> TLDFinderResult:
        """Synchronous wrapper."""
        return asyncio.run(self.run(domains, discovery_mode=discovery_mode, **kwargs))
