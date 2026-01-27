"""Chaos Service for ProjectDiscovery subdomain dataset.

Chaos provides access to ProjectDiscovery's pre-indexed subdomain database
containing billions of subdomains collected from various passive sources.

This is different from active enumeration - it queries an existing dataset
for fast, passive subdomain discovery.

Reference: https://chaos.projectdiscovery.io/docs/quick-start
"""

import asyncio
import logging
import os
import tempfile
from typing import List, Optional

logger = logging.getLogger(__name__)


def _check_chaos_available() -> bool:
    """Check if chaos binary is available."""
    import subprocess
    try:
        result = subprocess.run(
            ["chaos", "-version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


def _get_pdcp_api_key() -> Optional[str]:
    """Get the ProjectDiscovery Cloud API key from environment."""
    return os.environ.get("PDCP_API_KEY")


CHAOS_AVAILABLE = _check_chaos_available()
CHAOS_CONFIGURED = CHAOS_AVAILABLE and bool(_get_pdcp_api_key())


class ChaosService:
    """
    Service for querying ProjectDiscovery's Chaos subdomain dataset.
    
    Chaos provides passive subdomain data collected from:
    - Bug bounty programs
    - Public datasets
    - Certificate transparency logs
    - DNS aggregators
    - And other passive sources
    
    This is fast because it queries a pre-built database rather than
    doing active enumeration.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize Chaos service.
        
        Args:
            api_key: ProjectDiscovery Cloud API key. Falls back to PDCP_API_KEY env var.
        """
        self.api_key = api_key or _get_pdcp_api_key()
        self.available = CHAOS_AVAILABLE
        
        if not self.available:
            logger.warning("Chaos binary not found - passive subdomain lookup disabled")
        elif not self.api_key:
            logger.warning("PDCP_API_KEY not set - Chaos subdomain lookup disabled")
    
    @property
    def is_configured(self) -> bool:
        """Check if Chaos is properly configured."""
        return self.available and bool(self.api_key)
    
    async def get_subdomain_count(self, domain: str, timeout: int = 30) -> Optional[int]:
        """
        Get the count of subdomains available for a domain in the Chaos dataset.
        
        Args:
            domain: Domain to query
            timeout: Command timeout in seconds
            
        Returns:
            Number of subdomains available, or None if query failed
        """
        if not self.is_configured:
            logger.debug("Chaos not configured, skipping count query")
            return None
        
        try:
            cmd = [
                "chaos",
                "-d", domain,
                "-count",
                "-silent",
                "-key", self.api_key
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "PDCP_API_KEY": self.api_key}
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            output = stdout.decode().strip()
            
            # Parse count from output (format: "domain: count")
            if ":" in output:
                count_str = output.split(":")[-1].strip()
                return int(count_str)
            elif output.isdigit():
                return int(output)
            
            return None
            
        except asyncio.TimeoutError:
            logger.warning(f"Chaos count query timed out for {domain}")
            return None
        except Exception as e:
            logger.error(f"Chaos count query failed for {domain}: {e}")
            return None
    
    async def fetch_subdomains(
        self, 
        domain: str, 
        timeout: int = 120
    ) -> List[str]:
        """
        Fetch subdomains for a domain from the Chaos dataset.
        
        Args:
            domain: Domain to query
            timeout: Command timeout in seconds
            
        Returns:
            List of subdomains found
        """
        if not self.is_configured:
            logger.debug("Chaos not configured, skipping subdomain fetch")
            return []
        
        subdomains = []
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                "chaos",
                "-d", domain,
                "-o", output_path,
                "-silent",
                "-key", self.api_key
            ]
            
            logger.info(f"Querying Chaos dataset for {domain}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "PDCP_API_KEY": self.api_key}
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            if stderr:
                stderr_text = stderr.decode()
                if "error" in stderr_text.lower():
                    logger.warning(f"Chaos stderr: {stderr_text[:500]}")
            
            # Read results from output file
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        subdomain = line.strip().lower()
                        if subdomain and subdomain.endswith(domain):
                            subdomains.append(subdomain)
            
            # Also check stdout in case results went there
            if stdout:
                for line in stdout.decode().split('\n'):
                    subdomain = line.strip().lower()
                    if subdomain and subdomain.endswith(domain) and subdomain not in subdomains:
                        subdomains.append(subdomain)
            
            logger.info(f"Chaos found {len(subdomains)} subdomains for {domain}")
            
        except asyncio.TimeoutError:
            logger.warning(f"Chaos query timed out for {domain}")
        except Exception as e:
            logger.error(f"Chaos query failed for {domain}: {e}")
        finally:
            if os.path.exists(output_path):
                try:
                    os.unlink(output_path)
                except Exception:
                    pass
        
        return list(set(subdomains))  # Remove duplicates
    
    async def fetch_subdomains_batch(
        self, 
        domains: List[str], 
        timeout: int = 300
    ) -> dict:
        """
        Fetch subdomains for multiple domains from the Chaos dataset.
        
        Args:
            domains: List of domains to query
            timeout: Command timeout in seconds
            
        Returns:
            Dictionary mapping domains to their subdomains
        """
        if not self.is_configured:
            return {}
        
        results = {}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as domain_file:
            domain_file.write('\n'.join(domains))
            domain_path = domain_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as output_file:
            output_path = output_file.name
        
        try:
            cmd = [
                "chaos",
                "-dL", domain_path,
                "-o", output_path,
                "-silent",
                "-key", self.api_key
            ]
            
            logger.info(f"Querying Chaos dataset for {len(domains)} domains")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "PDCP_API_KEY": self.api_key}
            )
            
            await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            # Initialize results
            for domain in domains:
                results[domain] = []
            
            # Read and categorize results
            if os.path.exists(output_path):
                with open(output_path, 'r') as f:
                    for line in f:
                        subdomain = line.strip().lower()
                        if subdomain:
                            # Find which domain this subdomain belongs to
                            for domain in domains:
                                if subdomain.endswith(domain):
                                    results[domain].append(subdomain)
                                    break
            
            total = sum(len(v) for v in results.values())
            logger.info(f"Chaos found {total} total subdomains for {len(domains)} domains")
            
        except asyncio.TimeoutError:
            logger.warning(f"Chaos batch query timed out")
        except Exception as e:
            logger.error(f"Chaos batch query failed: {e}")
        finally:
            for path in [domain_path, output_path]:
                if os.path.exists(path):
                    try:
                        os.unlink(path)
                    except Exception:
                        pass
        
        return results


def get_chaos_service(api_key: Optional[str] = None) -> ChaosService:
    """Factory function to create a ChaosService instance."""
    return ChaosService(api_key)
