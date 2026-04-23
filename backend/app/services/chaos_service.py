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
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        organization_id: Optional[int] = None,
    ):
        """
        Initialize Chaos service.

        Args:
            api_key: ProjectDiscovery Cloud API key. Falls back to the API key
                rotator (multiple keys per org) and then to ``PDCP_API_KEY`` env var.
            organization_id: If set, the rotator picks the next healthy key
                configured for this org under service name ``pdcp``.
        """
        self.api_key = api_key or _get_pdcp_api_key()
        self.available = CHAOS_AVAILABLE
        self.organization_id = organization_id

        if not self.available:
            logger.warning("Chaos binary not found - passive subdomain lookup disabled")
        elif not self.api_key and organization_id is None:
            logger.warning("PDCP_API_KEY not set - Chaos subdomain lookup disabled")

    @property
    def is_configured(self) -> bool:
        """Chaos is usable if the binary exists and we can obtain at least one key."""
        return self.available and (bool(self.api_key) or self.organization_id is not None)

    async def _acquire_key(self):
        """
        Acquire an API key lease, preferring the rotator. Returns a tuple of
        ``(api_key, lease_or_none)``. If ``lease`` is ``None`` the caller
        does not need to record success/failure (env-only path).
        """
        from app.services.api_key_rotator_service import get_rotator

        lease = await get_rotator().lease(
            service="pdcp",
            organization_id=self.organization_id,
            env_fallback="PDCP_API_KEY",
        )
        if lease and lease.api_key:
            return lease.api_key, lease
        return self.api_key, None
    
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

        api_key, lease = await self._acquire_key()
        if not api_key:
            logger.debug("Chaos: no healthy key available")
            return None

        try:
            cmd = [
                "chaos",
                "-d", domain,
                "-count",
                "-silent",
                "-key", api_key
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "PDCP_API_KEY": api_key}
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            output = stdout.decode().strip()
            stderr_text = stderr.decode() if stderr else ""

            if process.returncode != 0 or "unauthorized" in stderr_text.lower():
                if lease:
                    lease.record_failure(stderr_text or "non-zero exit", kind="auth" if "unauthorized" in stderr_text.lower() else "transient")
                return None

            if lease:
                lease.record_success()

            if ":" in output:
                count_str = output.split(":")[-1].strip()
                return int(count_str)
            elif output.isdigit():
                return int(output)

            return None

        except asyncio.TimeoutError:
            logger.warning(f"Chaos count query timed out for {domain}")
            if lease:
                lease.record_failure("timeout", kind="transient")
            return None
        except Exception as e:
            logger.error(f"Chaos count query failed for {domain}: {e}")
            if lease:
                lease.record_failure(str(e), kind="transient")
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

        api_key, lease = await self._acquire_key()
        if not api_key:
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
                "-key", api_key
            ]

            logger.info(f"Querying Chaos dataset for {domain}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "PDCP_API_KEY": api_key}
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            stderr_text = stderr.decode() if stderr else ""
            if stderr_text and "error" in stderr_text.lower():
                logger.warning(f"Chaos stderr: {stderr_text[:500]}")
                if lease and ("unauthorized" in stderr_text.lower() or "invalid" in stderr_text.lower()):
                    lease.record_failure(stderr_text, kind="auth")
                    return []
                if lease and ("rate" in stderr_text.lower() or "429" in stderr_text):
                    lease.record_failure(stderr_text, kind="rate")
                    return []
            
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
            if lease:
                lease.record_success()

        except asyncio.TimeoutError:
            logger.warning(f"Chaos query timed out for {domain}")
            if lease:
                lease.record_failure("timeout", kind="transient")
        except Exception as e:
            logger.error(f"Chaos query failed for {domain}: {e}")
            if lease:
                lease.record_failure(str(e), kind="transient")
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

        api_key, lease = await self._acquire_key()
        if not api_key:
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
                "-key", api_key
            ]

            logger.info(f"Querying Chaos dataset for {len(domains)} domains")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "PDCP_API_KEY": api_key}
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            stderr_text = stderr.decode() if stderr else ""
            if process.returncode != 0 and lease:
                kind = "auth" if "unauthorized" in stderr_text.lower() else ("rate" if "429" in stderr_text else "transient")
                lease.record_failure(stderr_text or "non-zero exit", kind=kind)
            
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
            if lease and process.returncode == 0:
                lease.record_success()

        except asyncio.TimeoutError:
            logger.warning(f"Chaos batch query timed out")
            if lease:
                lease.record_failure("timeout", kind="transient")
        except Exception as e:
            logger.error(f"Chaos batch query failed: {e}")
            if lease:
                lease.record_failure(str(e), kind="transient")
        finally:
            for path in [domain_path, output_path]:
                if os.path.exists(path):
                    try:
                        os.unlink(path)
                    except Exception:
                        pass
        
        return results


def get_chaos_service(
    api_key: Optional[str] = None,
    organization_id: Optional[int] = None,
) -> ChaosService:
    """Factory function to create a ChaosService instance.

    Pass ``organization_id`` to enable the API key rotator so calls will
    transparently rotate across every healthy ``pdcp`` key configured for
    the org.
    """
    return ChaosService(api_key=api_key, organization_id=organization_id)
