"""Login Portal Detection Service.

Identifies login pages, admin panels, and authentication endpoints on assets.
Uses waybackurls, httpx, and pattern matching to find high-value targets.
"""

import asyncio
import subprocess
import logging
import re
from typing import List, Dict, Any, Optional, Set
from datetime import datetime

logger = logging.getLogger(__name__)

# Patterns to identify login/admin portals
LOGIN_PATTERNS = [
    # Authentication pages
    r'login', r'signin', r'sign-in', r'sign_in',
    r'auth', r'authenticate', r'authentication',
    r'logon', r'log-on', r'sso', r'saml',
    r'oauth', r'oidc', r'cas',
    
    # Admin panels
    r'admin', r'administrator', r'adm',
    r'controlpanel', r'control-panel', r'cpanel',
    r'dashboard', r'panel', r'console',
    r'manage', r'manager', r'management',
    r'backend', r'backoffice', r'back-office',
    
    # User management
    r'user', r'users', r'usuario', r'usuarios',
    r'account', r'accounts', r'profile',
    r'member', r'members', r'membership',
    r'moderator', r'mod',
    
    # Password/Registration
    r'password', r'passwd', r'pwd',
    r'register', r'signup', r'sign-up', r'sign_up',
    r'forgot', r'reset', r'recover',
    
    # Common CMS/Framework admin paths
    r'wp-admin', r'wp-login', r'wordpress',
    r'phpmyadmin', r'adminer', r'phpMyAdmin',
    r'drupal', r'joomla', r'magento',
    r'webmail', r'mail', r'owa', r'outlook',
    r'portal', r'intranet', r'extranet',
    r'affiliate', r'partner', r'vendor',
    
    # API authentication
    r'api/auth', r'api/login', r'api/token',
    r'oauth/authorize', r'oauth/token',
    r'\.auth', r'/auth/',
]

# Compile pattern for efficiency
LOGIN_REGEX = re.compile(
    r'(' + '|'.join(LOGIN_PATTERNS) + r')',
    re.IGNORECASE
)


class LoginPortalService:
    """Service to detect login portals and admin pages."""
    
    def __init__(self):
        self.results: List[Dict[str, Any]] = []
    
    async def detect_login_portals(
        self,
        domain: str,
        include_subdomains: bool = True,
        use_wayback: bool = True,
        verify_live: bool = True,
        timeout: int = 300
    ) -> Dict[str, Any]:
        """
        Detect login portals for a domain.
        
        Args:
            domain: Target domain
            include_subdomains: Whether to enumerate subdomains first
            use_wayback: Whether to check wayback machine for historical URLs
            verify_live: Whether to verify URLs are still accessible
            timeout: Maximum time in seconds
            
        Returns:
            Dictionary with detected login portals
        """
        start_time = datetime.utcnow()
        all_urls: Set[str] = set()
        login_urls: Set[str] = set()
        # Cap per-domain time so the scan doesn't run for hours (and get marked stale)
        effective_timeout = min(timeout, 600)  # max 10 min per domain by default

        async def _run() -> Dict[str, Any]:
            nonlocal all_urls, login_urls
            # Step 1: Get target URLs (subdomains + wayback)
            targets = [domain]

            if include_subdomains:
                subdomains = await self._enumerate_subdomains(domain, timeout=min(60, effective_timeout // 4))
                targets.extend(subdomains)
                logger.info(f"Found {len(subdomains)} subdomains for {domain}")

            # Step 2: Probe for live hosts
            live_hosts = await self._probe_hosts(targets, timeout=min(60, effective_timeout // 4))
            logger.info(f"Found {len(live_hosts)} live hosts")

            # Step 3: Get historical URLs from wayback (limit hosts so we finish within timeout)
            max_wayback_hosts = 15  # 15 * 20s ≈ 5 min max for wayback
            if use_wayback and live_hosts:
                for host in live_hosts[:max_wayback_hosts]:
                    wayback_urls = await self._get_wayback_urls(host, timeout=20)
                    all_urls.update(wayback_urls)
                logger.info(f"Found {len(all_urls)} URLs from wayback")
            
            # Step 4: Filter for login-related URLs
            for url in all_urls:
                if LOGIN_REGEX.search(url):
                    login_urls.add(url)
            
            # Also add common paths to live hosts
            common_login_paths = [
                '/login', '/admin', '/signin', '/auth',
                '/wp-admin', '/wp-login.php', '/administrator',
                '/user/login', '/account/login', '/portal',
                '/dashboard', '/console', '/manage',
                '/phpmyadmin', '/webmail', '/owa',
            ]
            
            for host in live_hosts:
                for path in common_login_paths:
                    login_urls.add(f"{host}{path}")
            
            # Step 5: Verify live URLs
            verified_portals = []
            if verify_live and login_urls:
                verified_portals = await self._verify_urls(list(login_urls)[:200], timeout=120)
            else:
                verified_portals = [{"url": url, "verified": False} for url in login_urls]
            
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            
            return {
                "domain": domain,
                "total_subdomains": len(targets) - 1,
                "live_hosts": len(live_hosts),
                "wayback_urls": len(all_urls),
                "login_portals_found": len(verified_portals),
                "portals": verified_portals[:100],  # Limit response size
                "elapsed_seconds": elapsed,
                "patterns_used": len(LOGIN_PATTERNS)
            }

        try:
            return await asyncio.wait_for(_run(), timeout=effective_timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Login portal detection timed out for {domain} after {effective_timeout}s")
            return {
                "domain": domain,
                "error": f"Timed out after {effective_timeout} seconds",
                "portals": [],
                "elapsed_seconds": effective_timeout
            }
        except Exception as e:
            logger.error(f"Error detecting login portals for {domain}: {e}")
            return {
                "domain": domain,
                "error": str(e),
                "portals": []
            }
    
    async def _enumerate_subdomains(self, domain: str, timeout: int = 60) -> List[str]:
        """Enumerate subdomains using subfinder."""
        try:
            proc = await asyncio.create_subprocess_exec(
                'subfinder', '-d', domain, '-silent', '-all',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            subdomains = stdout.decode().strip().split('\n')
            return [s.strip() for s in subdomains if s.strip() and s.strip() != domain]
            
        except asyncio.TimeoutError:
            logger.warning(f"Subfinder timeout for {domain}")
            return []
        except Exception as e:
            logger.error(f"Subfinder error: {e}")
            return []
    
    async def _probe_hosts(self, hosts: List[str], timeout: int = 60) -> List[str]:
        """Probe hosts with httpx to find live ones."""
        try:
            input_data = '\n'.join(hosts).encode()
            
            proc = await asyncio.create_subprocess_exec(
                'httpx', '-silent', '-no-color',
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data),
                timeout=timeout
            )
            
            live = stdout.decode().strip().split('\n')
            return [h.strip() for h in live if h.strip()]
            
        except asyncio.TimeoutError:
            logger.warning("HTTPX probe timeout")
            return [f"https://{h}" for h in hosts[:20]]  # Return some with https prefix
        except Exception as e:
            logger.error(f"HTTPX probe error: {e}")
            return []
    
    async def _get_wayback_urls(self, host: str, timeout: int = 30) -> Set[str]:
        """Get historical URLs from wayback machine."""
        urls = set()
        try:
            # Extract domain from URL
            domain = host.replace('https://', '').replace('http://', '').split('/')[0]
            
            proc = await asyncio.create_subprocess_exec(
                'waybackurls', domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            
            for line in stdout.decode().strip().split('\n'):
                url = line.strip()
                if url:
                    urls.add(url)
                    
        except asyncio.TimeoutError:
            logger.warning(f"Waybackurls timeout for {host}")
        except Exception as e:
            logger.error(f"Waybackurls error: {e}")
        
        return urls
    
    async def _verify_urls(self, urls: List[str], timeout: int = 120) -> List[Dict[str, Any]]:
        """Verify which URLs are still accessible."""
        verified = []
        
        try:
            input_data = '\n'.join(urls).encode()
            
            proc = await asyncio.create_subprocess_exec(
                'httpx', '-silent', '-no-color', '-status-code', '-title',
                '-mc', '200,301,302,401,403',  # Match these status codes
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(
                proc.communicate(input=input_data),
                timeout=timeout
            )
            
            for line in stdout.decode().strip().split('\n'):
                if not line.strip():
                    continue
                    
                parts = line.split()
                if len(parts) >= 2:
                    url = parts[0]
                    status = parts[1] if len(parts) > 1 else "unknown"
                    title = ' '.join(parts[2:]) if len(parts) > 2 else ""
                    
                    # Categorize the portal type
                    portal_type = self._categorize_portal(url, title)
                    
                    verified.append({
                        "url": url,
                        "status_code": status,
                        "title": title,
                        "portal_type": portal_type,
                        "verified": True,
                        "detected_at": datetime.utcnow().isoformat()
                    })
                    
        except asyncio.TimeoutError:
            logger.warning("URL verification timeout")
            # Return unverified
            for url in urls[:50]:
                verified.append({
                    "url": url,
                    "verified": False,
                    "portal_type": self._categorize_portal(url, "")
                })
        except Exception as e:
            logger.error(f"URL verification error: {e}")
        
        return verified
    
    def _categorize_portal(self, url: str, title: str) -> str:
        """Categorize the type of login portal."""
        url_lower = url.lower()
        title_lower = title.lower() if title else ""
        combined = f"{url_lower} {title_lower}"
        
        if any(p in combined for p in ['wp-admin', 'wp-login', 'wordpress']):
            return "WordPress Admin"
        elif any(p in combined for p in ['phpmyadmin', 'adminer']):
            return "Database Admin"
        elif any(p in combined for p in ['webmail', 'owa', 'outlook', 'roundcube']):
            return "Webmail"
        elif any(p in combined for p in ['cpanel', 'plesk', 'whm']):
            return "Hosting Panel"
        elif any(p in combined for p in ['jira', 'confluence', 'bitbucket']):
            return "Atlassian"
        elif any(p in combined for p in ['jenkins', 'gitlab', 'github']):
            return "DevOps"
        elif any(p in combined for p in ['grafana', 'kibana', 'prometheus']):
            return "Monitoring"
        elif any(p in combined for p in ['admin', 'administrator', 'backend']):
            return "Admin Panel"
        elif any(p in combined for p in ['api', 'oauth', 'token']):
            return "API Auth"
        elif any(p in combined for p in ['login', 'signin', 'auth']):
            return "Login Page"
        elif any(p in combined for p in ['portal', 'intranet']):
            return "Portal"
        else:
            return "Other"


async def scan_domain_for_login_portals(
    domain: str,
    include_subdomains: bool = True,
    use_wayback: bool = True
) -> Dict[str, Any]:
    """
    Convenience function to scan a domain for login portals.
    
    Args:
        domain: Target domain to scan
        include_subdomains: Include subdomain enumeration
        use_wayback: Check wayback machine
        
    Returns:
        Scan results with detected portals
    """
    service = LoginPortalService()
    return await service.detect_login_portals(
        domain=domain,
        include_subdomains=include_subdomains,
        use_wayback=use_wayback
    )
