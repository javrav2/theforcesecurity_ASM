"""Subdomain enumeration service for asset discovery."""

import asyncio
import logging
from typing import Optional, Callable
from dataclasses import dataclass

import dns.resolver
import dns.exception
import httpx

logger = logging.getLogger(__name__)


# Common subdomain wordlist for brute-force enumeration
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "email", "vpn",
    "remote", "admin", "administrator", "app", "apps", "api", "apis", "dev",
    "development", "stage", "staging", "test", "testing", "prod", "production",
    "uat", "qa", "demo", "sandbox", "beta", "alpha", "preview", "portal",
    "web", "www1", "www2", "www3", "m", "mobile", "wap", "blog", "blogs",
    "news", "shop", "store", "cart", "secure", "ssl", "login", "signin",
    "auth", "sso", "id", "identity", "account", "accounts", "my", "support",
    "help", "helpdesk", "ticket", "tickets", "forum", "forums", "community",
    "wiki", "docs", "doc", "documentation", "kb", "knowledge", "faq", "cdn",
    "static", "assets", "images", "img", "media", "video", "videos", "files",
    "download", "downloads", "upload", "uploads", "backup", "backups", "db",
    "database", "mysql", "postgres", "postgresql", "mongodb", "redis", "cache",
    "memcache", "memcached", "elastic", "elasticsearch", "kibana", "grafana",
    "prometheus", "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket",
    "svn", "repo", "repository", "code", "build", "deploy", "release", "jira",
    "confluence", "slack", "teams", "zoom", "meet", "calendar", "drive", "cloud",
    "aws", "azure", "gcp", "s3", "ec2", "lambda", "k8s", "kubernetes", "docker",
    "container", "registry", "harbor", "nexus", "artifactory", "sonar", "vault",
    "consul", "nomad", "terraform", "ansible", "puppet", "chef", "nagios",
    "zabbix", "splunk", "elk", "logstash", "graylog", "sentry", "newrelic",
    "datadog", "pagerduty", "opsgenie", "statuspage", "status", "health",
    "monitor", "monitoring", "metrics", "analytics", "track", "tracking", "crm",
    "erp", "hr", "payroll", "finance", "billing", "invoice", "payment", "pay",
    "checkout", "order", "orders", "inventory", "warehouse", "shipping", "delivery",
    "internal", "intranet", "extranet", "partner", "partners", "vendor", "vendors",
    "client", "clients", "customer", "customers", "member", "members", "user",
    "users", "profile", "profiles", "dashboard", "panel", "console", "control",
    "manager", "management", "office", "outlook", "exchange", "autodiscover",
    "lyncdiscover", "sip", "voip", "pbx", "phone", "tel", "fax", "print", "printer",
    "scan", "scanner", "ntp", "time", "log", "logs", "audit", "report", "reports",
    "export", "import", "sync", "api-v1", "api-v2", "v1", "v2", "v3", "old", "new",
    "legacy", "archive", "archives", "temp", "tmp", "data", "info", "about", "contact",
    "feedback", "survey", "poll", "search", "sitemap", "rss", "feed", "xml", "json",
    "rest", "graphql", "websocket", "ws", "wss", "socket", "proxy", "gateway", "lb",
    "loadbalancer", "haproxy", "nginx", "apache", "iis", "tomcat", "jboss", "weblogic",
    "websphere", "glassfish", "wildfly", "node", "express", "django", "flask", "rails",
    "spring", "laravel", "symfony", "wordpress", "wp", "joomla", "drupal", "magento",
    "shopify", "woocommerce", "prestashop", "opencart"
]


@dataclass
class SubdomainResult:
    """Result of subdomain enumeration."""
    subdomain: str
    ip_addresses: list[str]
    source: str  # How it was discovered
    is_alive: bool = False


class SubdomainService:
    """Service for subdomain enumeration."""
    
    def __init__(
        self,
        nameservers: Optional[list[str]] = None,
        timeout: float = 3.0,
        max_concurrent: int = 50
    ):
        """
        Initialize subdomain service.
        
        Args:
            nameservers: Custom DNS servers to use
            timeout: Query timeout in seconds
            max_concurrent: Maximum concurrent DNS queries
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        
        if nameservers:
            self.resolver.nameservers = nameservers
        else:
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        
        self.max_concurrent = max_concurrent
        self.timeout = timeout
    
    async def enumerate_subdomains(
        self,
        domain: str,
        wordlist: Optional[list[str]] = None,
        use_crtsh: bool = True,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> list[SubdomainResult]:
        """
        Enumerate subdomains using multiple techniques.
        
        Args:
            domain: Base domain to enumerate
            wordlist: Custom wordlist (defaults to COMMON_SUBDOMAINS)
            use_crtsh: Whether to query crt.sh for certificate transparency logs
            progress_callback: Optional callback for progress updates (current, total)
            
        Returns:
            List of discovered subdomains
        """
        discovered = {}
        
        # 1. Query certificate transparency logs
        if use_crtsh:
            logger.info(f"Querying certificate transparency logs for {domain}")
            ct_subdomains = await self._query_crtsh(domain)
            for subdomain in ct_subdomains:
                if subdomain not in discovered:
                    discovered[subdomain] = SubdomainResult(
                        subdomain=subdomain,
                        ip_addresses=[],
                        source="crt.sh"
                    )
        
        # 2. Brute-force common subdomains
        wordlist = wordlist or COMMON_SUBDOMAINS
        logger.info(f"Brute-forcing {len(wordlist)} subdomain names for {domain}")
        
        total = len(wordlist)
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def check_subdomain(prefix: str, index: int):
            async with semaphore:
                subdomain = f"{prefix}.{domain}"
                result = await self._check_subdomain_exists(subdomain)
                if progress_callback:
                    progress_callback(index + 1, total)
                return result
        
        tasks = [check_subdomain(prefix, i) for i, prefix in enumerate(wordlist)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, SubdomainResult) and result.ip_addresses:
                if result.subdomain not in discovered:
                    discovered[result.subdomain] = result
                else:
                    # Update with IP addresses
                    discovered[result.subdomain].ip_addresses = result.ip_addresses
                    discovered[result.subdomain].is_alive = True
        
        # 3. Resolve IPs for CT-discovered subdomains
        logger.info("Resolving IP addresses for discovered subdomains")
        for subdomain, result in discovered.items():
            if not result.ip_addresses:
                ips = await self._resolve_subdomain(subdomain)
                result.ip_addresses = ips
                result.is_alive = len(ips) > 0
        
        return list(discovered.values())
    
    async def _query_crtsh(self, domain: str) -> list[str]:
        """Query crt.sh certificate transparency logs."""
        subdomains = set()
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    follow_redirects=True
                )
                
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        # Split by newline (crt.sh returns multiple names per cert)
                        for n in name.split("\n"):
                            n = n.strip().lower()
                            # Remove wildcard prefix
                            if n.startswith("*."):
                                n = n[2:]
                            # Ensure it's a subdomain of the target
                            if n.endswith(f".{domain}") or n == domain:
                                subdomains.add(n)
        except Exception as e:
            logger.warning(f"crt.sh query failed for {domain}: {e}")
        
        return list(subdomains)
    
    async def _check_subdomain_exists(self, subdomain: str) -> SubdomainResult:
        """Check if a subdomain exists via DNS."""
        result = SubdomainResult(
            subdomain=subdomain,
            ip_addresses=[],
            source="bruteforce"
        )
        
        ips = await self._resolve_subdomain(subdomain)
        if ips:
            result.ip_addresses = ips
            result.is_alive = True
        
        return result
    
    async def _resolve_subdomain(self, subdomain: str) -> list[str]:
        """Resolve subdomain to IP addresses."""
        ips = []
        
        # Run DNS resolution in executor to not block
        loop = asyncio.get_event_loop()
        
        try:
            # Try A records
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(subdomain, 'A')
            )
            ips.extend([str(rdata.address) for rdata in answers])
        except Exception:
            pass
        
        try:
            # Try AAAA records
            answers = await loop.run_in_executor(
                None,
                lambda: self.resolver.resolve(subdomain, 'AAAA')
            )
            ips.extend([str(rdata.address) for rdata in answers])
        except Exception:
            pass
        
        return ips
    
    def enumerate_subdomains_sync(
        self,
        domain: str,
        wordlist: Optional[list[str]] = None,
        use_crtsh: bool = True
    ) -> list[SubdomainResult]:
        """Synchronous wrapper for subdomain enumeration."""
        return asyncio.run(
            self.enumerate_subdomains(domain, wordlist, use_crtsh)
        )



