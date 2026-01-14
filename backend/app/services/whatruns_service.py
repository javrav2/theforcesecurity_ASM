"""
WhatRuns API integration service for enhanced technology detection.

This service integrates with the WhatRuns API (https://www.whatruns.com) to detect
web technologies on websites. WhatRuns provides detailed technology fingerprinting
including CMS, JavaScript frameworks, fonts, analytics, and security technologies.

Usage:
    service = WhatRunsService()
    techs = await service.detect_technologies("example.com", "https://example.com/")
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class WhatRunsTechnology:
    """A technology detected by WhatRuns."""
    name: str
    slug: str
    category: str
    category_id: int
    icon: Optional[str] = None
    website: Optional[str] = None
    source_url: Optional[str] = None
    detected_time: Optional[str] = None
    is_theme: bool = False
    is_plugin: bool = False
    confidence: int = 100  # WhatRuns doesn't provide confidence, assume 100%
    
    def to_detected_technology(self):
        """Convert to DetectedTechnology format for compatibility with existing code."""
        from app.services.wappalyzer_service import DetectedTechnology
        return DetectedTechnology(
            name=self.name,
            slug=self.slug,
            confidence=self.confidence,
            version=None,  # WhatRuns doesn't provide version info
            categories=[self.category],
            website=self.website,
            icon=self.icon,
            cpe=None  # WhatRuns doesn't provide CPE
        )


# WhatRuns category mapping (based on their API response category IDs)
WHATRUNS_CATEGORIES = {
    1: "CMS",
    2: "Message boards",
    3: "Database managers",
    4: "Documentation",
    5: "Widgets",
    6: "Ecommerce",
    7: "Photo galleries",
    8: "Wikis",
    9: "Hosting panels",
    10: "Analytics",
    11: "Blogs",
    12: "JavaScript Libraries",
    13: "Issue trackers",
    14: "Video players",
    15: "Comment systems",
    16: "Security",
    17: "Font",
    18: "Web frameworks",
    19: "Miscellaneous",
    20: "Editors",
    21: "LMS",
    22: "Web servers",
    23: "Caching",
    24: "Rich text editors",
    25: "JavaScript graphics",
    26: "Mobile frameworks",
    27: "Programming languages",
    28: "Operating systems",
    29: "Search engines",
    30: "Web mail",
    31: "CDN",
    32: "Marketing automation",
    33: "Web server extensions",
    34: "Databases",
    35: "Maps",
    36: "Advertising",
    37: "Network devices",
    38: "Media servers",
    39: "Webcams",
    40: "Printer",
    41: "Payment processors",
    42: "Tag managers",
    43: "Paywalls",
    44: "CI",
    45: "Control systems",
    46: "Remote access",
    47: "Dev tools",
    48: "Network storage",
    49: "Feed readers",
    50: "Document management",
    51: "Page builders",
    52: "Live chat",
    53: "CRM",
    54: "SEO",
    55: "Accounting",
    56: "Cryptominers",
    57: "Static site generator",
    58: "User onboarding",
    59: "JavaScript libraries",
    60: "Containers",
    61: "SaaS",
    62: "Security",  # Also security (duplicate in their system)
    63: "IaaS",
    64: "Reverse proxies",
    65: "Load balancers",
    66: "UI frameworks",
    67: "Cookie compliance",
    68: "Accessibility",
    69: "Social login",
    70: "SSL/TLS certificate authorities",
    71: "Affiliate programs",
    72: "Appointment scheduling",
    73: "Surveys",
    74: "A/B testing",
    75: "Email",
    76: "Personalization",
    77: "Retargeting",
    78: "RUM",
    79: "Geolocation",
    80: "WordPress themes",
    81: "Shopify themes",
    82: "Drupal themes",
    83: "Browser fingerprinting",
    84: "Loyalty & rewards",
    85: "Feature management",
    86: "Segmentation",
    87: "WordPress plugins",
    88: "Hosting",
    89: "Translation",
    90: "Reviews",
    91: "Buy now pay later",
    92: "Performance",
    93: "Reservations & delivery",
    94: "Referral marketing",
    95: "Digital asset management",
    96: "Content curation",
    97: "Customer data platform",
    98: "Cart abandonment",
    99: "Shipping carriers",
    100: "Shopify apps",
    101: "Recruitment & staffing",
    102: "Returns",
    103: "Livestreaming",
    104: "Ticket & event management",
    105: "Authentication",
    106: "Security",
    107: "Form builders",
}


def slugify(name: str) -> str:
    """Convert technology name to URL-safe slug."""
    slug = name.lower()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    slug = slug.strip('-')
    return slug


def extract_domain_parts(hostname: str) -> tuple[str, str, str]:
    """
    Extract domain parts for WhatRuns API request.
    
    Returns:
        tuple: (rawhostname, hostname, subdomain)
        
    Examples:
        "sub.example.com" -> ("sub.example.com", "example.com", "sub")
        "example.com" -> ("example.com", "example.com", "")
        "sub.sub2.example.com" -> ("sub.sub2.example.com", "example.com", "sub.sub2")
    """
    # Remove protocol if present
    hostname = hostname.lower().strip()
    if hostname.startswith("http://"):
        hostname = hostname[7:]
    elif hostname.startswith("https://"):
        hostname = hostname[8:]
    
    # Remove path and port
    hostname = hostname.split("/")[0].split(":")[0]
    
    rawhostname = hostname
    parts = hostname.split(".")
    
    # Common TLDs that have second-level domains
    second_level_tlds = {
        "co.uk", "com.au", "co.nz", "co.za", "com.br", "co.jp",
        "co.kr", "co.in", "com.mx", "com.ar", "com.cn", "org.uk",
        "me.uk", "net.au", "org.au", "gov.uk", "ac.uk", "com.sg",
        "my.site.com", "my.salesforce.com", "my.site.com"  # Salesforce domains
    }
    
    # Check for second-level TLDs
    if len(parts) >= 3:
        potential_sld = ".".join(parts[-2:])
        if potential_sld in second_level_tlds or len(parts[-1]) == 2:
            # This is a second-level TLD
            root_domain = ".".join(parts[-3:])
            subdomain = ".".join(parts[:-3]) if len(parts) > 3 else ""
        else:
            root_domain = ".".join(parts[-2:])
            subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    elif len(parts) == 2:
        root_domain = hostname
        subdomain = ""
    else:
        root_domain = hostname
        subdomain = ""
    
    return (rawhostname, root_domain, subdomain)


class WhatRunsService:
    """
    Service for detecting web technologies using the WhatRuns API.
    
    WhatRuns provides detailed technology detection including:
    - CMS platforms
    - JavaScript frameworks and libraries
    - Analytics and tag managers
    - Fonts and UI frameworks
    - Security headers
    - And many more categories
    """
    
    API_URL = "https://www.whatruns.com/api/v1/get_site_apps"
    
    def __init__(
        self,
        timeout: float = 30.0,
        user_agent: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        rate_limit_delay: float = 1.0,  # Delay between requests to avoid rate limiting
    ):
        """
        Initialize WhatRuns service.
        
        Args:
            timeout: HTTP request timeout in seconds
            user_agent: User agent for HTTP requests
            rate_limit_delay: Delay between requests in seconds
        """
        self.timeout = timeout
        self.user_agent = user_agent
        self.rate_limit_delay = rate_limit_delay
        self._last_request_time = 0.0
    
    def _build_request_data(self, hostname: str, url: Optional[str] = None) -> str:
        """
        Build the request data payload for the WhatRuns API.
        
        Args:
            hostname: The hostname to analyze (e.g., "sub.example.com")
            url: Optional full URL to analyze
            
        Returns:
            URL-encoded form data string
        """
        rawhostname, root_domain, subdomain = extract_domain_parts(hostname)
        
        # If no URL provided, construct one
        if not url:
            url = f"https://{hostname}/"
        
        # Build the data payload (matches the format from the curl command)
        payload = {
            "rawhostname": rawhostname,
            "hostname": root_domain,
            "subdomain": subdomain,
            "url": url,
            "encode": True
        }
        
        # URL-encode the JSON payload
        data_json = json.dumps(payload)
        return f"data={urllib.parse.quote(data_json)}"
    
    def _parse_response(self, response_data: dict, source_url: str) -> List[WhatRunsTechnology]:
        """
        Parse the WhatRuns API response and extract technologies.
        
        Args:
            response_data: The JSON response from the API
            source_url: The URL that was scanned
            
        Returns:
            List of detected technologies
        """
        technologies = []
        
        if not response_data.get("status"):
            logger.warning(f"WhatRuns API returned status=false for {source_url}")
            return technologies
        
        # The apps field is a JSON string that needs to be parsed
        apps_str = response_data.get("apps", "{}")
        if not apps_str:
            return technologies
        
        try:
            apps_data = json.loads(apps_str) if isinstance(apps_str, str) else apps_str
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse WhatRuns apps JSON: {e}")
            return technologies
        
        # The response is organized by timestamp, then by category
        # Example: {"timestamp": {"CMS": [...], "JavaScript Libraries": [...]}}
        for timestamp, categories in apps_data.items():
            if not isinstance(categories, dict):
                continue
            
            for category_name, tech_list in categories.items():
                if not isinstance(tech_list, list):
                    continue
                
                for tech in tech_list:
                    if not isinstance(tech, dict):
                        continue
                    
                    name = tech.get("name", "Unknown")
                    category_id = tech.get("category", 0)
                    
                    # Get category name from ID, or use the key from response
                    category = WHATRUNS_CATEGORIES.get(category_id, category_name)
                    
                    # Clean up category names (remove trailing spaces)
                    category = category.strip()
                    
                    # Extract website URL (clean up WhatRuns redirect URL)
                    website = tech.get("website", "")
                    if website and "whatruns.com/click/?target=" in website:
                        # Extract the actual website from the redirect URL
                        match = re.search(r'target=([^&]+)', website)
                        if match:
                            website = urllib.parse.unquote(match.group(1))
                            if not website.startswith("http"):
                                website = f"https://{website}"
                    
                    technologies.append(WhatRunsTechnology(
                        name=name,
                        slug=slugify(name),
                        category=category,
                        category_id=category_id,
                        icon=tech.get("icon"),
                        website=website if website else None,
                        source_url=tech.get("sourceUrl", source_url),
                        detected_time=tech.get("detectedTime"),
                        is_theme=tech.get("theme", False),
                        is_plugin=tech.get("plugin", False),
                    ))
        
        return technologies
    
    async def detect_technologies(
        self,
        hostname: str,
        url: Optional[str] = None,
    ) -> List[WhatRunsTechnology]:
        """
        Detect technologies for a given hostname using the WhatRuns API.
        
        Args:
            hostname: The hostname to analyze (e.g., "sub.example.com")
            url: Optional full URL to analyze (defaults to https://{hostname}/)
            
        Returns:
            List of detected technologies
        """
        # Rate limiting
        import time
        now = time.time()
        if now - self._last_request_time < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - (now - self._last_request_time))
        
        # Build request data
        request_data = self._build_request_data(hostname, url)
        
        # Set up headers to mimic the browser extension request
        headers = {
            "Host": "www.whatruns.com",
            "User-Agent": self.user_agent,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "*/*",
            "Origin": "chrome-extension://cmkdbmfndkfgebldhnkbfhlneefdaaip",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        }
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                verify=False  # WhatRuns uses standard HTTPS
            ) as client:
                response = await client.post(
                    self.API_URL,
                    content=request_data,
                    headers=headers,
                )
                
                self._last_request_time = time.time()
                
                if response.status_code != 200:
                    logger.warning(
                        f"WhatRuns API returned status {response.status_code} for {hostname}"
                    )
                    return []
                
                response_data = response.json()
                return self._parse_response(response_data, url or f"https://{hostname}/")
                
        except httpx.TimeoutException:
            logger.warning(f"WhatRuns API timeout for {hostname}")
            return []
        except Exception as e:
            logger.error(f"WhatRuns API error for {hostname}: {e}")
            return []
    
    def detect_technologies_sync(
        self,
        hostname: str,
        url: Optional[str] = None,
    ) -> List[WhatRunsTechnology]:
        """Synchronous wrapper for detect_technologies."""
        return asyncio.run(self.detect_technologies(hostname, url))
    
    async def detect_technologies_batch(
        self,
        hostnames: List[str],
        max_concurrent: int = 5,
    ) -> Dict[str, List[WhatRunsTechnology]]:
        """
        Detect technologies for multiple hostnames.
        
        Args:
            hostnames: List of hostnames to analyze
            max_concurrent: Maximum concurrent requests
            
        Returns:
            Dictionary mapping hostname to list of detected technologies
        """
        results = {}
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_host(hostname: str):
            async with semaphore:
                techs = await self.detect_technologies(hostname)
                results[hostname] = techs
        
        tasks = [scan_host(h) for h in hostnames]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return results


# Singleton instance
_whatruns_service: Optional[WhatRunsService] = None


def get_whatruns_service() -> WhatRunsService:
    """Get singleton WhatRuns service instance."""
    global _whatruns_service
    if _whatruns_service is None:
        _whatruns_service = WhatRunsService()
    return _whatruns_service


# For testing
if __name__ == "__main__":
    import asyncio
    
    async def test():
        service = WhatRunsService()
        techs = await service.detect_technologies(
            "plex.my.site.com",
            "https://plex.my.site.com/community/s/login/"
        )
        
        print(f"\nFound {len(techs)} technologies:")
        for tech in techs:
            print(f"  - {tech.name} ({tech.category})")
            if tech.website:
                print(f"    Website: {tech.website}")
    
    asyncio.run(test())
