"""
Wappalyzer integration service for technology fingerprinting.

This service implements technology detection similar to Wappalyzer
(https://github.com/tomnomnom/wappalyzer) by analyzing:
- HTTP headers
- HTML content
- JavaScript variables
- Meta tags
- Cookies
"""

import re
import json
import logging
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class DetectedTechnology:
    """A detected technology."""
    name: str
    slug: str
    confidence: int = 100
    version: Optional[str] = None
    categories: list[str] = field(default_factory=list)
    website: Optional[str] = None
    icon: Optional[str] = None
    cpe: Optional[str] = None


# Built-in technology fingerprints (subset of Wappalyzer patterns)
# In production, load from wappalyzer/src/technologies/*.json
TECHNOLOGY_FINGERPRINTS = {
    "WordPress": {
        "cats": ["CMS", "Blog"],
        "headers": {"X-Powered-By": r"WordPress"},
        "meta": {"generator": r"WordPress(?:\s([\d.]+))?"},
        "html": [r"wp-content/", r"wp-includes/"],
        "icon": "WordPress.svg",
        "website": "https://wordpress.org",
        "cpe": "cpe:2.3:a:wordpress:wordpress"
    },
    "Nginx": {
        "cats": ["Web servers"],
        "headers": {"Server": r"nginx(?:/([\d.]+))?"},
        "icon": "Nginx.svg",
        "website": "https://nginx.org",
        "cpe": "cpe:2.3:a:nginx:nginx"
    },
    "Apache": {
        "cats": ["Web servers"],
        "headers": {"Server": r"Apache(?:/([\d.]+))?"},
        "icon": "Apache.svg",
        "website": "https://apache.org",
        "cpe": "cpe:2.3:a:apache:http_server"
    },
    "Microsoft IIS": {
        "cats": ["Web servers"],
        "headers": {"Server": r"Microsoft-IIS(?:/([\d.]+))?"},
        "icon": "Microsoft.svg",
        "website": "https://www.iis.net",
        "cpe": "cpe:2.3:a:microsoft:iis"
    },
    "PHP": {
        "cats": ["Programming languages"],
        "headers": {"X-Powered-By": r"PHP(?:/([\d.]+))?", "Server": r"PHP(?:/([\d.]+))?"},
        "cookies": {"PHPSESSID": ""},
        "icon": "PHP.svg",
        "website": "https://php.net",
        "cpe": "cpe:2.3:a:php:php"
    },
    "ASP.NET": {
        "cats": ["Programming languages", "Web frameworks"],
        "headers": {"X-AspNet-Version": r"([\d.]+)", "X-Powered-By": r"ASP\.NET"},
        "cookies": {"ASP.NET_SessionId": "", "ASPSESSIONID": ""},
        "icon": "Microsoft.svg",
        "website": "https://dotnet.microsoft.com/apps/aspnet",
        "cpe": "cpe:2.3:a:microsoft:asp.net"
    },
    "jQuery": {
        "cats": ["JavaScript libraries"],
        "scriptSrc": [r"jquery[.-]?([\d.]+)?(?:\.min)?\.js"],
        "html": [r"<script[^>]+jquery"],
        "icon": "jQuery.svg",
        "website": "https://jquery.com",
        "cpe": "cpe:2.3:a:jquery:jquery"
    },
    "Bootstrap": {
        "cats": ["UI frameworks"],
        "html": [r"<link[^>]+bootstrap(?:[.-]([\d.]+))?(?:\.min)?\.css"],
        "scriptSrc": [r"bootstrap(?:[.-]([\d.]+))?(?:\.min)?\.js"],
        "icon": "Bootstrap.svg",
        "website": "https://getbootstrap.com"
    },
    "React": {
        "cats": ["JavaScript frameworks"],
        "html": [r"data-reactroot", r"data-reactid"],
        "scriptSrc": [r"react(?:\.production)?(?:\.min)?\.js"],
        "icon": "React.svg",
        "website": "https://reactjs.org"
    },
    "Vue.js": {
        "cats": ["JavaScript frameworks"],
        "html": [r"data-v-[a-f0-9]+", r"<[^>]+v-(?:if|for|bind|on)"],
        "scriptSrc": [r"vue(?:[.-]([\d.]+))?(?:\.min)?\.js"],
        "icon": "Vue.js.svg",
        "website": "https://vuejs.org"
    },
    "Angular": {
        "cats": ["JavaScript frameworks"],
        "html": [r"<[^>]+ng-(?:app|controller|model)", r"ng-version=\"([\d.]+)\""],
        "scriptSrc": [r"angular(?:[.-]([\d.]+))?(?:\.min)?\.js"],
        "icon": "Angular.svg",
        "website": "https://angular.io"
    },
    "Drupal": {
        "cats": ["CMS"],
        "headers": {"X-Drupal-Cache": "", "X-Generator": r"Drupal(?:\s([\d.]+))?"},
        "meta": {"generator": r"Drupal(?:\s([\d.]+))?"},
        "html": [r"drupal\.js", r"Drupal\.settings"],
        "icon": "Drupal.svg",
        "website": "https://drupal.org",
        "cpe": "cpe:2.3:a:drupal:drupal"
    },
    "Joomla": {
        "cats": ["CMS"],
        "meta": {"generator": r"Joomla(?:!)?(?:\s([\d.]+))?"},
        "html": [r"/media/jui/", r"/media/system/js/"],
        "icon": "Joomla.svg",
        "website": "https://joomla.org",
        "cpe": "cpe:2.3:a:joomla:joomla"
    },
    "Shopify": {
        "cats": ["Ecommerce"],
        "headers": {"X-ShopId": "", "X-Shopify-Stage": ""},
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "icon": "Shopify.svg",
        "website": "https://shopify.com"
    },
    "Magento": {
        "cats": ["Ecommerce"],
        "cookies": {"frontend": ""},
        "html": [r"/skin/frontend/", r"Mage\.Cookies", r"mage/cookies"],
        "icon": "Magento.svg",
        "website": "https://magento.com",
        "cpe": "cpe:2.3:a:magento:magento"
    },
    "WooCommerce": {
        "cats": ["Ecommerce"],
        "meta": {"generator": r"WooCommerce(?:\s([\d.]+))?"},
        "html": [r"woocommerce", r"wc-"],
        "icon": "WooCommerce.svg",
        "website": "https://woocommerce.com"
    },
    "Google Analytics": {
        "cats": ["Analytics"],
        "html": [r"google-analytics\.com/(?:ga|analytics)\.js", r"googletagmanager\.com/gtag/js"],
        "scriptSrc": [r"google-analytics\.com", r"googletagmanager\.com"],
        "icon": "Google Analytics.svg",
        "website": "https://google.com/analytics"
    },
    "Google Tag Manager": {
        "cats": ["Tag managers"],
        "html": [r"googletagmanager\.com/gtm\.js"],
        "icon": "Google Tag Manager.svg",
        "website": "https://tagmanager.google.com"
    },
    "Cloudflare": {
        "cats": ["CDN", "Security"],
        "headers": {"CF-RAY": "", "Server": r"cloudflare"},
        "cookies": {"__cfduid": "", "__cf_bm": ""},
        "icon": "CloudFlare.svg",
        "website": "https://cloudflare.com"
    },
    "Amazon Web Services": {
        "cats": ["PaaS", "IaaS"],
        "headers": {"X-Amz-Cf-Id": "", "X-Amz-Request-Id": ""},
        "html": [r"\.amazonaws\.com", r"s3\.amazonaws\.com"],
        "icon": "Amazon Web Services.svg",
        "website": "https://aws.amazon.com"
    },
    "Varnish": {
        "cats": ["Caching"],
        "headers": {"Via": r"varnish", "X-Varnish": ""},
        "icon": "Varnish.svg",
        "website": "https://varnish-cache.org",
        "cpe": "cpe:2.3:a:varnish-cache:varnish"
    },
    "Redis": {
        "cats": ["Databases", "Caching"],
        "headers": {"X-Redis": ""},
        "icon": "Redis.svg",
        "website": "https://redis.io",
        "cpe": "cpe:2.3:a:redis:redis"
    },
    "Laravel": {
        "cats": ["Web frameworks"],
        "cookies": {"laravel_session": "", "XSRF-TOKEN": ""},
        "headers": {"X-Powered-By": r"Laravel"},
        "icon": "Laravel.svg",
        "website": "https://laravel.com"
    },
    "Django": {
        "cats": ["Web frameworks"],
        "cookies": {"csrftoken": "", "django_language": ""},
        "headers": {"X-Frame-Options": r"SAMEORIGIN"},
        "html": [r"__admin_media_prefix__", r"csrfmiddlewaretoken"],
        "icon": "Django.svg",
        "website": "https://djangoproject.com"
    },
    "Express": {
        "cats": ["Web frameworks"],
        "headers": {"X-Powered-By": r"Express"},
        "icon": "Express.svg",
        "website": "https://expressjs.com"
    },
    "Ruby on Rails": {
        "cats": ["Web frameworks"],
        "headers": {"X-Powered-By": r"Phusion Passenger", "Server": r"Phusion Passenger"},
        "cookies": {"_session_id": ""},
        "meta": {"csrf-param": r"authenticity_token"},
        "icon": "Ruby on Rails.svg",
        "website": "https://rubyonrails.org"
    },
    "Next.js": {
        "cats": ["Web frameworks", "Static site generator"],
        "headers": {"X-Powered-By": r"Next\.js"},
        "html": [r"/_next/", r"__NEXT_DATA__"],
        "icon": "Next.js.svg",
        "website": "https://nextjs.org"
    },
    "Nuxt.js": {
        "cats": ["Web frameworks", "Static site generator"],
        "html": [r"/_nuxt/", r"__NUXT__"],
        "meta": {"generator": r"Nuxt"},
        "icon": "Nuxt.js.svg",
        "website": "https://nuxtjs.org"
    },
    "Gatsby": {
        "cats": ["Static site generator"],
        "meta": {"generator": r"Gatsby(?:\s([\d.]+))?"},
        "html": [r"gatsby-"],
        "icon": "Gatsby.svg",
        "website": "https://gatsbyjs.com"
    },
    "Tailwind CSS": {
        "cats": ["UI frameworks"],
        "html": [r"class=\"[^\"]*(?:tw-|md:|lg:|xl:|sm:)"],
        "icon": "Tailwind CSS.svg",
        "website": "https://tailwindcss.com"
    },
    "Font Awesome": {
        "cats": ["Font scripts"],
        "html": [r"fontawesome", r"font-awesome", r"class=\"fa[bsrl]?\s+fa-"],
        "scriptSrc": [r"fontawesome"],
        "icon": "Font Awesome.svg",
        "website": "https://fontawesome.com"
    },
    "reCAPTCHA": {
        "cats": ["Security"],
        "html": [r"google\.com/recaptcha", r"grecaptcha"],
        "scriptSrc": [r"recaptcha"],
        "icon": "reCAPTCHA.svg",
        "website": "https://google.com/recaptcha"
    },
    "Hotjar": {
        "cats": ["Analytics"],
        "html": [r"static\.hotjar\.com"],
        "scriptSrc": [r"hotjar\.com"],
        "icon": "Hotjar.svg",
        "website": "https://hotjar.com"
    },
    "Stripe": {
        "cats": ["Payment processors"],
        "html": [r"js\.stripe\.com"],
        "scriptSrc": [r"stripe\.com"],
        "icon": "Stripe.svg",
        "website": "https://stripe.com"
    },
    "PayPal": {
        "cats": ["Payment processors"],
        "html": [r"paypal\.com/sdk/js", r"paypalobjects\.com"],
        "icon": "PayPal.svg",
        "website": "https://paypal.com"
    },
    "Intercom": {
        "cats": ["Live chat"],
        "html": [r"widget\.intercom\.io", r"intercomSettings"],
        "icon": "Intercom.svg",
        "website": "https://intercom.com"
    },
    "Zendesk": {
        "cats": ["Live chat", "Helpdesk"],
        "html": [r"static\.zdassets\.com", r"zendesk"],
        "icon": "Zendesk.svg",
        "website": "https://zendesk.com"
    },
    "HubSpot": {
        "cats": ["Marketing automation", "CRM"],
        "html": [r"js\.hs-scripts\.com", r"js\.hubspot\.com"],
        "cookies": {"hubspotutk": "", "__hstc": ""},
        "icon": "HubSpot.svg",
        "website": "https://hubspot.com"
    },
    "Salesforce": {
        "cats": ["CRM"],
        "html": [r"force\.com", r"salesforce\.com"],
        "cookies": {"sfdc-stream": ""},
        "icon": "Salesforce.svg",
        "website": "https://salesforce.com"
    },
    "Akamai": {
        "cats": ["CDN"],
        "headers": {"X-Akamai-Transformed": ""},
        "html": [r"akamaihd\.net", r"akamai\.net"],
        "icon": "Akamai.svg",
        "website": "https://akamai.com"
    },
    "Fastly": {
        "cats": ["CDN"],
        "headers": {"X-Served-By": r"cache-", "Via": r"varnish"},
        "icon": "Fastly.svg",
        "website": "https://fastly.com"
    },
    "LiteSpeed": {
        "cats": ["Web servers"],
        "headers": {"Server": r"LiteSpeed"},
        "icon": "LiteSpeed.svg",
        "website": "https://litespeedtech.com"
    },
    "OpenSSL": {
        "cats": ["Web server extensions"],
        "headers": {"Server": r"OpenSSL(?:/([\d.]+[a-z]?))?"},
        "icon": "OpenSSL.svg",
        "website": "https://openssl.org",
        "cpe": "cpe:2.3:a:openssl:openssl"
    },
    "mod_ssl": {
        "cats": ["Web server extensions"],
        "headers": {"Server": r"mod_ssl(?:/([\d.]+))?"},
        "icon": "Apache.svg",
        "website": "https://modssl.org"
    },
}


def slugify(name: str) -> str:
    """Convert technology name to URL-safe slug."""
    slug = name.lower()
    slug = re.sub(r'[^a-z0-9]+', '-', slug)
    slug = slug.strip('-')
    return slug


class WappalyzerService:
    """
    Service for detecting web technologies using Wappalyzer-style fingerprinting.
    
    Based on the Wappalyzer project: https://github.com/tomnomnom/wappalyzer
    """
    
    def __init__(
        self,
        fingerprints: Optional[dict] = None,
        timeout: float = 10.0,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    ):
        """
        Initialize Wappalyzer service.
        
        Args:
            fingerprints: Custom technology fingerprints (defaults to built-in)
            timeout: HTTP request timeout
            user_agent: User agent for HTTP requests
        """
        self.fingerprints = fingerprints or TECHNOLOGY_FINGERPRINTS
        self.timeout = timeout
        self.user_agent = user_agent
    
    async def analyze_url(self, url: str) -> list[DetectedTechnology]:
        """
        Analyze a URL and detect technologies.
        
        Args:
            url: URL to analyze
            
        Returns:
            List of detected technologies
        """
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False
            ) as client:
                response = await client.get(
                    url,
                    headers={"User-Agent": self.user_agent}
                )
                
                return self._analyze_response(response)
                
        except Exception as e:
            logger.error(f"Error analyzing {url}: {e}")
            return []
    
    def analyze_url_sync(self, url: str) -> list[DetectedTechnology]:
        """Synchronous wrapper for analyze_url."""
        import asyncio
        return asyncio.run(self.analyze_url(url))
    
    def _analyze_response(self, response: httpx.Response) -> list[DetectedTechnology]:
        """
        Analyze HTTP response for technologies.
        
        Args:
            response: httpx Response object
            
        Returns:
            List of detected technologies
        """
        detected = {}
        
        # Parse HTML
        html = response.text
        headers = dict(response.headers)
        cookies = {c.name: c.value for c in response.cookies.jar}
        
        # Parse meta tags
        meta_tags = self._extract_meta_tags(html)
        
        # Extract script sources
        script_sources = self._extract_script_sources(html)
        
        # Check each technology fingerprint
        for tech_name, fingerprint in self.fingerprints.items():
            confidence = 0
            version = None
            
            # Check headers
            if "headers" in fingerprint:
                header_match = self._check_headers(headers, fingerprint["headers"])
                if header_match:
                    confidence = max(confidence, header_match["confidence"])
                    version = version or header_match.get("version")
            
            # Check HTML patterns
            if "html" in fingerprint:
                html_match = self._check_patterns(html, fingerprint["html"])
                if html_match:
                    confidence = max(confidence, html_match["confidence"])
                    version = version or html_match.get("version")
            
            # Check meta tags
            if "meta" in fingerprint:
                meta_match = self._check_meta(meta_tags, fingerprint["meta"])
                if meta_match:
                    confidence = max(confidence, meta_match["confidence"])
                    version = version or meta_match.get("version")
            
            # Check cookies
            if "cookies" in fingerprint:
                cookie_match = self._check_cookies(cookies, fingerprint["cookies"])
                if cookie_match:
                    confidence = max(confidence, cookie_match["confidence"])
            
            # Check script sources
            if "scriptSrc" in fingerprint:
                script_match = self._check_patterns(
                    " ".join(script_sources),
                    fingerprint["scriptSrc"]
                )
                if script_match:
                    confidence = max(confidence, script_match["confidence"])
                    version = version or script_match.get("version")
            
            # If detected, add to results
            if confidence > 0:
                detected[tech_name] = DetectedTechnology(
                    name=tech_name,
                    slug=slugify(tech_name),
                    confidence=confidence,
                    version=version,
                    categories=fingerprint.get("cats", []),
                    website=fingerprint.get("website"),
                    icon=fingerprint.get("icon"),
                    cpe=fingerprint.get("cpe")
                )
        
        return list(detected.values())
    
    def _check_headers(self, headers: dict, patterns: dict) -> Optional[dict]:
        """Check HTTP headers against patterns."""
        result = None
        
        for header_name, pattern in patterns.items():
            header_value = headers.get(header_name.lower(), "")
            if not header_value:
                continue
            
            if not pattern:  # Empty pattern means just check existence
                return {"confidence": 100}
            
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                result = {"confidence": 100}
                if match.groups():
                    result["version"] = match.group(1)
                return result
        
        return result
    
    def _check_patterns(self, content: str, patterns: list) -> Optional[dict]:
        """Check content against regex patterns."""
        for pattern in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                result = {"confidence": 100}
                if match.groups():
                    result["version"] = match.group(1)
                return result
        return None
    
    def _check_meta(self, meta_tags: dict, patterns: dict) -> Optional[dict]:
        """Check meta tags against patterns."""
        for meta_name, pattern in patterns.items():
            meta_value = meta_tags.get(meta_name.lower(), "")
            if not meta_value:
                continue
            
            if not pattern:
                return {"confidence": 100}
            
            match = re.search(pattern, meta_value, re.IGNORECASE)
            if match:
                result = {"confidence": 100}
                if match.groups():
                    result["version"] = match.group(1)
                return result
        
        return None
    
    def _check_cookies(self, cookies: dict, patterns: dict) -> Optional[dict]:
        """Check cookies against patterns."""
        for cookie_name, pattern in patterns.items():
            # Check for cookie existence (case-insensitive)
            for name in cookies:
                if name.lower() == cookie_name.lower():
                    if not pattern:
                        return {"confidence": 100}
                    if re.search(pattern, cookies[name], re.IGNORECASE):
                        return {"confidence": 100}
        return None
    
    def _extract_meta_tags(self, html: str) -> dict:
        """Extract meta tag names and content from HTML."""
        meta_tags = {}
        try:
            soup = BeautifulSoup(html, 'lxml')
            for tag in soup.find_all('meta'):
                name = tag.get('name', tag.get('property', '')).lower()
                content = tag.get('content', '')
                if name and content:
                    meta_tags[name] = content
        except Exception:
            pass
        return meta_tags
    
    def _extract_script_sources(self, html: str) -> list[str]:
        """Extract script src attributes from HTML."""
        sources = []
        try:
            soup = BeautifulSoup(html, 'lxml')
            for tag in soup.find_all('script', src=True):
                sources.append(tag['src'])
        except Exception:
            pass
        return sources
    
    def get_technology_categories(self, technologies: list[DetectedTechnology]) -> dict[str, list[str]]:
        """
        Group detected technologies by category.
        
        Args:
            technologies: List of detected technologies
            
        Returns:
            Dictionary mapping category names to technology names
        """
        categories = {}
        for tech in technologies:
            for cat in tech.categories:
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(tech.name)
        return categories















