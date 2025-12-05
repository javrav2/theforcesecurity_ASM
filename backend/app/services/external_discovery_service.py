"""
External Discovery Service

Integrates multiple external intelligence sources for comprehensive asset discovery:
- WhoisXML API - IP/CIDR ranges by organization name
- Whoxy - Reverse WHOIS by registration email
- VirusTotal - Subdomain enumeration
- AlienVault OTX - Passive DNS and URL data
- Wayback Machine - Historical subdomains
- RapidDNS - Subdomain enumeration
- Common Crawl - Web crawl data
- Microsoft 365 - Federated domain discovery
- ASN Discovery - BGP/ASN data for organizations

Based on HISAC discovery scripts.
"""

import asyncio
import logging
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Set, Tuple
import json

import httpx
from sqlalchemy.orm import Session

from app.models.api_config import APIConfig, ExternalService, DEFAULT_RATE_LIMITS

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryResult:
    """Result from an external discovery source."""
    source: str
    success: bool
    domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)  # CIDRs
    asns: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    error: Optional[str] = None
    raw_data: Optional[Dict] = None
    elapsed_time: float = 0.0


class ExternalDiscoveryService:
    """
    Service for discovering assets using external intelligence sources.
    """
    
    def __init__(self, db: Session, organization_id: int):
        """
        Initialize the external discovery service.
        
        Args:
            db: Database session
            organization_id: Organization to use API configs from
        """
        self.db = db
        self.organization_id = organization_id
        self._api_configs: Dict[str, APIConfig] = {}
        self._load_api_configs()
    
    def _load_api_configs(self):
        """Load API configurations for the organization."""
        configs = self.db.query(APIConfig).filter(
            APIConfig.organization_id == self.organization_id,
            APIConfig.is_active == True
        ).all()
        
        for config in configs:
            self._api_configs[config.service_name] = config
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service."""
        config = self._api_configs.get(service)
        if config:
            return config.get_api_key()
        return None
    
    def get_config(self, service: str) -> Optional[Dict]:
        """Get service-specific configuration."""
        config = self._api_configs.get(service)
        if config:
            return config.config
        return {}
    
    async def _make_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        data: Optional[str] = None,
        timeout: int = 30
    ) -> Tuple[bool, Any]:
        """Make an HTTP request with error handling."""
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                if method == "GET":
                    response = await client.get(url, headers=headers, params=params)
                else:
                    response = await client.post(url, headers=headers, data=data)
                
                if response.status_code == 200:
                    try:
                        return True, response.json()
                    except:
                        return True, response.text
                else:
                    return False, f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as e:
            return False, str(e)

    # =========================================================================
    # WhoisXML API - IP/CIDR Ranges by Organization
    # =========================================================================
    
    async def discover_whoisxml(
        self,
        organization_names: Optional[List[str]] = None
    ) -> DiscoveryResult:
        """
        Discover IP ranges and CIDRs using WhoisXML API based on organization names.
        
        Args:
            organization_names: List of organization names to search for
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.WHOISXML, success=False)
        
        api_key = self.get_api_key(ExternalService.WHOISXML)
        if not api_key:
            result.error = "WhoisXML API key not configured"
            return result
        
        config = self.get_config(ExternalService.WHOISXML)
        org_names = organization_names or config.get("organization_names", [])
        
        if not org_names:
            result.error = "No organization names configured"
            return result
        
        url = "https://ip-netblocks.whoisxmlapi.com/api/v2"
        
        all_ips = set()
        all_cidrs = set()
        
        for org_name in org_names:
            try:
                params = {
                    "apiKey": api_key,
                    "org[]": org_name,
                    "limit": 1000
                }
                
                success, data = await self._make_request(url, params=params)
                
                if not success:
                    logger.warning(f"WhoisXML error for {org_name}: {data}")
                    continue
                
                if "result" in data and "inetnums" in data["result"]:
                    for inetnum in data["result"]["inetnums"]:
                        if "org" not in inetnum:
                            continue
                        
                        org = inetnum.get("org", {})
                        org_name_found = org.get("name", "").lower()
                        org_email = org.get("email", "").lower()
                        
                        # Verify this matches our organization
                        org_search = org_name.lower()
                        if org_search not in org_name_found and org_search not in org_email:
                            continue
                        
                        inetnum_value = inetnum.get("inetnum", "")
                        if ":" in inetnum_value:  # Skip IPv6
                            continue
                        
                        # Parse IP range
                        if " - " in inetnum_value:
                            first, last = inetnum_value.split(" - ")
                            # Convert to CIDR(s)
                            cidrs = self._ip_range_to_cidrs(first.strip(), last.strip())
                            all_cidrs.update(cidrs)
                            # Also expand to individual IPs for small ranges
                            ips = self._expand_ip_range(first.strip(), last.strip())
                            all_ips.update(ips)
                
                await asyncio.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                logger.error(f"WhoisXML error for {org_name}: {e}")
        
        result.success = True
        result.ip_addresses = list(all_ips)
        result.ip_ranges = list(all_cidrs)
        result.elapsed_time = time.time() - start_time
        
        return result
    
    def _ip_range_to_cidrs(self, first: str, last: str) -> List[str]:
        """Convert IP range to CIDR notation."""
        try:
            import ipaddress
            first_ip = ipaddress.IPv4Address(first)
            last_ip = ipaddress.IPv4Address(last)
            
            cidrs = []
            for cidr in ipaddress.summarize_address_range(first_ip, last_ip):
                cidrs.append(str(cidr))
            return cidrs
        except Exception as e:
            logger.warning(f"Could not convert IP range {first}-{last}: {e}")
            return []
    
    def _expand_ip_range(self, first: str, last: str, max_ips: int = 256) -> List[str]:
        """Expand IP range to individual IPs (limited to max_ips)."""
        try:
            import ipaddress
            first_ip = ipaddress.IPv4Address(first)
            last_ip = ipaddress.IPv4Address(last)
            
            count = int(last_ip) - int(first_ip) + 1
            if count > max_ips:
                return []  # Too large to expand
            
            ips = []
            current = first_ip
            while current <= last_ip:
                # Skip network and broadcast addresses for /24 and larger
                ips.append(str(current))
                current += 1
            return ips
        except Exception as e:
            logger.warning(f"Could not expand IP range {first}-{last}: {e}")
            return []

    # =========================================================================
    # Whoxy - Reverse WHOIS by Email
    # =========================================================================
    
    async def discover_whoxy(
        self,
        registration_emails: Optional[List[str]] = None
    ) -> DiscoveryResult:
        """
        Discover domains using Whoxy reverse WHOIS by registration email.
        
        Args:
            registration_emails: List of email addresses used for domain registration
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.WHOXY, success=False)
        
        api_key = self.get_api_key(ExternalService.WHOXY)
        if not api_key:
            result.error = "Whoxy API key not configured"
            return result
        
        config = self.get_config(ExternalService.WHOXY)
        emails = registration_emails or config.get("registration_emails", [])
        
        if not emails:
            result.error = "No registration emails configured"
            return result
        
        base_url = "https://api.whoxy.com"
        all_domains = set()
        
        for email in emails:
            try:
                # Get first page to find total pages
                params = {
                    "key": api_key,
                    "reverse": "whois",
                    "email": email,
                    "mode": "micro",
                    "page": 1
                }
                
                success, data = await self._make_request(f"{base_url}/", params=params)
                
                if not success:
                    logger.warning(f"Whoxy error for {email}: {data}")
                    continue
                
                total_pages = data.get("total_pages", 1)
                
                # Process first page
                if "search_result" in data:
                    for item in data["search_result"]:
                        domain = item.get("domain_name", "")
                        if domain:
                            all_domains.add(domain.lower())
                
                # Get remaining pages
                for page in range(2, min(total_pages + 1, 20)):  # Limit to 20 pages
                    params["page"] = page
                    success, page_data = await self._make_request(f"{base_url}/", params=params)
                    
                    if success and "search_result" in page_data:
                        for item in page_data["search_result"]:
                            domain = item.get("domain_name", "")
                            if domain:
                                all_domains.add(domain.lower())
                    
                    await asyncio.sleep(0.5)  # Rate limiting
                
            except Exception as e:
                logger.error(f"Whoxy error for {email}: {e}")
        
        result.success = True
        result.domains = list(all_domains)
        result.elapsed_time = time.time() - start_time
        
        return result

    # =========================================================================
    # VirusTotal - Subdomain Enumeration
    # =========================================================================
    
    async def discover_virustotal(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains using VirusTotal API.
        
        Args:
            domain: Domain to search for subdomains
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.VIRUSTOTAL, success=False)
        
        api_key = self.get_api_key(ExternalService.VIRUSTOTAL)
        if not api_key:
            result.error = "VirusTotal API key not configured"
            return result
        
        # Using v2 API as it returns up to 100 subdomains in one request
        url = f"https://www.virustotal.com/vtapi/v2/domain/report"
        params = {
            "apikey": api_key,
            "domain": domain
        }
        
        try:
            success, data = await self._make_request(url, params=params)
            
            if not success:
                result.error = f"VirusTotal error: {data}"
                return result
            
            if isinstance(data, dict):
                if "error" in data:
                    result.error = data["error"]
                    return result
                
                subdomains = data.get("subdomains", [])
                if subdomains:
                    result.subdomains = [s.lower() for s in subdomains]
                    result.success = True
                else:
                    result.success = True  # No error, just no subdomains
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # AlienVault OTX - Passive DNS
    # =========================================================================
    
    async def discover_otx(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains using AlienVault OTX passive DNS and URL data.
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.OTX, success=False)
        
        api_key = self.get_api_key(ExternalService.OTX)
        if not api_key:
            result.error = "OTX API key not configured"
            return result
        
        base_url = "https://otx.alienvault.com/api/v1"
        headers = {"X-OTX-API-KEY": api_key}
        
        all_subdomains = set()
        
        try:
            # Encode domain for punycode
            try:
                punycode_domain = domain.encode("idna").decode()
            except:
                punycode_domain = domain
            
            # Get passive DNS data
            url = f"{base_url}/indicators/domain/{punycode_domain}/passive_dns"
            success, data = await self._make_request(url, headers=headers)
            
            if success and "passive_dns" in data:
                for record in data["passive_dns"]:
                    hostname = record.get("hostname", "").lower()
                    if hostname.endswith(f".{domain}"):
                        all_subdomains.add(hostname)
            
            await asyncio.sleep(0.5)
            
            # Get URL list data
            url = f"{base_url}/indicators/domain/{punycode_domain}/url_list"
            success, data = await self._make_request(url, headers=headers)
            
            if success and "url_list" in data:
                for record in data["url_list"]:
                    hostname = record.get("hostname", "").lower()
                    if hostname.endswith(f".{domain}"):
                        all_subdomains.add(hostname)
            
            result.success = True
            result.subdomains = list(all_subdomains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # Wayback Machine - Historical Subdomains
    # =========================================================================
    
    async def discover_wayback(self, domain: str) -> DiscoveryResult:
        """
        Discover historical subdomains from Wayback Machine.
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.WAYBACK, success=False)
        
        url = f"http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{domain}/*",
            "output": "txt",
            "fl": "original",
            "collapse": "urlkey"
        }
        
        try:
            success, data = await self._make_request(url, params=params, timeout=60)
            
            if not success:
                result.error = f"Wayback error: {data}"
                return result
            
            all_subdomains = set()
            
            if isinstance(data, str):
                lines = data.strip().split("\n")
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        parsed = urllib.parse.urlparse(line)
                        hostname = parsed.netloc.lower()
                        
                        # Remove port if present
                        if ":" in hostname:
                            hostname = hostname.split(":")[0]
                        
                        if hostname and hostname.endswith(f".{domain}"):
                            all_subdomains.add(hostname)
                    except:
                        continue
            
            result.success = True
            result.subdomains = list(all_subdomains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # RapidDNS - Subdomain Enumeration
    # =========================================================================
    
    async def discover_rapiddns(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains using RapidDNS.
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.RAPIDDNS, success=False)
        
        url = f"https://rapiddns.io/subdomain/{domain}"
        params = {"full": "1"}
        
        try:
            success, data = await self._make_request(url, params=params, timeout=30)
            
            if not success:
                result.error = f"RapidDNS error: {data}"
                return result
            
            all_subdomains = set()
            
            if isinstance(data, str):
                # Parse HTML response - look for subdomains in table
                # Simple regex extraction
                pattern = rf'<td>([a-zA-Z0-9][-a-zA-Z0-9]*\.{re.escape(domain)})</td>'
                matches = re.findall(pattern, data, re.IGNORECASE)
                
                for match in matches:
                    subdomain = match.lower()
                    if subdomain.endswith(f".{domain}"):
                        all_subdomains.add(subdomain)
            
            result.success = True
            result.subdomains = list(all_subdomains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # Microsoft 365 - Federated Domain Discovery
    # =========================================================================
    
    async def discover_m365(self, domain: str) -> DiscoveryResult:
        """
        Discover Microsoft 365 federated domains.
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.M365, success=False)
        
        # SOAP request to Microsoft autodiscover
        body = f"""<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
            xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <soap:Header>
            <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
            <a:MessageID>urn:uuid:6389558d-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
            <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
            <a:To soap:mustUnderstand="1">https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc</a:To>
            <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
        </soap:Header>
        <soap:Body>
            <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
            <Request>
                <Domain>{domain}</Domain>
            </Request>
            </GetFederationInformationRequestMessage>
        </soap:Body>
        </soap:Envelope>"""
        
        headers = {
            "Content-Type": "text/xml; charset=utf-8",
            "User-Agent": "AutodiscoverClient"
        }
        
        url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
        
        # Unrelated domains to filter out
        unrelated_domains = ["call2teams.com", "onmicrosoft.com", "audiocodesaas.com"]
        
        try:
            success, data = await self._make_request(
                url, method="POST", headers=headers, data=body, timeout=30
            )
            
            if not success:
                result.error = f"M365 error: {data}"
                return result
            
            all_domains = set()
            
            if isinstance(data, str):
                try:
                    tree = ET.fromstring(data)
                    ns = "{http://schemas.microsoft.com/exchange/2010/Autodiscover}"
                    
                    for elem in tree.iter(f"{ns}Domain"):
                        found_domain = elem.text.lower() if elem.text else ""
                        
                        # Filter out unrelated domains
                        skip = False
                        for unrelated in unrelated_domains:
                            if unrelated in found_domain:
                                skip = True
                                break
                        
                        if not skip and found_domain:
                            all_domains.add(found_domain)
                except ET.ParseError:
                    result.error = "Failed to parse M365 response"
                    return result
            
            result.success = True
            result.domains = list(all_domains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # crt.sh - Certificate Transparency
    # =========================================================================
    
    async def discover_crtsh(self, domain: str) -> DiscoveryResult:
        """
        Discover subdomains from certificate transparency logs (crt.sh).
        
        Args:
            domain: Domain to search
        """
        start_time = time.time()
        result = DiscoveryResult(source=ExternalService.CRTSH, success=False)
        
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            success, data = await self._make_request(url, timeout=60)
            
            if not success:
                result.error = f"crt.sh error: {data}"
                return result
            
            all_subdomains = set()
            
            if isinstance(data, list):
                for cert in data:
                    name_value = cert.get("name_value", "")
                    # Split by newlines (multiple names per cert)
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        # Remove wildcard prefix
                        if name.startswith("*."):
                            name = name[2:]
                        
                        if name.endswith(f".{domain}") or name == domain:
                            all_subdomains.add(name)
            
            result.success = True
            result.subdomains = list(all_subdomains)
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = time.time() - start_time
        return result

    # =========================================================================
    # Full Discovery - Run All Sources
    # =========================================================================
    
    async def full_discovery(
        self,
        domain: str,
        include_paid: bool = True,
        include_free: bool = True,
        organization_names: Optional[List[str]] = None,
        registration_emails: Optional[List[str]] = None
    ) -> Dict[str, DiscoveryResult]:
        """
        Run full discovery using all available sources.
        
        Args:
            domain: Primary domain to discover assets for
            include_paid: Include paid API sources
            include_free: Include free sources
            organization_names: Organization names for WHOIS lookups
            registration_emails: Emails for reverse WHOIS
            
        Returns:
            Dictionary of results by source
        """
        results = {}
        tasks = []
        
        # Free sources (always available)
        if include_free:
            tasks.append(("wayback", self.discover_wayback(domain)))
            tasks.append(("rapiddns", self.discover_rapiddns(domain)))
            tasks.append(("crtsh", self.discover_crtsh(domain)))
            tasks.append(("m365", self.discover_m365(domain)))
        
        # Paid sources (require API keys)
        if include_paid:
            if self.get_api_key(ExternalService.VIRUSTOTAL):
                tasks.append(("virustotal", self.discover_virustotal(domain)))
            
            if self.get_api_key(ExternalService.OTX):
                tasks.append(("otx", self.discover_otx(domain)))
            
            if self.get_api_key(ExternalService.WHOXY) and registration_emails:
                tasks.append(("whoxy", self.discover_whoxy(registration_emails)))
            
            if self.get_api_key(ExternalService.WHOISXML) and organization_names:
                tasks.append(("whoisxml", self.discover_whoisxml(organization_names)))
        
        # Run all tasks concurrently
        task_results = await asyncio.gather(
            *[t[1] for t in tasks],
            return_exceptions=True
        )
        
        # Map results to source names
        for i, (name, _) in enumerate(tasks):
            if isinstance(task_results[i], Exception):
                results[name] = DiscoveryResult(
                    source=name,
                    success=False,
                    error=str(task_results[i])
                )
            else:
                results[name] = task_results[i]
        
        return results
    
    def aggregate_results(
        self,
        results: Dict[str, DiscoveryResult],
        base_domain: str
    ) -> Dict[str, Set[str]]:
        """
        Aggregate results from all sources into deduplicated sets.
        
        Args:
            results: Results from full_discovery
            base_domain: Base domain for filtering
            
        Returns:
            Aggregated results with domains, subdomains, IPs, CIDRs
        """
        aggregated = {
            "domains": set(),
            "subdomains": set(),
            "ip_addresses": set(),
            "ip_ranges": set(),
            "asns": set(),
            "urls": set(),
        }
        
        for source, result in results.items():
            if not result.success:
                continue
            
            aggregated["domains"].update(result.domains)
            aggregated["subdomains"].update(result.subdomains)
            aggregated["ip_addresses"].update(result.ip_addresses)
            aggregated["ip_ranges"].update(result.ip_ranges)
            aggregated["asns"].update(result.asns)
            aggregated["urls"].update(result.urls)
        
        # Add base domain
        aggregated["domains"].add(base_domain)
        
        # Move exact domain matches from subdomains to domains
        to_move = []
        for sub in aggregated["subdomains"]:
            if sub == base_domain:
                to_move.append(sub)
        for sub in to_move:
            aggregated["subdomains"].remove(sub)
            aggregated["domains"].add(sub)
        
        return aggregated

