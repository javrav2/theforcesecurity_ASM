"""DNS Enrichment Service using WhoisXML API."""

import httpx
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class DNSEnrichmentService:
    """Service to enrich domains with DNS records from WhoisXML API."""
    
    BASE_URL = "https://www.whoisxmlapi.com/whoisserver/DNSService"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def get_dns_records(self, domain: str, record_types: str = "_all") -> Dict[str, Any]:
        """
        Fetch DNS records for a domain from WhoisXML API.
        
        Args:
            domain: The domain to look up
            record_types: Type of records to fetch (_all, A, AAAA, MX, NS, TXT, SOA, etc.)
            
        Returns:
            Dictionary containing parsed DNS records
        """
        try:
            params = {
                "apiKey": self.api_key,
                "domainName": domain,
                "type": record_types,
                "outputFormat": "JSON"
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(self.BASE_URL, params=params)
                response.raise_for_status()
                
                data = response.json()
                return self._parse_dns_response(data, domain)
                
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error fetching DNS for {domain}: {e}")
            return {"error": str(e), "domain": domain}
        except Exception as e:
            logger.error(f"Error fetching DNS for {domain}: {e}")
            return {"error": str(e), "domain": domain}
    
    def _parse_dns_response(self, data: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Parse the WhoisXML DNS response into a structured format."""
        result = {
            "domain": domain,
            "fetched_at": datetime.utcnow().isoformat(),
            "records": {
                "A": [],
                "AAAA": [],
                "MX": [],
                "NS": [],
                "TXT": [],
                "SOA": None,
                "CNAME": [],
            },
            "summary": {
                "has_mail": False,
                "mail_providers": [],
                "nameservers": [],
                "ip_addresses": [],
                "ipv6_addresses": [],
                "txt_verifications": [],
            }
        }
        
        dns_data = data.get("DNSData", data)
        dns_records = dns_data.get("dnsRecords", [])
        
        # Handle both list and dict formats
        if isinstance(dns_records, dict):
            # Flatten the nested structure
            all_records = []
            for key, value in dns_records.items():
                if isinstance(value, list):
                    all_records.extend(value)
                elif isinstance(value, dict):
                    all_records.append(value)
        else:
            all_records = dns_records
        
        for record in all_records:
            dns_type = record.get("dnsType", "")
            
            if dns_type == "A":
                addr = record.get("address")
                if addr:
                    result["records"]["A"].append({
                        "address": addr,
                        "ttl": record.get("ttl")
                    })
                    if addr not in result["summary"]["ip_addresses"]:
                        result["summary"]["ip_addresses"].append(addr)
                        
            elif dns_type == "AAAA":
                addr = record.get("address")
                if addr:
                    result["records"]["AAAA"].append({
                        "address": addr,
                        "ttl": record.get("ttl")
                    })
                    if addr not in result["summary"]["ipv6_addresses"]:
                        result["summary"]["ipv6_addresses"].append(addr)
                        
            elif dns_type == "MX":
                target = record.get("target", "")
                priority = record.get("priority", 0)
                result["records"]["MX"].append({
                    "target": target,
                    "priority": priority,
                    "ttl": record.get("ttl")
                })
                result["summary"]["has_mail"] = True
                # Extract mail provider from MX record
                if target:
                    provider = self._detect_mail_provider(target)
                    if provider and provider not in result["summary"]["mail_providers"]:
                        result["summary"]["mail_providers"].append(provider)
                        
            elif dns_type == "NS":
                target = record.get("target", "")
                if target:
                    result["records"]["NS"].append({
                        "target": target,
                        "ttl": record.get("ttl")
                    })
                    if target not in result["summary"]["nameservers"]:
                        result["summary"]["nameservers"].append(target)
                        
            elif dns_type == "TXT":
                strings = record.get("strings", [])
                raw_text = record.get("rawText", "")
                for txt in strings:
                    result["records"]["TXT"].append({
                        "value": txt,
                        "ttl": record.get("ttl")
                    })
                    # Detect verification records
                    verification = self._detect_txt_verification(txt)
                    if verification and verification not in result["summary"]["txt_verifications"]:
                        result["summary"]["txt_verifications"].append(verification)
                        
            elif dns_type == "SOA":
                result["records"]["SOA"] = {
                    "admin": record.get("admin"),
                    "host": record.get("host"),
                    "serial": record.get("serial"),
                    "refresh": record.get("refresh"),
                    "retry": record.get("retry"),
                    "expire": record.get("expire"),
                    "minimum": record.get("minimum"),
                    "ttl": record.get("ttl")
                }
                
            elif dns_type == "CNAME":
                target = record.get("target", "")
                if target:
                    result["records"]["CNAME"].append({
                        "target": target,
                        "ttl": record.get("ttl")
                    })
        
        return result
    
    def _detect_mail_provider(self, mx_target: str) -> Optional[str]:
        """Detect the mail provider from an MX record."""
        mx_lower = mx_target.lower()
        
        providers = {
            "google": ["google.com", "googlemail.com", "aspmx.l.google.com"],
            "microsoft": ["outlook.com", "protection.outlook.com", "mail.protection.outlook.com"],
            "proofpoint": ["pphosted.com", "proofpoint.com"],
            "mimecast": ["mimecast.com"],
            "barracuda": ["barracudanetworks.com"],
            "messagelabs": ["messagelabs.com", "symantec.com"],
            "mailchimp": ["mailchimp.com"],
            "sendgrid": ["sendgrid.net"],
            "amazon_ses": ["amazonses.com", "amazonaws.com"],
            "zoho": ["zoho.com"],
            "fastmail": ["fastmail.com"],
            "rackspace": ["emailsrvr.com"],
            "godaddy": ["secureserver.net"],
        }
        
        for provider, domains in providers.items():
            for domain in domains:
                if domain in mx_lower:
                    return provider
        
        return None
    
    def _detect_txt_verification(self, txt_value: str) -> Optional[str]:
        """Detect known TXT verification records."""
        txt_lower = txt_value.lower()
        
        verifications = {
            "google-site-verification": "Google Site Verification",
            "ms=": "Microsoft 365",
            "docusign=": "DocuSign",
            "atlassian": "Atlassian",
            "facebook-domain-verification": "Facebook",
            "slack-domain-verification": "Slack",
            "apple-domain-verification": "Apple",
            "adobe-idp-site-verification": "Adobe",
            "hubspot-developer-verification": "HubSpot",
            "docker-verification": "Docker",
            "jamf-site-verification": "Jamf",
            "zendesk-domain-verification": "Zendesk",
            "stripe-verification": "Stripe",
            "v=spf1": "SPF Record",
            "v=dmarc1": "DMARC Record",
            "v=dkim1": "DKIM Record",
        }
        
        for pattern, name in verifications.items():
            if pattern in txt_lower:
                return name
        
        return None
    
    async def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """
        Full DNS enrichment for a domain.
        
        Returns all DNS records plus analysis.
        """
        dns_data = await self.get_dns_records(domain)
        
        if "error" in dns_data:
            return dns_data
        
        # Add analysis
        dns_data["analysis"] = {
            "is_active": bool(dns_data["summary"]["ip_addresses"] or dns_data["summary"]["ipv6_addresses"]),
            "has_email": dns_data["summary"]["has_mail"],
            "uses_cdn": self._detect_cdn(dns_data),
            "security_features": self._detect_security_features(dns_data),
        }
        
        return dns_data
    
    def _detect_cdn(self, dns_data: Dict[str, Any]) -> Optional[str]:
        """Detect if domain uses a CDN based on DNS records."""
        # Check nameservers and A records for CDN indicators
        nameservers = " ".join(dns_data["summary"].get("nameservers", []))
        ips = dns_data["summary"].get("ip_addresses", [])
        
        cdn_indicators = {
            "cloudflare": ["cloudflare"],
            "akamai": ["akamai", "akam"],
            "fastly": ["fastly"],
            "cloudfront": ["cloudfront", "amazonaws"],
            "azure_cdn": ["azureedge", "azure"],
            "google_cloud": ["googleusercontent", "google"],
            "stackpath": ["stackpath"],
            "sucuri": ["sucuri"],
        }
        
        for cdn, indicators in cdn_indicators.items():
            for indicator in indicators:
                if indicator in nameservers.lower():
                    return cdn
        
        return None
    
    def _detect_security_features(self, dns_data: Dict[str, Any]) -> List[str]:
        """Detect security features from DNS records."""
        features = []
        
        txt_records = dns_data.get("records", {}).get("TXT", [])
        for txt in txt_records:
            value = txt.get("value", "").lower()
            if "v=spf1" in value:
                features.append("SPF")
            if "v=dmarc1" in value:
                features.append("DMARC")
        
        # Check for DKIM (would need specific selector queries)
        verifications = dns_data.get("summary", {}).get("txt_verifications", [])
        if "DKIM Record" in verifications:
            features.append("DKIM")
        
        return features


async def enrich_domains_batch(
    domains: List[str],
    api_key: str,
    max_concurrent: int = 5
) -> Dict[str, Dict[str, Any]]:
    """
    Enrich multiple domains with DNS data.
    
    Args:
        domains: List of domain names
        api_key: WhoisXML API key
        max_concurrent: Maximum concurrent requests
        
    Returns:
        Dictionary mapping domain names to their DNS data
    """
    import asyncio
    
    service = DNSEnrichmentService(api_key)
    results = {}
    
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def enrich_with_limit(domain: str):
        async with semaphore:
            return domain, await service.enrich_domain(domain)
    
    tasks = [enrich_with_limit(domain) for domain in domains]
    completed = await asyncio.gather(*tasks, return_exceptions=True)
    
    for item in completed:
        if isinstance(item, Exception):
            logger.error(f"Error in batch enrichment: {item}")
            continue
        domain, data = item
        results[domain] = data
    
    return results
