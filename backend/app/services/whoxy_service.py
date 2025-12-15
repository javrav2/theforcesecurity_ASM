"""
Whoxy service for domain reconnaissance.

Performs WHOIS lookup and reverse WHOIS searches to find all related domains
by email and company attribution.

Based on: https://www.whoxy.com/
API Docs: https://www.whoxy.com/#api
"""

import logging
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
import httpx

logger = logging.getLogger(__name__)


class WhoxyService:
    """Handle all Whoxy API interactions for domain reconnaissance."""
    
    BASE_URL = "https://api.whoxy.com/"
    RATE_LIMIT_DELAY = 1.5  # seconds between requests
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    async def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup for a single domain.
        
        Returns WHOIS data including registrant info, emails, company names.
        """
        logger.info(f"Performing WHOIS lookup for {domain}")
        
        url = f"{self.BASE_URL}?key={self.api_key}&whois={domain}"
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                
                if response.status_code == 429:
                    logger.warning("Whoxy rate limited, waiting...")
                    time.sleep(10)
                    return await self.whois_lookup(domain)
                
                if response.status_code != 200:
                    logger.error(f"Whoxy HTTP error {response.status_code}")
                    return {}
                
                data = response.json()
                
                if data.get('status') != 1:
                    logger.warning(f"Whoxy API error: {data.get('status_reason', 'Unknown')}")
                    return {}
                
                logger.info(f"WHOIS data retrieved for {domain}")
                return data
                
        except Exception as e:
            logger.error(f"Error during WHOIS lookup for {domain}: {e}")
            return {}
    
    def extract_attributes(self, whois_data: Dict) -> Tuple[Set[str], Set[str]]:
        """
        Extract email addresses and company names from WHOIS data.
        
        Returns: (emails_set, companies_set)
        """
        emails = set()
        companies = set()
        
        if not whois_data:
            return emails, companies
        
        # Common fields where emails might appear
        email_fields = [
            'registrant_email',
            'administrative_email', 
            'technical_email',
            'billing_email',
            'registrant_contact',
            'administrative_contact',
            'technical_contact'
        ]
        
        # Extract emails
        for field in email_fields:
            value = whois_data.get(field, '')
            if value and '@' in str(value):
                email = str(value).strip().lower()
                if self._is_valid_email(email):
                    emails.add(email)
        
        # Check contact_email field
        if 'contact_email' in whois_data:
            contact_email = whois_data.get('contact_email', '')
            if '@' in str(contact_email):
                email = str(contact_email).split('(')[0].strip().lower()
                if self._is_valid_email(email):
                    emails.add(email)
        
        # Extract company names
        company_fields = [
            'registrant_company',
            'registrant_organization',
            'administrative_company',
            'technical_company'
        ]
        
        for field in company_fields:
            value = whois_data.get(field, '')
            if value and str(value).strip():
                company = str(value).strip()
                if not self._is_privacy_service(company):
                    companies.add(company)
        
        return emails, companies
    
    def _is_valid_email(self, email: str) -> bool:
        """Basic email validation."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _is_privacy_service(self, company: str) -> bool:
        """Check if company name is a privacy/proxy service."""
        privacy_keywords = [
            'privacy', 'proxy', 'protected', 'whoisguard', 
            'domains by proxy', 'perfect privacy', 'redacted',
            'data protected', 'contact privacy', 'withheld',
            'not disclosed', 'gdpr'
        ]
        company_lower = company.lower()
        return any(keyword in company_lower for keyword in privacy_keywords)
    
    async def reverse_whois_by_email(self, email: str, max_pages: int = 10) -> List[Dict]:
        """
        Perform reverse WHOIS lookup by email.
        
        Returns list of domain records.
        """
        logger.info(f"Reverse WHOIS lookup by email: {email}")
        return await self._reverse_whois_query("email", email, max_pages)
    
    async def reverse_whois_by_company(self, company: str, max_pages: int = 10) -> List[Dict]:
        """
        Perform reverse WHOIS lookup by company name.
        
        Returns list of domain records.
        """
        logger.info(f"Reverse WHOIS lookup by company: {company}")
        return await self._reverse_whois_query("company", company, max_pages)
    
    async def _reverse_whois_query(
        self, 
        param_type: str, 
        param_value: str, 
        max_pages: int = 10
    ) -> List[Dict]:
        """Generic reverse WHOIS query handler."""
        base_url = f"{self.BASE_URL}?key={self.api_key}&reverse=whois&{param_type}={param_value}&mode=micro"
        
        all_results = []
        page = 1
        
        while page <= max_pages:
            url = f"{base_url}&page={page}"
            
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(url)
                    
                    if response.status_code == 429:
                        logger.warning("Whoxy rate limited, waiting 10s...")
                        time.sleep(10)
                        continue
                    
                    if response.status_code != 200:
                        logger.error(f"Whoxy HTTP error {response.status_code}")
                        break
                    
                    data = response.json()
                    
                    if data.get('status') != 1:
                        logger.warning(f"Whoxy API error: {data.get('status_reason')}")
                        break
                    
                    search_results = data.get("search_result", [])
                    
                    if not search_results:
                        break
                    
                    all_results.extend(search_results)
                    
                    total_pages = data.get('total_pages', 1)
                    logger.debug(f"Page {page}/{total_pages}: got {len(search_results)} domains (total: {len(all_results)})")
                    
                    if page >= total_pages:
                        break
                    
                    page += 1
                    time.sleep(self.RATE_LIMIT_DELAY)
                    
            except httpx.TimeoutException:
                logger.warning("Timeout, retrying...")
                time.sleep(5)
                continue
            except Exception as e:
                logger.error(f"Error during reverse WHOIS: {e}")
                break
        
        logger.info(f"Reverse WHOIS found {len(all_results)} domains for {param_type}={param_value}")
        return all_results
    
    async def discover_related_domains(
        self, 
        domain: str,
        additional_emails: Optional[List[str]] = None,
        additional_companies: Optional[List[str]] = None,
        max_pages_per_query: int = 5
    ) -> Dict[str, Any]:
        """
        Full domain reconnaissance workflow.
        
        1. WHOIS lookup on target domain
        2. Extract emails and companies
        3. Reverse WHOIS for each email and company
        
        Args:
            domain: Target domain to investigate
            additional_emails: Extra emails to search (from settings)
            additional_companies: Extra company names to search (from settings)
            max_pages_per_query: Limit pages per reverse WHOIS query
            
        Returns:
            Dictionary with:
            - whois_data: Raw WHOIS data
            - discovered_emails: Emails found in WHOIS
            - discovered_companies: Companies found in WHOIS
            - related_domains: List of all discovered related domains
            - domains_by_email: Dict of email -> domains list
            - domains_by_company: Dict of company -> domains list
        """
        result = {
            "target_domain": domain,
            "whois_data": {},
            "discovered_emails": [],
            "discovered_companies": [],
            "related_domains": [],
            "domains_by_email": {},
            "domains_by_company": {},
            "total_domains_found": 0,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Step 1: WHOIS Lookup
        whois_data = await self.whois_lookup(domain)
        result["whois_data"] = whois_data
        
        # Step 2: Extract attributes
        emails, companies = self.extract_attributes(whois_data)
        
        # Add additional emails/companies from settings
        if additional_emails:
            for email in additional_emails:
                if self._is_valid_email(email.lower()):
                    emails.add(email.lower())
        
        if additional_companies:
            for company in additional_companies:
                if company and not self._is_privacy_service(company):
                    companies.add(company)
        
        result["discovered_emails"] = list(emails)
        result["discovered_companies"] = list(companies)
        
        all_domains = set()
        
        # Step 3: Reverse WHOIS by email
        for email in emails:
            domains = await self.reverse_whois_by_email(email, max_pages_per_query)
            domain_names = [d.get('domain_name') for d in domains if d.get('domain_name')]
            result["domains_by_email"][email] = domain_names
            all_domains.update(domain_names)
            time.sleep(self.RATE_LIMIT_DELAY)
        
        # Step 4: Reverse WHOIS by company
        for company in companies:
            domains = await self.reverse_whois_by_company(company, max_pages_per_query)
            domain_names = [d.get('domain_name') for d in domains if d.get('domain_name')]
            result["domains_by_company"][company] = domain_names
            all_domains.update(domain_names)
            time.sleep(self.RATE_LIMIT_DELAY)
        
        result["related_domains"] = list(all_domains)
        result["total_domains_found"] = len(all_domains)
        
        logger.info(f"Whoxy discovery complete for {domain}: found {len(all_domains)} related domains")
        
        return result


def get_whoxy_service(api_key: str) -> WhoxyService:
    """Get a Whoxy service instance with the given API key."""
    return WhoxyService(api_key)
