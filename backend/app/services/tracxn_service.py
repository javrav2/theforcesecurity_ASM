"""Tracxn API Service for M&A / Acquisition data.

Based on Tracxn API v2.2 documentation:
https://www.postman.com/tracxnapi/tracxn-api/documentation/210lc69/tracxnapi-playground
"""

import httpx
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class TracxnService:
    """Service to fetch M&A data from Tracxn API."""
    
    BASE_URL = "https://tracxn.com/api/2.2"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "accessToken": api_key,
            "Content-Type": "application/json"
        }
    
    async def search_company(self, company_name: str) -> Dict[str, Any]:
        """
        Search for a company by name to get its Tracxn ID.
        
        Args:
            company_name: Name of the company to search
            
        Returns:
            Company search results
        """
        try:
            payload = {
                "companyName": company_name
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.BASE_URL}/company/search",
                    headers=self.headers,
                    json=payload
                )
                
                logger.info(f"Tracxn search response: {response.status_code}")
                
                if response.status_code == 401:
                    return {"error": "Invalid API key or unauthorized", "status_code": 401}
                elif response.status_code == 403:
                    return {"error": "Access forbidden - check API key permissions", "status_code": 403}
                elif response.status_code == 404:
                    return {"error": "Company not found", "status_code": 404}
                elif response.status_code != 200:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }
                
                return response.json()
                
        except httpx.TimeoutException:
            logger.error(f"Timeout searching company: {company_name}")
            return {"error": "Request timeout"}
        except Exception as e:
            logger.error(f"Error searching company: {e}")
            return {"error": str(e)}
    
    async def get_company_profile(self, company_id: str) -> Dict[str, Any]:
        """
        Get detailed company profile including acquisitions.
        
        Args:
            company_id: Tracxn company ID
            
        Returns:
            Company profile with acquisitions data
        """
        try:
            payload = {
                "id": company_id,
                "fields": [
                    "name",
                    "domain",
                    "website",
                    "description",
                    "hqLocation",
                    "foundedYear",
                    "employeeCount",
                    "acquisitions",
                    "acquiredBy"
                ]
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    f"{self.BASE_URL}/company/profile",
                    headers=self.headers,
                    json=payload
                )
                
                if response.status_code != 200:
                    return {"error": f"API error: {response.status_code}", "detail": response.text}
                
                return response.json()
                
        except Exception as e:
            logger.error(f"Error getting company profile: {e}")
            return {"error": str(e)}
    
    async def search_acquisitions_by_acquirer(
        self,
        acquirer_name: str,
        limit: int = 50
    ) -> Dict[str, Any]:
        """
        Search for acquisitions by an acquirer company.
        
        This works by:
        1. Finding the company ID
        2. Getting company profile with acquisitions field
        
        Args:
            acquirer_name: Name of the acquiring company
            limit: Maximum acquisitions to return
            
        Returns:
            Dictionary containing acquisition data
        """
        # First, search for the company
        search_result = await self.search_company(acquirer_name)
        
        if "error" in search_result:
            return search_result
        
        # Get company ID from search results
        companies = search_result.get("result", [])
        if not companies:
            return {"error": "Company not found", "acquisitions": []}
        
        # Find best match
        company = None
        for c in companies:
            if c.get("name", "").lower() == acquirer_name.lower():
                company = c
                break
        
        if not company:
            company = companies[0]  # Take first result
        
        company_id = company.get("id")
        if not company_id:
            return {"error": "No company ID found", "acquisitions": []}
        
        # Get company profile with acquisitions
        profile = await self.get_company_profile(company_id)
        
        if "error" in profile:
            return profile
        
        # Parse acquisitions from profile
        acquisitions = []
        raw_acquisitions = profile.get("result", {}).get("acquisitions", [])
        
        for acq in raw_acquisitions[:limit]:
            parsed = self._parse_acquisition(acq)
            if parsed:
                acquisitions.append(parsed)
        
        return {
            "total": len(acquisitions),
            "acquisitions": acquisitions,
            "acquirer": {
                "name": company.get("name"),
                "id": company_id,
                "domain": company.get("domain")
            }
        }
    
    def _parse_acquisition(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single acquisition record from Tracxn response."""
        try:
            # Handle different response structures
            if isinstance(item, str):
                return {"target_name": item, "source": "tracxn"}
            
            target_name = (
                item.get("name") or 
                item.get("companyName") or 
                item.get("targetName") or
                item.get("company", {}).get("name")
            )
            
            if not target_name:
                return None
            
            # Parse dates
            announced_date = None
            if item.get("date") or item.get("announcedDate"):
                date_str = item.get("date") or item.get("announcedDate")
                try:
                    if isinstance(date_str, str):
                        announced_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    elif isinstance(date_str, (int, float)):
                        announced_date = datetime.fromtimestamp(date_str / 1000)
                except:
                    pass
            
            # Extract domain
            domain = item.get("domain") or item.get("website")
            if domain:
                domain = self._extract_domain(domain)
            
            return {
                "target_name": target_name,
                "target_domain": domain,
                "target_description": item.get("description"),
                "target_industry": item.get("industry") or item.get("sector"),
                "target_country": item.get("hqCountry") or item.get("country"),
                "target_city": item.get("hqCity") or item.get("city"),
                "target_founded_year": item.get("foundedYear"),
                "target_employees": item.get("employeeCount") or item.get("employees"),
                "announced_date": announced_date,
                "closed_date": None,
                "deal_value": item.get("dealValue") or item.get("amount"),
                "deal_currency": item.get("currency", "USD"),
                "tracxn_id": str(item.get("id")) if item.get("id") else None,
                "website_url": item.get("website"),
                "linkedin_url": item.get("linkedinUrl"),
                "source": "tracxn",
                "raw_data": item
            }
            
        except Exception as e:
            logger.error(f"Error parsing acquisition: {e}")
            return None
    
    def _extract_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL."""
        if not url:
            return None
        
        url = url.lower().strip()
        
        # Remove protocol
        if "://" in url:
            url = url.split("://")[1]
        
        # Remove path and query
        url = url.split("/")[0].split("?")[0]
        
        # Remove www prefix
        if url.startswith("www."):
            url = url[4:]
        
        return url if url else None


async def fetch_acquisitions_for_org(
    org_name: str,
    api_key: str,
    limit: int = 50
) -> Dict[str, Any]:
    """
    Fetch all acquisitions for an organization.
    
    Args:
        org_name: Name of the acquiring organization
        api_key: Tracxn API key
        limit: Maximum acquisitions to fetch
        
    Returns:
        Dictionary with acquisitions and stats
    """
    service = TracxnService(api_key)
    
    result = await service.search_acquisitions_by_acquirer(
        acquirer_name=org_name,
        limit=limit
    )
    
    if "error" in result:
        return result
    
    return {
        "total": result.get("total", 0),
        "acquisitions": result.get("acquisitions", []),
        "organization": org_name,
        "acquirer": result.get("acquirer")
    }
