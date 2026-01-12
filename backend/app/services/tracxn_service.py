"""Tracxn API Service for M&A / Acquisition data."""

import httpx
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class TracxnService:
    """Service to fetch M&A data from Tracxn API."""
    
    BASE_URL = "https://platform.tracxn.com/api/2.2"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    async def search_acquisitions(
        self,
        acquirer: str,
        limit: int = 20,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Search for acquisitions by acquirer name.
        
        Args:
            acquirer: Name of the acquiring company
            limit: Maximum number of results
            offset: Pagination offset
            
        Returns:
            Dictionary containing acquisition data
        """
        try:
            params = {
                "acquirer": acquirer,
                "limit": limit,
                "offset": offset
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/acquisitions/search",
                    headers=self.headers,
                    params=params
                )
                
                if response.status_code == 401:
                    return {
                        "error": "Invalid API key",
                        "status_code": 401
                    }
                elif response.status_code == 403:
                    return {
                        "error": "Access forbidden - check API key permissions",
                        "status_code": 403
                    }
                elif response.status_code != 200:
                    return {
                        "error": f"API error: {response.status_code}",
                        "status_code": response.status_code,
                        "detail": response.text
                    }
                
                data = response.json()
                return self._parse_acquisitions_response(data)
                
        except httpx.TimeoutException:
            logger.error(f"Timeout searching acquisitions for {acquirer}")
            return {"error": "Request timeout", "acquisitions": []}
        except Exception as e:
            logger.error(f"Error searching acquisitions: {e}")
            return {"error": str(e), "acquisitions": []}
    
    def _parse_acquisitions_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Tracxn API response into normalized format."""
        acquisitions = []
        
        # Handle different response structures from Tracxn
        items = data.get("results", data.get("acquisitions", data.get("items", [])))
        
        for item in items:
            acquisition = self._parse_acquisition(item)
            if acquisition:
                acquisitions.append(acquisition)
        
        return {
            "total": data.get("total", len(acquisitions)),
            "acquisitions": acquisitions,
            "has_more": data.get("hasMore", False),
            "offset": data.get("offset", 0)
        }
    
    def _parse_acquisition(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single acquisition record."""
        try:
            # Extract target company info
            target = item.get("target", item.get("acquiredCompany", {}))
            if isinstance(target, str):
                target = {"name": target}
            
            target_name = target.get("name") or item.get("targetName") or item.get("companyName")
            if not target_name:
                return None
            
            # Parse dates
            announced_date = None
            closed_date = None
            
            if item.get("announcedDate"):
                try:
                    announced_date = datetime.fromisoformat(item["announcedDate"].replace("Z", "+00:00"))
                except:
                    pass
            elif item.get("date"):
                try:
                    announced_date = datetime.fromisoformat(item["date"].replace("Z", "+00:00"))
                except:
                    pass
            
            if item.get("closedDate"):
                try:
                    closed_date = datetime.fromisoformat(item["closedDate"].replace("Z", "+00:00"))
                except:
                    pass
            
            # Extract domain from website
            domain = None
            website = target.get("website") or item.get("website")
            if website:
                domain = self._extract_domain(website)
            
            return {
                "target_name": target_name,
                "target_domain": domain,
                "target_description": target.get("description") or item.get("description"),
                "target_industry": target.get("industry") or target.get("sector") or item.get("industry"),
                "target_country": target.get("country") or target.get("hqCountry") or item.get("country"),
                "target_city": target.get("city") or target.get("hqCity"),
                "target_founded_year": target.get("foundedYear") or target.get("founded"),
                "target_employees": target.get("employees") or target.get("employeeCount"),
                "announced_date": announced_date,
                "closed_date": closed_date,
                "deal_value": item.get("dealValue") or item.get("amount"),
                "deal_currency": item.get("currency", "USD"),
                "tracxn_id": str(item.get("id")) if item.get("id") else None,
                "website_url": website,
                "linkedin_url": target.get("linkedinUrl") or target.get("linkedin"),
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
    
    async def get_company_details(self, company_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a company.
        
        Args:
            company_id: Tracxn company ID
            
        Returns:
            Company details including domains
        """
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/companies/{company_id}",
                    headers=self.headers
                )
                
                if response.status_code != 200:
                    return {"error": f"API error: {response.status_code}"}
                
                return response.json()
                
        except Exception as e:
            logger.error(f"Error getting company details: {e}")
            return {"error": str(e)}
    
    async def search_companies(
        self,
        name: str,
        limit: int = 10
    ) -> Dict[str, Any]:
        """
        Search for companies by name.
        
        Args:
            name: Company name to search
            limit: Maximum results
            
        Returns:
            List of matching companies
        """
        try:
            params = {
                "name": name,
                "limit": limit
            }
            
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(
                    f"{self.BASE_URL}/companies/search",
                    headers=self.headers,
                    params=params
                )
                
                if response.status_code != 200:
                    return {"error": f"API error: {response.status_code}"}
                
                return response.json()
                
        except Exception as e:
            logger.error(f"Error searching companies: {e}")
            return {"error": str(e)}


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
    
    all_acquisitions = []
    offset = 0
    page_size = 20
    
    while len(all_acquisitions) < limit:
        result = await service.search_acquisitions(
            acquirer=org_name,
            limit=min(page_size, limit - len(all_acquisitions)),
            offset=offset
        )
        
        if "error" in result:
            return result
        
        acquisitions = result.get("acquisitions", [])
        if not acquisitions:
            break
        
        all_acquisitions.extend(acquisitions)
        
        if not result.get("has_more", False):
            break
        
        offset += page_size
    
    return {
        "total": len(all_acquisitions),
        "acquisitions": all_acquisitions,
        "organization": org_name
    }
