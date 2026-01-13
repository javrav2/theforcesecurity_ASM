"""Tracxn API Service for M&A / Acquisition data.

Attempts multiple API endpoint variations to find the correct one.
"""

import httpx
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class TracxnService:
    """Service to fetch M&A data from Tracxn API."""
    
    # Try multiple possible API base URLs
    POSSIBLE_BASE_URLS = [
        "https://api.tracxn.com/2.2",
        "https://api.tracxn.com/v2",
        "https://api.tracxn.com",
        "https://tracxn.com/api/2.2",
        "https://platform.tracxn.com/api/2.2",
    ]
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        # Try different auth header formats
        self.auth_headers = [
            {"accessToken": api_key, "Content-Type": "application/json"},
            {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            {"X-API-Key": api_key, "Content-Type": "application/json"},
            {"api-key": api_key, "Content-Type": "application/json"},
        ]
    
    async def _try_request(self, method: str, endpoint: str, payload: dict = None) -> Dict[str, Any]:
        """Try request against multiple base URLs and auth methods."""
        all_errors = []
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            for base_url in self.POSSIBLE_BASE_URLS:
                for headers in self.auth_headers:
                    url = f"{base_url}/{endpoint}"
                    try:
                        if method == "POST":
                            response = await client.post(url, headers=headers, json=payload)
                        else:
                            response = await client.get(url, headers=headers, params=payload)
                        
                        logger.info(f"Tracxn API: {method} {url} -> {response.status_code}")
                        
                        if response.status_code == 200:
                            return {"success": True, "data": response.json(), "url": url}
                        elif response.status_code == 401:
                            all_errors.append(f"{url}: Unauthorized (401)")
                        elif response.status_code == 403:
                            all_errors.append(f"{url}: Forbidden (403)")
                        elif response.status_code == 404:
                            all_errors.append(f"{url}: Not Found (404)")
                        else:
                            all_errors.append(f"{url}: {response.status_code} - {response.text[:200]}")
                            
                    except Exception as e:
                        all_errors.append(f"{url}: {str(e)}")
        
        return {
            "success": False,
            "error": "All API endpoints failed",
            "attempts": all_errors
        }
    
    async def search_company(self, company_name: str) -> Dict[str, Any]:
        """Search for a company by name."""
        # Try different payload formats
        payloads = [
            {"companyName": company_name},
            {"name": company_name},
            {"query": company_name},
            {"search": company_name},
        ]
        
        endpoints = [
            "company/search",
            "companies/search",
            "search/company",
            "search",
        ]
        
        for endpoint in endpoints:
            for payload in payloads:
                result = await self._try_request("POST", endpoint, payload)
                if result.get("success"):
                    return result.get("data", {})
        
        # If all POST requests fail, try GET
        for endpoint in endpoints:
            result = await self._try_request("GET", f"{endpoint}?q={company_name}", None)
            if result.get("success"):
                return result.get("data", {})
        
        return {"error": "Could not find company via Tracxn API", "details": result.get("attempts", [])}
    
    async def search_acquisitions_by_acquirer(
        self,
        acquirer_name: str,
        limit: int = 50
    ) -> Dict[str, Any]:
        """Search for acquisitions by an acquirer company."""
        
        # First try to search for the company
        search_result = await self.search_company(acquirer_name)
        
        if "error" in search_result:
            # Return helpful error with API test results
            return {
                "error": f"Tracxn API integration issue. The API endpoints are not responding as expected. "
                         f"Please verify your Tracxn API key and subscription includes API access. "
                         f"You can still add acquisitions manually.",
                "details": search_result.get("details", []),
                "acquisitions": []
            }
        
        # Parse acquisitions from response
        acquisitions = []
        
        # Try to extract acquisitions from various response formats
        data = search_result
        if isinstance(data, dict):
            # Try different possible response structures
            acq_data = (
                data.get("acquisitions", []) or
                data.get("result", {}).get("acquisitions", []) or
                data.get("data", {}).get("acquisitions", []) or
                data.get("companies", [{}])[0].get("acquisitions", []) if data.get("companies") else []
            )
            
            for acq in acq_data[:limit]:
                parsed = self._parse_acquisition(acq)
                if parsed:
                    acquisitions.append(parsed)
        
        return {
            "total": len(acquisitions),
            "acquisitions": acquisitions,
            "organization": acquirer_name
        }
    
    def _parse_acquisition(self, item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a single acquisition record."""
        try:
            if isinstance(item, str):
                return {"target_name": item, "source": "tracxn"}
            
            target_name = (
                item.get("name") or 
                item.get("companyName") or 
                item.get("targetName") or
                item.get("company", {}).get("name") if isinstance(item.get("company"), dict) else None
            )
            
            if not target_name:
                return None
            
            # Parse dates
            announced_date = None
            date_str = item.get("date") or item.get("announcedDate")
            if date_str:
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
        
        if "://" in url:
            url = url.split("://")[1]
        
        url = url.split("/")[0].split("?")[0]
        
        if url.startswith("www."):
            url = url[4:]
        
        return url if url else None


async def fetch_acquisitions_for_org(
    org_name: str,
    api_key: str,
    limit: int = 50
) -> Dict[str, Any]:
    """Fetch all acquisitions for an organization."""
    service = TracxnService(api_key)
    
    result = await service.search_acquisitions_by_acquirer(
        acquirer_name=org_name,
        limit=limit
    )
    
    return {
        "total": result.get("total", 0),
        "acquisitions": result.get("acquisitions", []),
        "organization": org_name,
        "error": result.get("error"),
        "details": result.get("details")
    }
