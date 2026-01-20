"""
VirusTotal Reputation Service

Provides domain and IP reputation lookups via VirusTotal API v3.
Stores detection ratios, categories, and analysis results in asset metadata.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class VTReputationResult:
    """Result from VirusTotal reputation lookup."""
    success: bool = False
    error: Optional[str] = None
    
    # Detection stats
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    
    # Calculated ratio
    detection_ratio: str = "0/0"
    is_malicious: bool = False
    
    # Categories from VT
    categories: Dict[str, str] = field(default_factory=dict)
    category_list: List[str] = field(default_factory=list)
    
    # Analysis info
    last_analysis_date: Optional[str] = None
    reputation_score: int = 0
    
    # Community votes
    community_harmless: int = 0
    community_malicious: int = 0
    
    # Additional context
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    whois_info: Optional[Dict[str, Any]] = None
    
    # Raw data for debugging
    raw_response: Optional[Dict[str, Any]] = None


class VirusTotalService:
    """
    Service for querying VirusTotal API v3 for domain and IP reputation.
    
    Usage:
        service = VirusTotalService(api_key="your-vt-api-key")
        result = await service.lookup_domain("example.com")
        result = await service.lookup_ip("1.2.3.4")
    """
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize with optional API key (can be set later)."""
        self.api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None
    
    def set_api_key(self, api_key: str):
        """Set the API key."""
        self.api_key = api_key
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers={
                    "x-apikey": self.api_key or "",
                    "Accept": "application/json"
                },
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self._session
    
    async def close(self):
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def lookup_domain(self, domain: str) -> VTReputationResult:
        """
        Look up domain reputation from VirusTotal.
        
        Args:
            domain: The domain to look up (e.g., "example.com")
            
        Returns:
            VTReputationResult with detection stats and categories
        """
        result = VTReputationResult()
        
        if not self.api_key:
            result.error = "VirusTotal API key not configured"
            return result
        
        try:
            session = await self._get_session()
            url = f"{self.BASE_URL}/domains/{domain}"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    result = self._parse_domain_response(data)
                elif response.status == 404:
                    result.error = f"Domain not found in VirusTotal: {domain}"
                elif response.status == 401:
                    result.error = "Invalid VirusTotal API key"
                elif response.status == 429:
                    result.error = "VirusTotal rate limit exceeded"
                else:
                    result.error = f"VirusTotal API error: {response.status}"
                    
        except asyncio.TimeoutError:
            result.error = "VirusTotal request timed out"
        except aiohttp.ClientError as e:
            result.error = f"Network error: {str(e)}"
        except Exception as e:
            result.error = f"Error querying VirusTotal: {str(e)}"
            logger.exception(f"VT lookup error for domain {domain}")
        
        return result
    
    async def lookup_ip(self, ip: str) -> VTReputationResult:
        """
        Look up IP address reputation from VirusTotal.
        
        Args:
            ip: The IP address to look up (e.g., "1.2.3.4")
            
        Returns:
            VTReputationResult with detection stats and categories
        """
        result = VTReputationResult()
        
        if not self.api_key:
            result.error = "VirusTotal API key not configured"
            return result
        
        try:
            session = await self._get_session()
            url = f"{self.BASE_URL}/ip_addresses/{ip}"
            
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    result = self._parse_ip_response(data)
                elif response.status == 404:
                    result.error = f"IP not found in VirusTotal: {ip}"
                elif response.status == 401:
                    result.error = "Invalid VirusTotal API key"
                elif response.status == 429:
                    result.error = "VirusTotal rate limit exceeded"
                else:
                    result.error = f"VirusTotal API error: {response.status}"
                    
        except asyncio.TimeoutError:
            result.error = "VirusTotal request timed out"
        except aiohttp.ClientError as e:
            result.error = f"Network error: {str(e)}"
        except Exception as e:
            result.error = f"Error querying VirusTotal: {str(e)}"
            logger.exception(f"VT lookup error for IP {ip}")
        
        return result
    
    def _parse_domain_response(self, data: Dict[str, Any]) -> VTReputationResult:
        """Parse VirusTotal domain response."""
        result = VTReputationResult(success=True)
        
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            # Get last analysis stats
            stats = attributes.get("last_analysis_stats", {})
            result.malicious = stats.get("malicious", 0)
            result.suspicious = stats.get("suspicious", 0)
            result.harmless = stats.get("harmless", 0)
            result.undetected = stats.get("undetected", 0)
            result.total_engines = sum(stats.values())
            
            # Calculate detection ratio
            detections = result.malicious + result.suspicious
            result.detection_ratio = f"{detections}/{result.total_engines}"
            result.is_malicious = result.malicious > 0
            
            # Get categories from multiple vendors
            categories = attributes.get("categories", {})
            result.categories = categories
            # Flatten to unique category list
            result.category_list = list(set(categories.values()))
            
            # Get analysis date
            last_analysis = attributes.get("last_analysis_date")
            if last_analysis:
                result.last_analysis_date = datetime.fromtimestamp(last_analysis).isoformat()
            
            # Get reputation score (negative = bad, positive = good)
            result.reputation_score = attributes.get("reputation", 0)
            
            # Get community votes
            votes = attributes.get("total_votes", {})
            result.community_harmless = votes.get("harmless", 0)
            result.community_malicious = votes.get("malicious", 0)
            
            # Get registrar info
            result.registrar = attributes.get("registrar")
            
            # Get creation date
            creation = attributes.get("creation_date")
            if creation:
                result.creation_date = datetime.fromtimestamp(creation).isoformat()
            
            # Store raw for debugging (exclude large fields)
            result.raw_response = {
                "last_analysis_stats": stats,
                "categories": categories,
                "reputation": result.reputation_score,
                "total_votes": votes,
            }
            
        except Exception as e:
            logger.error(f"Error parsing VT domain response: {e}")
            result.error = f"Parse error: {str(e)}"
        
        return result
    
    def _parse_ip_response(self, data: Dict[str, Any]) -> VTReputationResult:
        """Parse VirusTotal IP response."""
        result = VTReputationResult(success=True)
        
        try:
            attributes = data.get("data", {}).get("attributes", {})
            
            # Get last analysis stats
            stats = attributes.get("last_analysis_stats", {})
            result.malicious = stats.get("malicious", 0)
            result.suspicious = stats.get("suspicious", 0)
            result.harmless = stats.get("harmless", 0)
            result.undetected = stats.get("undetected", 0)
            result.total_engines = sum(stats.values())
            
            # Calculate detection ratio
            detections = result.malicious + result.suspicious
            result.detection_ratio = f"{detections}/{result.total_engines}"
            result.is_malicious = result.malicious > 0
            
            # IPs don't have categories like domains, but may have tags
            tags = attributes.get("tags", [])
            if tags:
                result.category_list = tags
            
            # Get analysis date
            last_analysis = attributes.get("last_analysis_date")
            if last_analysis:
                result.last_analysis_date = datetime.fromtimestamp(last_analysis).isoformat()
            
            # Get reputation score
            result.reputation_score = attributes.get("reputation", 0)
            
            # Get community votes
            votes = attributes.get("total_votes", {})
            result.community_harmless = votes.get("harmless", 0)
            result.community_malicious = votes.get("malicious", 0)
            
            # Get ASN/network info for context
            result.whois_info = {
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "country": attributes.get("country"),
                "network": attributes.get("network"),
            }
            
            # Store raw for debugging
            result.raw_response = {
                "last_analysis_stats": stats,
                "tags": tags,
                "reputation": result.reputation_score,
                "total_votes": votes,
            }
            
        except Exception as e:
            logger.error(f"Error parsing VT IP response: {e}")
            result.error = f"Parse error: {str(e)}"
        
        return result
    
    def result_to_metadata(self, result: VTReputationResult) -> Dict[str, Any]:
        """
        Convert VTReputationResult to metadata dict for storing on asset.
        
        Returns:
            Dict with VT data ready to merge into asset.metadata_
        """
        if not result.success:
            return {
                "virustotal": {
                    "error": result.error,
                    "lookup_date": datetime.utcnow().isoformat(),
                }
            }
        
        return {
            "virustotal": {
                "detection_ratio": result.detection_ratio,
                "malicious": result.malicious,
                "suspicious": result.suspicious,
                "harmless": result.harmless,
                "undetected": result.undetected,
                "total_engines": result.total_engines,
                "is_malicious": result.is_malicious,
                "categories": result.category_list,
                "reputation_score": result.reputation_score,
                "last_analysis_date": result.last_analysis_date,
                "community_votes": {
                    "harmless": result.community_harmless,
                    "malicious": result.community_malicious,
                },
                "lookup_date": datetime.utcnow().isoformat(),
            }
        }


# Singleton instance
_vt_service: Optional[VirusTotalService] = None


def get_virustotal_service() -> VirusTotalService:
    """Get or create the VirusTotal service singleton."""
    global _vt_service
    if _vt_service is None:
        _vt_service = VirusTotalService()
    return _vt_service


async def lookup_and_store_vt_data(
    db,
    asset,
    api_key: str
) -> Dict[str, Any]:
    """
    Look up VirusTotal data for an asset and store in metadata.
    
    Args:
        db: Database session
        asset: Asset model instance
        api_key: VirusTotal API key
        
    Returns:
        Dict with VT data that was stored
    """
    from app.models.asset import AssetType
    
    service = get_virustotal_service()
    service.set_api_key(api_key)
    
    # Determine lookup type based on asset type
    if asset.asset_type in [AssetType.DOMAIN, AssetType.SUBDOMAIN]:
        result = await service.lookup_domain(asset.value)
    elif asset.asset_type == AssetType.IP_ADDRESS:
        result = await service.lookup_ip(asset.value)
    else:
        return {"error": f"VT lookup not supported for asset type: {asset.asset_type}"}
    
    # Convert to metadata format
    vt_metadata = service.result_to_metadata(result)
    
    # Merge with existing metadata
    if asset.metadata_ is None:
        asset.metadata_ = {}
    
    asset.metadata_.update(vt_metadata)
    
    # Commit changes
    db.add(asset)
    db.commit()
    
    logger.info(f"Stored VT data for {asset.value}: {result.detection_ratio}")
    
    return vt_metadata
