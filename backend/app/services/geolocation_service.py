"""Geo-location service for IP address lookups."""

import logging
import socket
import asyncio
from typing import Optional, Dict, Any
import httpx

logger = logging.getLogger(__name__)


class GeoLocationService:
    """Service for looking up geo-location data for IP addresses."""
    
    # Free IP geolocation API (no API key required, 45 requests/minute)
    IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,lat,lon,isp,as,query"
    
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
    
    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            # Run DNS resolution in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                lambda: socket.gethostbyname(hostname)
            )
            return result
        except socket.gaierror as e:
            logger.debug(f"Failed to resolve {hostname}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error resolving {hostname}: {e}")
            return None
    
    async def lookup_ip(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Look up geo-location data for an IP address."""
        # Check cache first
        if ip_address in self._cache:
            return self._cache[ip_address]
        
        # Skip private/local IPs
        if self._is_private_ip(ip_address):
            return None
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(self.IP_API_URL.format(ip=ip_address))
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("status") == "success":
                        result = {
                            "ip_address": data.get("query", ip_address),
                            "latitude": str(data.get("lat", "")),
                            "longitude": str(data.get("lon", "")),
                            "city": data.get("city", ""),
                            "country": data.get("country", ""),
                            "country_code": data.get("countryCode", ""),
                            "isp": data.get("isp", ""),
                            "asn": data.get("as", ""),
                        }
                        
                        # Cache the result
                        self._cache[ip_address] = result
                        return result
                    else:
                        logger.debug(f"IP lookup failed for {ip_address}: {data.get('message')}")
                        return None
                else:
                    logger.warning(f"IP API returned {response.status_code} for {ip_address}")
                    return None
                    
        except httpx.TimeoutException:
            logger.warning(f"Timeout looking up geo-location for {ip_address}")
            return None
        except Exception as e:
            logger.warning(f"Error looking up geo-location for {ip_address}: {e}")
            return None
    
    async def lookup_hostname(self, hostname: str) -> Optional[Dict[str, Any]]:
        """Resolve hostname and look up geo-location."""
        # First resolve the hostname to an IP
        ip_address = await self.resolve_hostname(hostname)
        
        if not ip_address:
            return None
        
        # Then look up the IP
        result = await self.lookup_ip(ip_address)
        
        if result:
            result["ip_address"] = ip_address
            
        return result
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP address is private/local."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return True
            
            first = int(parts[0])
            second = int(parts[1])
            
            # 10.x.x.x
            if first == 10:
                return True
            # 172.16.x.x - 172.31.x.x
            if first == 172 and 16 <= second <= 31:
                return True
            # 192.168.x.x
            if first == 192 and second == 168:
                return True
            # 127.x.x.x (localhost)
            if first == 127:
                return True
            # 0.x.x.x
            if first == 0:
                return True
                
            return False
        except:
            return True
    
    async def batch_lookup(self, hostnames: list[str], max_concurrent: int = 10) -> Dict[str, Dict[str, Any]]:
        """Look up geo-location for multiple hostnames concurrently."""
        results = {}
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def lookup_with_limit(hostname: str):
            async with semaphore:
                # Add small delay to respect rate limits
                await asyncio.sleep(0.1)
                result = await self.lookup_hostname(hostname)
                if result:
                    results[hostname] = result
        
        # Run lookups concurrently
        tasks = [lookup_with_limit(h) for h in hostnames]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return results


# Singleton instance
_geo_service: Optional[GeoLocationService] = None


def get_geolocation_service() -> GeoLocationService:
    """Get or create the geo-location service singleton."""
    global _geo_service
    if _geo_service is None:
        _geo_service = GeoLocationService()
    return _geo_service

