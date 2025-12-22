"""
WhoisXML API service for discovering IP netblocks/CIDR ranges.

Discovers IP ranges owned by organizations using the WhoisXML IP Netblocks API.
Based on the CIDR discovery script provided.
"""

import ipaddress
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any

import httpx

logger = logging.getLogger(__name__)


class WhoisXMLNetblockService:
    """Service for discovering IP netblocks via WhoisXML API."""
    
    BASE_URL = "https://ip-netblocks.whoisxmlapi.com/api/v2"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    def normalize_ip_address(self, ip_value: Any) -> str:
        """
        Normalize an IP address to standard format.
        Handles various input formats: standard notation, integers, hex, scientific notation.
        """
        if ip_value is None or ip_value == "":
            return ""
        
        # Handle numeric types
        if isinstance(ip_value, (int, float)):
            try:
                ip_int = int(ip_value)
                if ip_int <= 0xFFFFFFFF:
                    return str(ipaddress.IPv4Address(ip_int))
                else:
                    return str(ipaddress.IPv6Address(ip_int))
            except (ValueError, ipaddress.AddressValueError, OverflowError) as e:
                logger.warning(f"Could not convert numeric IP {ip_value}: {e}")
                return ""
        
        ip_str = str(ip_value).strip()
        
        # Handle scientific notation
        if 'e+' in ip_str.lower() or 'e-' in ip_str.lower():
            try:
                ip_int = int(float(ip_str))
                if ip_int <= 0xFFFFFFFF:
                    return str(ipaddress.IPv4Address(ip_int))
                else:
                    return str(ipaddress.IPv6Address(ip_int))
            except (ValueError, ipaddress.AddressValueError, OverflowError) as e:
                logger.warning(f"Could not convert scientific notation IP {ip_str}: {e}")
                return ""
        
        try:
            # Try standard IP parsing first
            return str(ipaddress.ip_address(ip_str))
        except ValueError:
            pass
        
        try:
            # Try numeric string parsing
            if ip_str.isdigit():
                ip_int = int(ip_str)
                if ip_int <= 0xFFFFFFFF:
                    return str(ipaddress.IPv4Address(ip_int))
                else:
                    return str(ipaddress.IPv6Address(ip_int))
        except (ValueError, ipaddress.AddressValueError):
            pass
        
        logger.warning(f"Could not normalize IP address: {ip_value}")
        return ""
    
    # PostgreSQL bigint max value
    MAX_BIGINT = 9223372036854775807
    
    def ip_range_to_cidr(self, start_ip: str, end_ip: str) -> Tuple[str, int]:
        """
        Convert IP range to CIDR notation and calculate IP count.
        Returns tuple of (cidr_notation, ip_count).
        Note: ip_count is capped at MAX_BIGINT for database compatibility.
        """
        if not start_ip or not end_ip:
            return "", 0
        
        try:
            start = ipaddress.ip_address(start_ip)
            end = ipaddress.ip_address(end_ip)
            networks = list(ipaddress.summarize_address_range(start, end))
            
            if len(networks) == 1:
                network = networks[0]
                ip_count = min(network.num_addresses, self.MAX_BIGINT)
                return str(network), ip_count
            elif len(networks) > 1:
                cidrs = [str(net) for net in networks]
                total_ips = sum(net.num_addresses for net in networks)
                ip_count = min(total_ips, self.MAX_BIGINT)
                return "; ".join(cidrs), ip_count
            else:
                ip_count = int(end) - int(start) + 1
                ip_count = min(ip_count, self.MAX_BIGINT)
                return f"{start_ip} - {end_ip}", ip_count
        except ValueError as e:
            logger.error(f"Error processing IP range {start_ip} - {end_ip}: {e}")
            return f"{start_ip} - {end_ip}", 0
    
    def detect_ip_version(self, ip: str) -> str:
        """Detect if IP is IPv4 or IPv6."""
        if not ip:
            return "unknown"
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return "ipv4"
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                return "ipv6"
        except ValueError:
            pass
        return "unknown"
    
    def is_owned_by_organization(
        self, 
        target_org: str,
        org_name: str, 
        description: str, 
        address: str,
        headquarters_keywords: Optional[List[str]] = None
    ) -> Tuple[bool, int]:
        """
        Evaluate if the netblock is owned by the target organization.
        
        Returns:
            Tuple of (is_owned, confidence_score)
            confidence_score is 0-100
        """
        if not target_org:
            return False, 0
        
        target_upper = target_org.upper().strip()
        
        # Generate variations of the target org name
        variations = [
            target_upper,
            f"{target_upper} INC",
            f"{target_upper} INC.",
            f"{target_upper}, INC",
            f"{target_upper}, INC.",
            f"THE {target_upper}",
        ]
        
        confidence = 0
        
        # Check org_name (highest confidence)
        if org_name:
            org_name_upper = org_name.upper().strip()
            for pattern in variations:
                if pattern in org_name_upper:
                    confidence = max(confidence, 90)
                    break
            # Partial match
            if target_upper in org_name_upper:
                confidence = max(confidence, 70)
        
        # Check description (medium confidence)
        if description:
            description_upper = description.upper().strip()
            if target_upper in description_upper:
                confidence = max(confidence, 50)
        
        # Check address for headquarters (high confidence)
        if address and headquarters_keywords:
            address_upper = address.upper().strip()
            matches = sum(1 for kw in headquarters_keywords if kw.upper() in address_upper)
            if matches >= 2:
                confidence = max(confidence, 85)
        
        return confidence >= 50, confidence
    
    async def fetch_netblocks(
        self, 
        search_term: str,
        limit: int = 1000
    ) -> List[Dict]:
        """
        Fetch netblocks from WhoisXML API for a search term.
        Handles pagination automatically.
        """
        all_data = []
        url = f"{self.BASE_URL}?apiKey={self.api_key}&org[]={search_term}&limit={limit}"
        
        async with httpx.AsyncClient(timeout=60.0, verify=False) as client:
            while url:
                try:
                    response = await client.get(url)
                    response.raise_for_status()
                    data = response.json()
                    
                    result = data.get("result", {})
                    inetnums = result.get("inetnums", [])
                    all_data.extend(inetnums)
                    
                    logger.info(f"Fetched {len(inetnums)} netblocks for '{search_term}'")
                    
                    # Check for next page
                    url = result.get("next")
                    
                except httpx.HTTPError as e:
                    logger.error(f"HTTP error fetching netblocks: {e}")
                    break
                except Exception as e:
                    logger.error(f"Error fetching netblocks: {e}")
                    break
        
        return all_data
    
    async def discover_netblocks(
        self,
        organization_name: str,
        search_terms: Optional[List[str]] = None,
        headquarters_keywords: Optional[List[str]] = None,
        include_variations: bool = True
    ) -> Dict[str, Any]:
        """
        Discover all netblocks for an organization.
        
        Args:
            organization_name: Primary organization name
            search_terms: Additional search terms
            headquarters_keywords: Keywords to identify HQ address (for ownership verification)
            include_variations: Include variations like "Inc", "Inc." etc.
            
        Returns:
            Dictionary with discovered netblocks and statistics
        """
        result = {
            "organization": organization_name,
            "search_terms": [],
            "netblocks": [],
            "total_found": 0,
            "owned_count": 0,
            "total_ips": 0,
            "owned_ips": 0,
            "ipv4_count": 0,
            "ipv6_count": 0,
            "duplicates_removed": 0,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Build search terms
        terms = set()
        if organization_name:
            terms.add(organization_name)
            if include_variations:
                # Add common variations
                base = organization_name.replace(" Inc", "").replace(" Inc.", "").replace(", Inc", "").strip()
                terms.add(base)
                terms.add(f"{base} Inc")
        
        if search_terms:
            terms.update(search_terms)
        
        result["search_terms"] = list(terms)
        
        # Track seen inetnums to deduplicate
        seen_inetnums = set()
        all_netblocks = []
        
        for term in terms:
            raw_data = await self.fetch_netblocks(term)
            
            for inetnum_info in raw_data:
                inetnum = inetnum_info.get("inetnum", "")
                
                # Skip duplicates
                if inetnum and inetnum in seen_inetnums:
                    result["duplicates_removed"] += 1
                    continue
                
                if inetnum:
                    seen_inetnums.add(inetnum)
                
                # Extract IPs
                start_ip = ""
                end_ip = ""
                
                if " - " in inetnum:
                    parts = inetnum.split(" - ")
                    if len(parts) == 2:
                        start_ip = parts[0].strip()
                        end_ip = parts[1].strip()
                
                if not start_ip:
                    start_ip = self.normalize_ip_address(inetnum_info.get("inetnumFirstString"))
                if not end_ip:
                    end_ip = self.normalize_ip_address(inetnum_info.get("inetnumLastString"))
                
                if not start_ip or not end_ip:
                    continue
                
                # Get metadata
                ip_version = self.detect_ip_version(start_ip)
                cidr_notation, ip_count = self.ip_range_to_cidr(start_ip, end_ip)
                
                # Extract org info
                org_data = inetnum_info.get("org") or {}
                org_name = org_data.get("name", "")
                
                description_list = inetnum_info.get("description", [])
                description = ", ".join(description_list) if isinstance(description_list, list) else str(description_list)
                
                address_list = inetnum_info.get("address", [])
                address = ", ".join(address_list) if isinstance(address_list, list) else str(address_list)
                
                # Check ownership
                is_owned, confidence = self.is_owned_by_organization(
                    organization_name, org_name, description, address, headquarters_keywords
                )
                
                # ASN info - convert to strings to avoid type issues
                as_data = inetnum_info.get("as") or {}
                asn_raw = as_data.get("asn", "")
                # Convert ASN to string (API may return integer)
                asn_str = str(asn_raw) if asn_raw else None
                
                netblock = {
                    "inetnum": inetnum,
                    "start_ip": start_ip,
                    "end_ip": end_ip,
                    "cidr_notation": cidr_notation,
                    "ip_count": ip_count,
                    "ip_version": ip_version,
                    "is_owned": is_owned,
                    "ownership_confidence": confidence,
                    "in_scope": is_owned,  # Default in_scope to match ownership
                    
                    # ASN - all converted to strings or None
                    "asn": asn_str,
                    "as_name": str(as_data.get("name", "")) or None,
                    "as_type": str(as_data.get("type", "")) or None,
                    "route": str(as_data.get("route", "")) or None,
                    "as_domain": str(as_data.get("domain", "")) or None,
                    
                    # Network
                    "netname": inetnum_info.get("netname", ""),
                    "nethandle": inetnum_info.get("nethandle", ""),
                    "description": description,
                    "whois_modified": inetnum_info.get("modified"),
                    
                    # Geographic
                    "country": inetnum_info.get("country", ""),
                    "city": inetnum_info.get("city", ""),
                    "address": address,
                    
                    # Org
                    "org_name": org_name,
                    "org_email": org_data.get("email", ""),
                    "org_phone": org_data.get("phone", ""),
                    "org_country": org_data.get("country", ""),
                    "org_city": org_data.get("city", ""),
                    "org_postal_code": org_data.get("postalCode", ""),
                }
                
                all_netblocks.append(netblock)
                
                # Update stats
                if ip_version == "ipv4":
                    result["ipv4_count"] += 1
                elif ip_version == "ipv6":
                    result["ipv6_count"] += 1
                
                result["total_ips"] += ip_count
                if is_owned:
                    result["owned_count"] += 1
                    result["owned_ips"] += ip_count
        
        result["netblocks"] = all_netblocks
        result["total_found"] = len(all_netblocks)
        
        logger.info(
            f"Discovered {result['total_found']} netblocks for {organization_name}: "
            f"{result['owned_count']} owned, {result['total_ips']:,} total IPs"
        )
        
        return result


def get_whoisxml_netblock_service(api_key: str) -> WhoisXMLNetblockService:
    """Get a WhoisXML netblock service instance."""
    return WhoisXMLNetblockService(api_key)


