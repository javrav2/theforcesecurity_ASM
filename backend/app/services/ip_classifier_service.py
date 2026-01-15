"""
IP Classifier Service

Classifies IP addresses as owned infrastructure vs cloud-hosted (ephemeral).

This is critical for ASM because:
1. Owned CIDRs (from WhoisXML) = static IPs, safe to scan directly
2. Cloud-hosted IPs (Azure, AWS, GCP) = ephemeral, could change anytime
3. Never scan cloud IPs directly - they could belong to someone else tomorrow

The service checks:
1. Is the IP in an owned CIDR block? → owned, safe to scan
2. Is the IP in a known cloud provider range? → cloud, scan by hostname only
3. Unknown → assume ephemeral to be safe
"""

import ipaddress
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


@dataclass
class IPClassification:
    """Classification result for an IP address."""
    ip: str
    hosting_type: str  # owned, cloud, cdn, third_party, unknown
    hosting_provider: Optional[str] = None  # azure, aws, gcp, cloudflare, etc.
    is_ephemeral: bool = True  # Assume ephemeral unless proven otherwise
    in_owned_cidr: bool = False
    netblock_id: Optional[int] = None
    confidence: int = 50  # 0-100 confidence in classification
    reason: Optional[str] = None  # Human-readable explanation


# Major cloud provider IP ranges
# These are approximate ranges - cloud providers publish their IP ranges publicly
# AWS: https://ip-ranges.amazonaws.com/ip-ranges.json
# Azure: https://www.microsoft.com/en-us/download/details.aspx?id=56519
# GCP: https://www.gstatic.com/ipranges/cloud.json
# Cloudflare: https://www.cloudflare.com/ips/

CLOUD_PROVIDER_RANGES: Dict[str, List[str]] = {
    "azure": [
        # Microsoft Azure - common ranges
        "13.64.0.0/11",      # 13.64-95.x.x
        "13.104.0.0/14",     # 13.104-107.x.x
        "20.0.0.0/8",        # 20.x.x.x (major Azure range)
        "40.64.0.0/10",      # 40.64-127.x.x
        "52.96.0.0/12",      # 52.96-111.x.x (includes Microsoft 365)
        "52.112.0.0/14",     # 52.112-115.x.x
        "52.120.0.0/14",     # 52.120-123.x.x
        "52.224.0.0/11",     # 52.224-255.x.x
        "104.40.0.0/13",     # 104.40-47.x.x
        "104.208.0.0/13",    # 104.208-215.x.x
        "137.116.0.0/15",    # 137.116-117.x.x
        "168.61.0.0/16",     # 168.61.x.x
        "168.62.0.0/15",     # 168.62-63.x.x
        "191.232.0.0/13",    # 191.232-239.x.x
    ],
    "aws": [
        # Amazon Web Services - common ranges
        "3.0.0.0/8",         # 3.x.x.x
        "13.32.0.0/12",      # 13.32-47.x.x (CloudFront)
        "13.224.0.0/12",     # 13.224-239.x.x
        "15.176.0.0/12",     # 15.176-191.x.x
        "18.0.0.0/8",        # 18.x.x.x
        "34.192.0.0/10",     # 34.192-255.x.x
        "35.80.0.0/12",      # 35.80-95.x.x
        "44.192.0.0/10",     # 44.192-255.x.x
        "52.0.0.0/11",       # 52.0-31.x.x
        "52.32.0.0/11",      # 52.32-63.x.x
        "52.64.0.0/12",      # 52.64-79.x.x
        "54.0.0.0/8",        # 54.x.x.x
        "99.77.0.0/16",      # 99.77.x.x
        "99.78.0.0/15",      # 99.78-79.x.x
        "176.32.0.0/12",     # 176.32-47.x.x
        "205.251.192.0/18",  # 205.251.192-255.x (Route 53)
    ],
    "gcp": [
        # Google Cloud Platform - common ranges
        "34.64.0.0/10",      # 34.64-127.x.x
        "34.128.0.0/10",     # 34.128-191.x.x
        "35.184.0.0/13",     # 35.184-191.x.x
        "35.192.0.0/12",     # 35.192-207.x.x
        "35.208.0.0/12",     # 35.208-223.x.x
        "35.224.0.0/12",     # 35.224-239.x.x
        "35.240.0.0/13",     # 35.240-247.x.x
        "104.196.0.0/14",    # 104.196-199.x.x
        "104.154.0.0/15",    # 104.154-155.x.x
        "130.211.0.0/16",    # 130.211.x.x
        "146.148.0.0/17",    # 146.148.0-127.x
        "199.192.112.0/22",  # 199.192.112-115.x
        "199.223.232.0/21",  # 199.223.232-239.x
    ],
    "cloudflare": [
        # Cloudflare CDN/WAF - IPs are shared across customers
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "104.16.0.0/13",     # 104.16-23.x.x
        "104.24.0.0/14",     # 104.24-27.x.x
        "108.162.192.0/18",
        "131.0.72.0/22",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "172.64.0.0/13",     # 172.64-71.x.x
        "173.245.48.0/20",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
    ],
    "akamai": [
        # Akamai CDN - common ranges
        "23.0.0.0/12",       # 23.0-15.x.x
        "23.32.0.0/11",      # 23.32-63.x.x
        "23.64.0.0/10",      # 23.64-127.x.x
        "23.192.0.0/11",     # 23.192-223.x.x
        "104.64.0.0/10",     # 104.64-127.x.x
        "184.24.0.0/13",     # 184.24-31.x.x
        "184.50.0.0/15",     # 184.50-51.x.x
        "184.84.0.0/14",     # 184.84-87.x.x
    ],
    "digitalocean": [
        # DigitalOcean - common ranges
        "64.225.0.0/16",
        "67.205.128.0/17",
        "68.183.0.0/16",
        "104.131.0.0/16",
        "104.236.0.0/16",
        "137.184.0.0/14",
        "138.68.0.0/15",
        "138.197.0.0/16",
        "139.59.0.0/16",
        "142.93.0.0/16",
        "143.110.0.0/15",
        "143.198.0.0/15",
        "157.230.0.0/15",
        "157.245.0.0/16",
        "159.65.0.0/16",
        "159.89.0.0/16",
        "159.203.0.0/16",
        "161.35.0.0/16",
        "162.243.0.0/16",
        "164.90.0.0/15",
        "165.22.0.0/15",
        "165.227.0.0/16",
        "167.71.0.0/16",
        "167.172.0.0/15",
        "174.138.0.0/15",
        "178.62.0.0/15",
        "188.166.0.0/15",
        "192.241.128.0/17",
        "198.199.64.0/18",
        "206.189.0.0/16",
        "209.97.128.0/17",
    ],
    "oracle": [
        # Oracle Cloud Infrastructure
        "129.146.0.0/15",
        "129.148.0.0/14",
        "129.152.0.0/13",
        "130.35.0.0/16",
        "130.61.0.0/16",
        "132.145.0.0/16",
        "134.65.0.0/16",
        "134.70.0.0/15",
        "138.1.0.0/16",
        "138.2.0.0/15",
        "140.83.0.0/16",
        "140.84.0.0/14",
        "140.91.0.0/16",
        "141.144.0.0/13",
        "141.147.0.0/16",
        "144.21.0.0/16",
        "144.22.0.0/15",
        "146.56.0.0/14",
        "147.154.0.0/15",
        "150.136.0.0/13",
        "152.67.0.0/16",
        "152.70.0.0/15",
        "155.248.0.0/14",
        "158.101.0.0/16",
        "168.138.0.0/15",
        "192.9.0.0/16",
        "193.122.0.0/15",
        "193.123.0.0/17",
    ],
    "linode": [
        # Linode/Akamai Cloud
        "45.33.0.0/16",
        "45.56.64.0/18",
        "45.79.0.0/16",
        "50.116.0.0/16",
        "66.175.208.0/20",
        "69.164.192.0/18",
        "72.14.176.0/20",
        "74.207.224.0/19",
        "96.126.96.0/19",
        "97.107.128.0/17",
        "139.144.0.0/14",
        "139.162.0.0/15",
        "172.104.0.0/14",
        "172.232.0.0/14",
        "173.255.192.0/18",
        "178.79.128.0/17",
        "192.155.80.0/20",
        "198.58.96.0/19",
    ],
}

# CDN providers - these IPs are shared across customers, never scan directly
CDN_PROVIDERS = {"cloudflare", "akamai", "fastly", "bunny"}


class IPClassifierService:
    """
    Service to classify IP addresses as owned vs cloud-hosted.
    
    This is essential for safe scanning:
    - Owned IPs (in org's CIDR blocks) → safe to scan directly
    - Cloud IPs (Azure, AWS, etc.) → ephemeral, scan by hostname only
    - CDN IPs (Cloudflare, Akamai) → shared, never scan directly
    """
    
    def __init__(self, db: Optional[Session] = None):
        """
        Initialize the classifier.
        
        Args:
            db: Optional database session for loading owned netblocks
        """
        self.db = db
        self._owned_netblocks_cache: Optional[List[Any]] = None
        
        # Pre-compile IP networks for faster lookup
        self._cloud_networks: Dict[str, List[ipaddress.IPv4Network]] = {}
        for provider, ranges in CLOUD_PROVIDER_RANGES.items():
            self._cloud_networks[provider] = []
            for cidr in ranges:
                try:
                    self._cloud_networks[provider].append(
                        ipaddress.ip_network(cidr, strict=False)
                    )
                except ValueError as e:
                    logger.warning(f"Invalid CIDR for {provider}: {cidr} - {e}")
    
    def _get_owned_netblocks(self, organization_id: Optional[int] = None) -> List[Any]:
        """Get owned netblocks from database."""
        if self._owned_netblocks_cache is not None:
            return self._owned_netblocks_cache
        
        if self.db is None:
            return []
        
        from app.models.netblock import Netblock
        
        query = self.db.query(Netblock).filter(
            Netblock.is_owned == True,
            Netblock.in_scope == True
        )
        
        if organization_id:
            query = query.filter(Netblock.organization_id == organization_id)
        
        self._owned_netblocks_cache = query.all()
        return self._owned_netblocks_cache
    
    def classify(
        self,
        ip: str,
        organization_id: Optional[int] = None
    ) -> IPClassification:
        """
        Classify an IP address.
        
        Args:
            ip: IP address to classify
            organization_id: Optional org ID to check owned netblocks
            
        Returns:
            IPClassification with hosting type and details
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return IPClassification(
                ip=ip,
                hosting_type="unknown",
                is_ephemeral=True,
                confidence=0,
                reason=f"Invalid IP address: {ip}"
            )
        
        # Handle IPv6 - for now, mark as unknown
        if ip_obj.version == 6:
            return IPClassification(
                ip=ip,
                hosting_type="unknown",
                is_ephemeral=True,
                confidence=30,
                reason="IPv6 classification not yet implemented"
            )
        
        # 1. Check owned CIDR blocks first (highest priority)
        owned_netblocks = self._get_owned_netblocks(organization_id)
        for netblock in owned_netblocks:
            if netblock.cidr_notation:
                for cidr in netblock.cidr_notation.replace(',', ';').split(';'):
                    cidr = cidr.strip()
                    if not cidr:
                        continue
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        if ip_obj in network:
                            return IPClassification(
                                ip=ip,
                                hosting_type="owned",
                                is_ephemeral=False,
                                in_owned_cidr=True,
                                netblock_id=netblock.id,
                                confidence=100,
                                reason=f"IP is within owned CIDR block {cidr} ({netblock.org_name or 'organization'})"
                            )
                    except ValueError:
                        pass
        
        # 2. Check known cloud provider ranges
        for provider, networks in self._cloud_networks.items():
            for network in networks:
                if ip_obj in network:
                    is_cdn = provider in CDN_PROVIDERS
                    return IPClassification(
                        ip=ip,
                        hosting_type="cdn" if is_cdn else "cloud",
                        hosting_provider=provider,
                        is_ephemeral=True,
                        confidence=90,
                        reason=f"IP is in {provider.upper()} range {network} - {'shared CDN IP' if is_cdn else 'ephemeral cloud IP'}"
                    )
        
        # 3. Check if it's a private/reserved IP
        if ip_obj.is_private:
            return IPClassification(
                ip=ip,
                hosting_type="private",
                is_ephemeral=False,
                confidence=100,
                reason="Private/internal IP address"
            )
        
        if ip_obj.is_reserved:
            return IPClassification(
                ip=ip,
                hosting_type="reserved",
                is_ephemeral=False,
                confidence=100,
                reason="Reserved IP address"
            )
        
        # 4. Unknown - assume ephemeral to be safe
        return IPClassification(
            ip=ip,
            hosting_type="unknown",
            is_ephemeral=True,  # Assume ephemeral - better safe than scanning someone else
            confidence=30,
            reason="IP not in owned CIDR blocks or known cloud ranges - assuming ephemeral for safety"
        )
    
    def classify_batch(
        self,
        ips: List[str],
        organization_id: Optional[int] = None
    ) -> Dict[str, IPClassification]:
        """
        Classify multiple IP addresses.
        
        Args:
            ips: List of IP addresses to classify
            organization_id: Optional org ID to check owned netblocks
            
        Returns:
            Dict mapping IP to classification
        """
        results = {}
        for ip in ips:
            results[ip] = self.classify(ip, organization_id)
        return results
    
    def is_safe_to_scan_directly(
        self,
        ip: str,
        organization_id: Optional[int] = None
    ) -> bool:
        """
        Check if an IP is safe to scan directly (vs by hostname).
        
        Only IPs in owned CIDR blocks are safe to scan directly.
        Cloud/CDN/unknown IPs should be scanned by hostname.
        
        Args:
            ip: IP address to check
            organization_id: Optional org ID
            
        Returns:
            True if safe to scan directly, False if should scan by hostname
        """
        classification = self.classify(ip, organization_id)
        return classification.hosting_type == "owned" and not classification.is_ephemeral


def get_ip_classifier(db: Optional[Session] = None) -> IPClassifierService:
    """Factory function to create IP classifier service."""
    return IPClassifierService(db)
