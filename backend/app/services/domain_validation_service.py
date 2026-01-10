"""
Domain Validation Service

Validates discovered domains to detect:
- Parked domains (Bodis, Sedo, etc.)
- Privacy-protected registrations
- Expired/grabbed domains
- Suspicious registrations

Helps reduce false positives from historical WHOIS data.
"""

import logging
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime
import httpx

logger = logging.getLogger(__name__)

# Known domain parking services (nameservers)
PARKING_NAMESERVERS = [
    'bodis.com',
    'sedo.com',
    'sedoparking.com',
    'parkingcrew.net',
    'domaincontrol.com',  # Sometimes used for parking
    'above.com',
    'dsredirection.com',
    'parklogic.com',
    'skenzo.com',
    'domainsponsor.com',
    'fabulous.com',
    'hitfarm.com',
    'smartname.com',
    'undeveloped.com',
    'hugedomains.com',
    'afternic.com',
    'dan.com',
]

# Known WHOIS privacy services
PRIVACY_SERVICES = [
    'whois privacy',
    'privacy protect',
    'domains by proxy',
    'whoisprivacycorp',
    'whoisguard',
    'privacyguardian',
    'contactprivacy',
    'perfect privacy',
    'withheldforprivacy',
    'redacted for privacy',
    'data protected',
    'identity protect',
    'domain privacy',
    'private registration',
    'proxy service',
    'registration private',
    'gdpr masked',
    'redacted',
    'not disclosed',
]

# Suspicious registrar patterns (often used by domainers/squatters)
SUSPICIOUS_REGISTRARS = [
    'internet.bs',
    'namecheap',  # Not inherently suspicious, but common for squatters
    'dynadot',
    'porkbun',
    'namesilo',
]


class DomainValidationService:
    """Service to validate and flag suspicious domains."""
    
    def __init__(self):
        self.whoxy_api_key: Optional[str] = None
    
    def set_whoxy_key(self, api_key: str):
        """Set Whoxy API key for WHOIS lookups."""
        self.whoxy_api_key = api_key
    
    def check_nameservers_for_parking(self, nameservers: List[str]) -> Tuple[bool, str]:
        """
        Check if nameservers indicate a parked domain.
        
        Returns: (is_parked, parking_service)
        """
        for ns in nameservers:
            ns_lower = ns.lower()
            for parking_ns in PARKING_NAMESERVERS:
                if parking_ns in ns_lower:
                    return True, parking_ns
        return False, ""
    
    def check_registrant_for_privacy(self, registrant_info: Dict) -> Tuple[bool, str]:
        """
        Check if registrant info indicates privacy protection.
        
        Returns: (is_private, privacy_service)
        """
        # Check various registrant fields
        fields_to_check = [
            registrant_info.get('registrant_name', ''),
            registrant_info.get('registrant_organization', ''),
            registrant_info.get('registrant_company', ''),
            registrant_info.get('registrant_email', ''),
            registrant_info.get('administrative_name', ''),
            registrant_info.get('administrative_organization', ''),
        ]
        
        combined_text = ' '.join(str(f) for f in fields_to_check).lower()
        
        for privacy_term in PRIVACY_SERVICES:
            if privacy_term in combined_text:
                return True, privacy_term
        
        return False, ""
    
    def check_registrar_suspicious(self, registrar: str) -> Tuple[bool, str]:
        """
        Check if registrar is commonly used by squatters.
        
        Note: This is a soft indicator, not definitive.
        Returns: (is_suspicious, registrar_name)
        """
        registrar_lower = registrar.lower() if registrar else ''
        
        for suspicious in SUSPICIOUS_REGISTRARS:
            if suspicious in registrar_lower:
                return True, suspicious
        
        return False, ""
    
    def calculate_suspicion_score(
        self,
        is_parked: bool,
        is_private: bool,
        is_suspicious_registrar: bool,
        creation_date: Optional[datetime] = None,
        original_discovery_date: Optional[datetime] = None
    ) -> Tuple[int, List[str]]:
        """
        Calculate a suspicion score for a domain.
        
        Returns: (score 0-100, list of reasons)
        """
        score = 0
        reasons = []
        
        # Parked domain is highly suspicious
        if is_parked:
            score += 50
            reasons.append("Domain is parked (likely expired/grabbed)")
        
        # Privacy protection is moderately suspicious
        if is_private:
            score += 25
            reasons.append("WHOIS privacy protection enabled")
        
        # Suspicious registrar is a soft indicator
        if is_suspicious_registrar:
            score += 10
            reasons.append("Registrar commonly used by domain squatters")
        
        # Recently created domain that should be old
        if creation_date and original_discovery_date:
            # If Whoxy says it was associated with org, but domain was created recently
            # that suggests it expired and was re-registered
            if creation_date > original_discovery_date:
                score += 40
                reasons.append("Domain was re-registered after original association")
        
        return min(score, 100), reasons
    
    async def validate_domain(self, domain: str) -> Dict:
        """
        Validate a domain and return suspicion indicators.
        
        Returns dict with:
        - is_suspicious: bool
        - suspicion_score: int (0-100)
        - is_parked: bool
        - is_private: bool
        - parking_service: str
        - privacy_service: str
        - reasons: List[str]
        - recommendation: str
        """
        result = {
            "domain": domain,
            "is_suspicious": False,
            "suspicion_score": 0,
            "is_parked": False,
            "is_private": False,
            "parking_service": "",
            "privacy_service": "",
            "reasons": [],
            "recommendation": "keep",
            "checked_at": datetime.utcnow().isoformat()
        }
        
        # Try to get WHOIS data
        whois_data = await self._fetch_whois(domain)
        
        if not whois_data:
            result["reasons"].append("Could not fetch WHOIS data")
            return result
        
        # Check nameservers for parking
        nameservers = whois_data.get('name_servers', [])
        if isinstance(nameservers, str):
            nameservers = [nameservers]
        
        is_parked, parking_service = self.check_nameservers_for_parking(nameservers)
        result["is_parked"] = is_parked
        result["parking_service"] = parking_service
        
        # Check for privacy protection
        is_private, privacy_service = self.check_registrant_for_privacy(whois_data)
        result["is_private"] = is_private
        result["privacy_service"] = privacy_service
        
        # Check registrar
        registrar = whois_data.get('registrar', {})
        if isinstance(registrar, dict):
            registrar_name = registrar.get('registrar_name', '')
        else:
            registrar_name = str(registrar)
        
        is_suspicious_registrar, _ = self.check_registrar_suspicious(registrar_name)
        
        # Calculate overall suspicion score
        score, reasons = self.calculate_suspicion_score(
            is_parked=is_parked,
            is_private=is_private,
            is_suspicious_registrar=is_suspicious_registrar
        )
        
        result["suspicion_score"] = score
        result["reasons"] = reasons
        result["is_suspicious"] = score >= 50
        
        # Set recommendation
        if score >= 75:
            result["recommendation"] = "remove"
        elif score >= 50:
            result["recommendation"] = "review"
        elif score >= 25:
            result["recommendation"] = "flag"
        else:
            result["recommendation"] = "keep"
        
        return result
    
    async def _fetch_whois(self, domain: str) -> Optional[Dict]:
        """Fetch WHOIS data for a domain."""
        if not self.whoxy_api_key:
            logger.warning("No Whoxy API key configured for WHOIS lookup")
            return None
        
        url = f"https://api.whoxy.com/?key={self.whoxy_api_key}&whois={domain}"
        
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(url)
                
                if response.status_code != 200:
                    logger.warning(f"WHOIS lookup failed for {domain}: HTTP {response.status_code}")
                    return None
                
                data = response.json()
                
                if data.get('status') != 1:
                    logger.warning(f"WHOIS lookup failed for {domain}: {data.get('status_reason')}")
                    return None
                
                return data
                
        except Exception as e:
            logger.error(f"Error fetching WHOIS for {domain}: {e}")
            return None
    
    async def validate_domains_batch(
        self, 
        domains: List[str],
        mark_suspicious: bool = True
    ) -> Dict:
        """
        Validate multiple domains and return summary.
        
        Returns dict with:
        - total: int
        - suspicious: int
        - parked: int
        - private: int
        - results: List[Dict]
        """
        results = []
        suspicious_count = 0
        parked_count = 0
        private_count = 0
        
        for domain in domains:
            try:
                result = await self.validate_domain(domain)
                results.append(result)
                
                if result["is_suspicious"]:
                    suspicious_count += 1
                if result["is_parked"]:
                    parked_count += 1
                if result["is_private"]:
                    private_count += 1
                    
            except Exception as e:
                logger.error(f"Error validating {domain}: {e}")
                results.append({
                    "domain": domain,
                    "error": str(e)
                })
        
        return {
            "total": len(domains),
            "suspicious": suspicious_count,
            "parked": parked_count,
            "private": private_count,
            "results": results
        }


def get_domain_validation_service() -> DomainValidationService:
    """Get a domain validation service instance."""
    return DomainValidationService()
