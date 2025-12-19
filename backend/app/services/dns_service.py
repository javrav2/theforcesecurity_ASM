"""DNS enumeration service for asset discovery."""

import socket
import logging
from typing import Optional
from dataclasses import dataclass, field

import dns.resolver
import dns.reversename
import dns.exception

logger = logging.getLogger(__name__)


@dataclass
class DNSRecords:
    """Container for DNS records."""
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[dict] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    soa_record: Optional[dict] = None
    ptr_records: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "A": self.a_records,
            "AAAA": self.aaaa_records,
            "MX": self.mx_records,
            "NS": self.ns_records,
            "TXT": self.txt_records,
            "CNAME": self.cname_records,
            "SOA": self.soa_record,
            "PTR": self.ptr_records,
        }


class DNSService:
    """Service for DNS record enumeration."""
    
    def __init__(self, nameservers: Optional[list[str]] = None, timeout: float = 5.0):
        """
        Initialize DNS service.
        
        Args:
            nameservers: Custom DNS servers to use (defaults to system DNS)
            timeout: Query timeout in seconds
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout * 2
        
        if nameservers:
            self.resolver.nameservers = nameservers
        else:
            # Use reliable public DNS servers
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    
    def enumerate_domain(self, domain: str) -> DNSRecords:
        """
        Enumerate all DNS records for a domain.
        
        Args:
            domain: Domain name to enumerate
            
        Returns:
            DNSRecords object containing all discovered records
        """
        records = DNSRecords()
        
        # Query each record type
        records.a_records = self._query_a(domain)
        records.aaaa_records = self._query_aaaa(domain)
        records.mx_records = self._query_mx(domain)
        records.ns_records = self._query_ns(domain)
        records.txt_records = self._query_txt(domain)
        records.cname_records = self._query_cname(domain)
        records.soa_record = self._query_soa(domain)
        
        return records
    
    def _query_a(self, domain: str) -> list[str]:
        """Query A records."""
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(rdata.address) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            logger.debug(f"No A records for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error querying A records for {domain}: {e}")
            return []
    
    def _query_aaaa(self, domain: str) -> list[str]:
        """Query AAAA (IPv6) records."""
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(rdata.address) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            logger.debug(f"No AAAA records for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error querying AAAA records for {domain}: {e}")
            return []
    
    def _query_mx(self, domain: str) -> list[dict]:
        """Query MX records."""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [
                {"priority": rdata.preference, "host": str(rdata.exchange).rstrip('.')}
                for rdata in answers
            ]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            logger.debug(f"No MX records for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error querying MX records for {domain}: {e}")
            return []
    
    def _query_ns(self, domain: str) -> list[str]:
        """Query NS records."""
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            logger.debug(f"No NS records for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error querying NS records for {domain}: {e}")
            return []
    
    def _query_txt(self, domain: str) -> list[str]:
        """Query TXT records."""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            return [str(rdata).strip('"') for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            logger.debug(f"No TXT records for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error querying TXT records for {domain}: {e}")
            return []
    
    def _query_cname(self, domain: str) -> list[str]:
        """Query CNAME records."""
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            logger.debug(f"No CNAME records for {domain}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error querying CNAME records for {domain}: {e}")
            return []
    
    def _query_soa(self, domain: str) -> Optional[dict]:
        """Query SOA record."""
        try:
            answers = self.resolver.resolve(domain, 'SOA')
            for rdata in answers:
                return {
                    "mname": str(rdata.mname).rstrip('.'),
                    "rname": str(rdata.rname).rstrip('.'),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum,
                }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
            logger.debug(f"No SOA record for {domain}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error querying SOA record for {domain}: {e}")
            return None
    
    def reverse_lookup(self, ip: str) -> list[str]:
        """
        Perform reverse DNS lookup.
        
        Args:
            ip: IP address to look up
            
        Returns:
            List of hostnames
        """
        try:
            rev_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(rev_name, 'PTR')
            return [str(rdata.target).rstrip('.') for rdata in answers]
        except Exception as e:
            logger.debug(f"Reverse lookup failed for {ip}: {e}")
            return []
    
    def resolve_hostname(self, hostname: str) -> list[str]:
        """
        Resolve hostname to IP addresses.
        
        Args:
            hostname: Hostname to resolve
            
        Returns:
            List of IP addresses
        """
        ips = []
        ips.extend(self._query_a(hostname))
        ips.extend(self._query_aaaa(hostname))
        return ips















