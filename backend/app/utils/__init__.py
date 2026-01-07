"""Utility functions for the ASM platform."""

import re
from urllib.parse import urlparse, urlunparse
from typing import Optional


def normalize_url(url: str, default_scheme: str = "https") -> str:
    """
    Normalize a URL to ensure it has a valid protocol and format.
    
    Fixes common issues like:
    - Missing protocol (adds https:// by default)
    - Malformed protocols (http// -> http://)
    - Double protocols (https://http://... -> https://...)
    - Extra slashes
    
    Args:
        url: The URL to normalize
        default_scheme: Default scheme to use if none present (default: https)
        
    Returns:
        Normalized URL string
    """
    if not url:
        return url
    
    url = url.strip()
    
    # Fix malformed protocols (http// -> http://)
    url = re.sub(r'^(https?)//+', r'\1://', url)
    url = re.sub(r'^(https?):/*', r'\1://', url)
    
    # Remove double protocols (https://http://... -> extract the innermost URL)
    double_protocol_match = re.match(r'^https?://+(https?://+.+)$', url, re.IGNORECASE)
    if double_protocol_match:
        url = double_protocol_match.group(1)
        # Fix the extracted URL too
        url = re.sub(r'^(https?)//+', r'\1://', url)
        url = re.sub(r'^(https?):/*', r'\1://', url)
    
    # If no protocol at all, add the default
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = f"{default_scheme}://{url}"
    
    # Parse and rebuild to clean up
    try:
        parsed = urlparse(url)
        # Rebuild with cleaned components
        cleaned = urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower() if parsed.netloc else "",
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))
        return cleaned if parsed.netloc else url
    except Exception:
        return url


def extract_hostname(url_or_host: str) -> str:
    """
    Extract just the hostname from a URL or return the host if already plain.
    
    Examples:
        https://example.com/path -> example.com
        http://sub.example.com:8080/page -> sub.example.com
        example.com -> example.com
        192.168.1.1 -> 192.168.1.1
    """
    if not url_or_host:
        return url_or_host
    
    url_or_host = url_or_host.strip()
    
    # If it looks like a URL, parse it
    if url_or_host.startswith(('http://', 'https://')):
        try:
            parsed = urlparse(url_or_host)
            hostname = parsed.netloc.split(':')[0]  # Remove port
            return hostname.lower() if hostname else url_or_host
        except Exception:
            pass
    
    # If it has a path, extract just the host part
    if '/' in url_or_host:
        host_part = url_or_host.split('/')[0]
        return host_part.split(':')[0].lower()
    
    # Remove port if present
    if ':' in url_or_host and not url_or_host.count(':') > 1:  # Not an IPv6
        return url_or_host.split(':')[0].lower()
    
    return url_or_host.lower()


def is_valid_domain(value: str) -> bool:
    """Check if a value looks like a valid domain name."""
    if not value:
        return False
    
    # Remove protocol if present
    hostname = extract_hostname(value)
    
    # Basic domain pattern
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, hostname))


def is_valid_ip(value: str) -> bool:
    """Check if a value looks like a valid IP address (v4 or v6)."""
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_cidr(value: str) -> bool:
    """Check if a value is a CIDR notation (e.g., 192.168.1.0/24)."""
    import ipaddress
    if '/' not in value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False

