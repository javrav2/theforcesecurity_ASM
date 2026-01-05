"""
SNI IP Ranges Service for cloud asset discovery.

Integrates with the kaeferjaeger.gay SNI IP ranges dataset which contains
SSL/TLS certificate data collected from scanning cloud provider IP ranges:
- Amazon AWS
- Google Cloud
- Microsoft Azure
- Oracle Cloud
- DigitalOcean

Source: https://kaeferjaeger.gay/?dir=sni-ip-ranges

This service can:
1. Download and sync SNI data to local storage or S3
2. Search for organization domains/keywords across all cloud providers
3. Discover hidden assets hosted on cloud infrastructure
"""

import asyncio
import gzip
import json
import logging
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Set, Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# Base URL for SNI data
SNI_BASE_URL = "https://kaeferjaeger.gay/?dir=sni-ip-ranges"

# Cloud provider directories and their data files
CLOUD_PROVIDERS = {
    "amazon": {
        "name": "Amazon AWS",
        "base_url": "https://kaeferjaeger.gay/sni-ip-ranges/amazon/",
        "files": ["ipv4_merged_sni.json.gz"],  # Main file with SNI data
    },
    "google": {
        "name": "Google Cloud",
        "base_url": "https://kaeferjaeger.gay/sni-ip-ranges/google/",
        "files": ["ipv4_merged_sni.json.gz"],
    },
    "microsoft": {
        "name": "Microsoft Azure",
        "base_url": "https://kaeferjaeger.gay/sni-ip-ranges/microsoft/",
        "files": ["ipv4_merged_sni.json.gz"],
    },
    "oracle": {
        "name": "Oracle Cloud",
        "base_url": "https://kaeferjaeger.gay/sni-ip-ranges/oracle/",
        "files": ["ipv4_merged_sni.json.gz"],
    },
    "digitalocean": {
        "name": "DigitalOcean",
        "base_url": "https://kaeferjaeger.gay/sni-ip-ranges/digitalocean/",
        "files": ["ipv4_merged_sni.json.gz"],
    },
}


@dataclass
class SNIRecord:
    """A single SNI record from the dataset."""
    ip: str
    port: int
    sni: str  # Server Name Indication (domain)
    cloud_provider: str
    timestamp: Optional[str] = None


@dataclass
class SNISearchResult:
    """Result from searching SNI data."""
    query: str
    total_records: int = 0
    domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    records: List[SNIRecord] = field(default_factory=list)
    by_cloud_provider: Dict[str, int] = field(default_factory=dict)
    success: bool = False
    error: Optional[str] = None
    elapsed_time: float = 0.0


class SNIScannerService:
    """
    Service for discovering assets using SNI IP ranges data.
    
    The SNI data contains SSL/TLS certificates observed across cloud provider
    IP ranges, revealing domains and subdomains hosted on cloud infrastructure.
    """
    
    # Default local storage path
    DEFAULT_DATA_DIR = os.environ.get("SNI_DATA_DIR", "/app/data/sni-ip-ranges")
    
    def __init__(
        self,
        data_dir: Optional[str] = None,
        s3_bucket: Optional[str] = None,
        s3_prefix: str = "sni-ip-ranges/",
    ):
        """
        Initialize SNI scanner service.
        
        Args:
            data_dir: Local directory for storing SNI data
            s3_bucket: Optional S3 bucket for storage (if using S3)
            s3_prefix: S3 prefix for SNI data files
        """
        self.data_dir = data_dir or self.DEFAULT_DATA_DIR
        self.s3_bucket = s3_bucket or os.environ.get("SNI_S3_BUCKET")
        self.s3_prefix = s3_prefix
        self._ensure_directories()
        
        # Index for fast searching (loaded on demand)
        self._index: Dict[str, List[SNIRecord]] = {}
        self._index_loaded = False
    
    def _ensure_directories(self):
        """Ensure data directories exist."""
        Path(self.data_dir).mkdir(parents=True, exist_ok=True)
        for provider in CLOUD_PROVIDERS:
            Path(os.path.join(self.data_dir, provider)).mkdir(exist_ok=True)
    
    async def download_provider_data(
        self,
        provider: str,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Download SNI data for a specific cloud provider.
        
        Args:
            provider: Cloud provider key (amazon, google, microsoft, oracle, digitalocean)
            force: Force re-download even if data exists
            
        Returns:
            Download status dict
        """
        if provider not in CLOUD_PROVIDERS:
            return {"success": False, "error": f"Unknown provider: {provider}"}
        
        config = CLOUD_PROVIDERS[provider]
        provider_dir = os.path.join(self.data_dir, provider)
        
        results = {
            "provider": provider,
            "files_downloaded": 0,
            "files_skipped": 0,
            "total_size_bytes": 0,
            "errors": [],
        }
        
        for filename in config["files"]:
            file_url = f"{config['base_url']}{filename}"
            local_path = os.path.join(provider_dir, filename)
            
            # Skip if exists and not forcing
            if os.path.exists(local_path) and not force:
                # Check if file is recent (within 7 days)
                mtime = os.path.getmtime(local_path)
                if datetime.fromtimestamp(mtime) > datetime.utcnow() - timedelta(days=7):
                    results["files_skipped"] += 1
                    continue
            
            try:
                logger.info(f"Downloading {file_url}")
                
                async with httpx.AsyncClient(timeout=300) as client:
                    response = await client.get(file_url)
                    
                    if response.status_code == 200:
                        with open(local_path, 'wb') as f:
                            f.write(response.content)
                        
                        results["files_downloaded"] += 1
                        results["total_size_bytes"] += len(response.content)
                        logger.info(f"Downloaded {filename} ({len(response.content)} bytes)")
                    else:
                        results["errors"].append(f"{filename}: HTTP {response.status_code}")
                        
            except Exception as e:
                results["errors"].append(f"{filename}: {str(e)}")
                logger.error(f"Failed to download {file_url}: {e}")
        
        results["success"] = len(results["errors"]) == 0
        return results
    
    async def sync_all_providers(self, force: bool = False) -> Dict[str, Any]:
        """
        Download/sync SNI data for all cloud providers.
        
        Args:
            force: Force re-download even if data exists
            
        Returns:
            Sync status for all providers
        """
        results = {
            "providers": {},
            "total_files_downloaded": 0,
            "total_size_bytes": 0,
            "started_at": datetime.utcnow().isoformat(),
        }
        
        for provider in CLOUD_PROVIDERS:
            provider_result = await self.download_provider_data(provider, force)
            results["providers"][provider] = provider_result
            results["total_files_downloaded"] += provider_result.get("files_downloaded", 0)
            results["total_size_bytes"] += provider_result.get("total_size_bytes", 0)
        
        results["completed_at"] = datetime.utcnow().isoformat()
        return results
    
    def _load_provider_data(self, provider: str) -> List[SNIRecord]:
        """Load SNI data from a provider's files."""
        records = []
        provider_dir = os.path.join(self.data_dir, provider)
        
        if not os.path.exists(provider_dir):
            return records
        
        config = CLOUD_PROVIDERS.get(provider, {})
        
        for filename in config.get("files", []):
            file_path = os.path.join(provider_dir, filename)
            
            if not os.path.exists(file_path):
                continue
            
            try:
                # Handle gzipped files
                if filename.endswith('.gz'):
                    with gzip.open(file_path, 'rt', encoding='utf-8') as f:
                        data = json.load(f)
                else:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                
                # Parse the data format
                # Expected format varies but typically: {ip: [sni1, sni2, ...]} or [{ip, sni, port}, ...]
                if isinstance(data, dict):
                    for ip, snis in data.items():
                        if isinstance(snis, list):
                            for sni in snis:
                                if isinstance(sni, str):
                                    records.append(SNIRecord(
                                        ip=ip,
                                        port=443,
                                        sni=sni.lower(),
                                        cloud_provider=provider,
                                    ))
                                elif isinstance(sni, dict):
                                    records.append(SNIRecord(
                                        ip=ip,
                                        port=sni.get("port", 443),
                                        sni=sni.get("sni", "").lower(),
                                        cloud_provider=provider,
                                    ))
                        elif isinstance(snis, str):
                            records.append(SNIRecord(
                                ip=ip,
                                port=443,
                                sni=snis.lower(),
                                cloud_provider=provider,
                            ))
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            records.append(SNIRecord(
                                ip=item.get("ip", ""),
                                port=item.get("port", 443),
                                sni=item.get("sni", "").lower(),
                                cloud_provider=provider,
                            ))
                
            except Exception as e:
                logger.error(f"Failed to load {file_path}: {e}")
        
        return records
    
    def _build_index(self) -> None:
        """Build in-memory index for fast searching."""
        if self._index_loaded:
            return
        
        logger.info("Building SNI search index...")
        start_time = datetime.utcnow()
        
        self._index = {}
        total_records = 0
        
        for provider in CLOUD_PROVIDERS:
            records = self._load_provider_data(provider)
            total_records += len(records)
            
            for record in records:
                # Index by domain parts for fast searching
                sni = record.sni
                if not sni:
                    continue
                
                # Add to full domain index
                if sni not in self._index:
                    self._index[sni] = []
                self._index[sni].append(record)
                
                # Also index by root domain
                parts = sni.split('.')
                if len(parts) >= 2:
                    root = '.'.join(parts[-2:])
                    if root not in self._index:
                        self._index[root] = []
                    if record not in self._index[root]:
                        self._index[root].append(record)
        
        self._index_loaded = True
        elapsed = (datetime.utcnow() - start_time).total_seconds()
        logger.info(f"SNI index built: {total_records} records, {len(self._index)} unique entries in {elapsed:.2f}s")
    
    async def search(
        self,
        query: str,
        search_type: str = "contains",  # exact, contains, endswith, regex
        providers: Optional[List[str]] = None,
        max_results: int = 10000,
    ) -> SNISearchResult:
        """
        Search SNI data for matching domains.
        
        Args:
            query: Domain/keyword to search for (e.g., "rockwellautomation")
            search_type: How to match - exact, contains, endswith, regex
            providers: Limit search to specific providers
            max_results: Maximum results to return
            
        Returns:
            SNISearchResult with discovered domains and IPs
        """
        result = SNISearchResult(query=query)
        start_time = datetime.utcnow()
        
        try:
            # Build index if needed
            self._build_index()
            
            query_lower = query.lower()
            matched_records: List[SNIRecord] = []
            
            # Different search strategies
            if search_type == "exact":
                # Exact domain match
                if query_lower in self._index:
                    matched_records.extend(self._index[query_lower])
                    
            elif search_type == "endswith":
                # Match domains ending with query (e.g., ".rockwellautomation.com")
                for domain, records in self._index.items():
                    if domain.endswith(query_lower):
                        matched_records.extend(records)
                        if len(matched_records) >= max_results:
                            break
                            
            elif search_type == "contains":
                # Match domains containing the query
                for domain, records in self._index.items():
                    if query_lower in domain:
                        matched_records.extend(records)
                        if len(matched_records) >= max_results:
                            break
                            
            elif search_type == "regex":
                # Regex matching
                try:
                    pattern = re.compile(query_lower, re.IGNORECASE)
                    for domain, records in self._index.items():
                        if pattern.search(domain):
                            matched_records.extend(records)
                            if len(matched_records) >= max_results:
                                break
                except re.error as e:
                    result.error = f"Invalid regex: {e}"
                    return result
            
            # Filter by providers if specified
            if providers:
                matched_records = [r for r in matched_records if r.cloud_provider in providers]
            
            # Deduplicate and aggregate
            seen_domains: Set[str] = set()
            seen_ips: Set[str] = set()
            by_provider: Dict[str, int] = {}
            
            for record in matched_records[:max_results]:
                result.records.append(record)
                
                if record.sni:
                    seen_domains.add(record.sni)
                    
                    # Categorize as domain or subdomain
                    parts = record.sni.split('.')
                    if len(parts) == 2:
                        result.domains.append(record.sni)
                    elif len(parts) > 2:
                        result.subdomains.append(record.sni)
                
                if record.ip:
                    seen_ips.add(record.ip)
                
                provider = record.cloud_provider
                by_provider[provider] = by_provider.get(provider, 0) + 1
            
            result.domains = sorted(list(set(result.domains)))
            result.subdomains = sorted(list(set(result.subdomains)))
            result.ips = sorted(list(seen_ips))
            result.total_records = len(matched_records)
            result.by_cloud_provider = by_provider
            result.success = True
            
            logger.info(
                f"SNI search '{query}' found {result.total_records} records, "
                f"{len(result.domains)} domains, {len(result.subdomains)} subdomains"
            )
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"SNI search error: {e}")
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def search_organization(
        self,
        org_name: str,
        primary_domain: Optional[str] = None,
        keywords: Optional[List[str]] = None,
    ) -> SNISearchResult:
        """
        Comprehensive organization search across all cloud providers.
        
        Searches for:
        1. Primary domain and all subdomains (e.g., *.rockwellautomation.com)
        2. Organization name anywhere in domain (e.g., *rockwellautomation*)
        3. Additional keywords if provided
        
        Args:
            org_name: Organization name (e.g., "rockwellautomation")
            primary_domain: Primary domain (e.g., "rockwellautomation.com")
            keywords: Additional keywords to search
            
        Returns:
            Combined SNISearchResult
        """
        result = SNISearchResult(query=org_name)
        start_time = datetime.utcnow()
        
        all_domains: Set[str] = set()
        all_subdomains: Set[str] = set()
        all_ips: Set[str] = set()
        all_records: List[SNIRecord] = []
        by_provider: Dict[str, int] = {}
        
        try:
            # 1. Search for primary domain subdomains
            if primary_domain:
                domain_result = await self.search(
                    f".{primary_domain}",
                    search_type="endswith"
                )
                if domain_result.success:
                    all_subdomains.update(domain_result.subdomains)
                    all_ips.update(domain_result.ips)
                    all_records.extend(domain_result.records)
                    for k, v in domain_result.by_cloud_provider.items():
                        by_provider[k] = by_provider.get(k, 0) + v
            
            # 2. Search for org name pattern
            org_result = await self.search(org_name, search_type="contains")
            if org_result.success:
                all_domains.update(org_result.domains)
                all_subdomains.update(org_result.subdomains)
                all_ips.update(org_result.ips)
                all_records.extend(org_result.records)
                for k, v in org_result.by_cloud_provider.items():
                    by_provider[k] = by_provider.get(k, 0) + v
            
            # 3. Search additional keywords
            if keywords:
                for keyword in keywords:
                    kw_result = await self.search(keyword, search_type="contains")
                    if kw_result.success:
                        all_domains.update(kw_result.domains)
                        all_subdomains.update(kw_result.subdomains)
                        all_ips.update(kw_result.ips)
                        all_records.extend(kw_result.records)
                        for k, v in kw_result.by_cloud_provider.items():
                            by_provider[k] = by_provider.get(k, 0) + v
            
            result.domains = sorted(list(all_domains))
            result.subdomains = sorted(list(all_subdomains))
            result.ips = sorted(list(all_ips))
            result.records = all_records
            result.total_records = len(all_records)
            result.by_cloud_provider = by_provider
            result.success = True
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"SNI organization search error: {e}")
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded SNI data."""
        stats = {
            "data_dir": self.data_dir,
            "index_loaded": self._index_loaded,
            "unique_domains": len(self._index) if self._index_loaded else 0,
            "providers": {},
        }
        
        for provider, config in CLOUD_PROVIDERS.items():
            provider_dir = os.path.join(self.data_dir, provider)
            provider_stats = {
                "name": config["name"],
                "files": [],
                "total_size_bytes": 0,
            }
            
            for filename in config["files"]:
                file_path = os.path.join(provider_dir, filename)
                if os.path.exists(file_path):
                    size = os.path.getsize(file_path)
                    mtime = os.path.getmtime(file_path)
                    provider_stats["files"].append({
                        "name": filename,
                        "size_bytes": size,
                        "last_modified": datetime.fromtimestamp(mtime).isoformat(),
                    })
                    provider_stats["total_size_bytes"] += size
            
            stats["providers"][provider] = provider_stats
        
        return stats


# Singleton instance
_sni_service: Optional[SNIScannerService] = None


def get_sni_service() -> SNIScannerService:
    """Get or create the SNI scanner service singleton."""
    global _sni_service
    if _sni_service is None:
        _sni_service = SNIScannerService()
    return _sni_service


# Convenience functions
async def search_sni(query: str, search_type: str = "contains") -> SNISearchResult:
    """Quick function to search SNI data."""
    service = get_sni_service()
    return await service.search(query, search_type)


async def discover_cloud_assets(
    org_name: str,
    primary_domain: Optional[str] = None,
    keywords: Optional[List[str]] = None,
) -> SNISearchResult:
    """Discover organization assets across cloud providers."""
    service = get_sni_service()
    return await service.search_organization(org_name, primary_domain, keywords)

