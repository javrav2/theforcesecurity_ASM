"""
SNI IP Ranges S3-backed Service for fast cloud asset lookups.

This service uses a pre-processed SNI domain index stored in S3
for fast organization/keyword searches. Similar to Common Crawl pattern.

Source: https://kaeferjaeger.gay/?dir=sni-ip-ranges

Architecture:
1. Download SNI data from kaeferjaeger.gay
2. Process and create searchable index (reversed domains + IP mapping)
3. Store compressed index in S3
4. Application downloads index to local cache on startup
5. Fast binary search for domain/keyword lookups
6. Background job updates weekly (source updates periodically)

S3 Structure:
  s3://your-bucket/sni-ip-ranges/
    ├── domains.txt.gz          # All domains (gzipped, sorted, reversed)
    ├── domain-ip-map.json.gz   # Domain to IP/provider mapping
    ├── metadata.json           # Index metadata (version, count, updated_at)
    └── by-provider/
        ├── amazon.txt.gz       # AWS-hosted domains
        ├── google.txt.gz       # GCP-hosted domains
        ├── microsoft.txt.gz    # Azure-hosted domains
        ├── oracle.txt.gz       # Oracle Cloud domains
        └── digitalocean.txt.gz # DigitalOcean domains
"""

import asyncio
import gzip
import json
import logging
import os
import shutil
import tempfile
from bisect import bisect_left
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

import httpx

logger = logging.getLogger(__name__)

# S3 paths
DEFAULT_S3_PREFIX = "sni-ip-ranges/"
DEFAULT_DOMAINS_KEY = "sni-ip-ranges/domains.txt.gz"
DEFAULT_MAPPING_KEY = "sni-ip-ranges/domain-ip-map.json.gz"
DEFAULT_METADATA_KEY = "sni-ip-ranges/metadata.json"
DEFAULT_LOCAL_CACHE_DIR = "/app/data/sni-ip-ranges"

# Source URLs
SNI_SOURCE_BASE = "https://kaeferjaeger.gay/sni-ip-ranges"
CLOUD_PROVIDERS = ["amazon", "google", "microsoft", "oracle", "digitalocean"]


@dataclass
class SNIIndexMetadata:
    """Metadata about the SNI index."""
    version: str = ""
    total_domains: int = 0
    total_ips: int = 0
    file_size_bytes: int = 0
    created_at: str = ""
    updated_at: str = ""
    by_provider: Dict[str, int] = field(default_factory=dict)
    source_url: str = "https://kaeferjaeger.gay/?dir=sni-ip-ranges"
    
    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "total_domains": self.total_domains,
            "total_ips": self.total_ips,
            "file_size_bytes": self.file_size_bytes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "by_provider": self.by_provider,
            "source_url": self.source_url,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "SNIIndexMetadata":
        return cls(
            version=data.get("version", ""),
            total_domains=data.get("total_domains", 0),
            total_ips=data.get("total_ips", 0),
            file_size_bytes=data.get("file_size_bytes", 0),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            by_provider=data.get("by_provider", {}),
            source_url=data.get("source_url", ""),
        )


@dataclass
class SNIS3SearchResult:
    """Result from S3-backed SNI lookup."""
    query: str
    domains: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    by_provider: Dict[str, List[str]] = field(default_factory=dict)
    total_records: int = 0
    elapsed_time: float = 0.0
    index_version: str = ""
    error: Optional[str] = None


class SNIS3Service:
    """
    S3-backed SNI IP Ranges service for fast cloud asset lookups.
    
    Usage:
        # Initialize with S3 bucket
        sni = SNIS3Service(s3_bucket="my-asm-bucket")
        
        # Sync from S3 to local cache
        await sni.sync_from_s3()
        
        # Search for organization
        result = await sni.search("rockwellautomation")
        print(result.domains, result.subdomains)
    """
    
    def __init__(
        self,
        s3_bucket: Optional[str] = None,
        s3_prefix: str = DEFAULT_S3_PREFIX,
        aws_region: str = "us-east-1",
        local_cache_dir: str = DEFAULT_LOCAL_CACHE_DIR,
        cache_ttl_hours: int = 24
    ):
        self.s3_bucket = s3_bucket or os.getenv("SNI_S3_BUCKET") or os.getenv("CC_S3_BUCKET")
        self.s3_prefix = s3_prefix
        self.aws_region = aws_region
        self.local_cache_dir = Path(local_cache_dir)
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        
        self._s3_client = None
        self._domains: List[str] = []  # Reversed domain list for binary search
        self._domain_ip_map: Dict[str, Dict[str, Any]] = {}  # domain -> {ips, provider}
        self._metadata: Optional[SNIIndexMetadata] = None
        self._loaded = False
        self._last_sync: Optional[datetime] = None
    
    @property
    def s3(self):
        """Lazy-load S3 client."""
        if self._s3_client is None:
            import boto3
            self._s3_client = boto3.client("s3", region_name=self.aws_region)
        return self._s3_client
    
    @property
    def local_index_path(self) -> Path:
        return self.local_cache_dir / "domains.txt"
    
    @property
    def local_mapping_path(self) -> Path:
        return self.local_cache_dir / "domain-ip-map.json"
    
    @property
    def local_metadata_path(self) -> Path:
        return self.local_cache_dir / "metadata.json"
    
    async def sync_from_s3(self, force: bool = False) -> bool:
        """
        Sync the SNI index from S3 to local cache.
        
        Returns:
            True if sync was successful
        """
        if not self.s3_bucket:
            logger.warning("SNI_S3_BUCKET not configured")
            return False
        
        if not force and self._is_cache_fresh():
            logger.debug("Local SNI cache is fresh")
            return True
        
        try:
            from botocore.exceptions import ClientError
            
            self.local_cache_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Syncing SNI index from s3://{self.s3_bucket}/{self.s3_prefix}")
            
            # Download metadata
            try:
                meta_key = f"{self.s3_prefix}metadata.json"
                response = self.s3.get_object(Bucket=self.s3_bucket, Key=meta_key)
                meta_content = response["Body"].read().decode("utf-8")
                self._metadata = SNIIndexMetadata.from_dict(json.loads(meta_content))
                
                with open(self.local_metadata_path, "w") as f:
                    f.write(meta_content)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchKey":
                    logger.warning("No SNI metadata in S3")
                    self._metadata = SNIIndexMetadata()
                else:
                    raise
            
            # Download domains index
            domains_key = f"{self.s3_prefix}domains.txt.gz"
            with tempfile.NamedTemporaryFile(delete=False, suffix=".gz") as tmp:
                self.s3.download_file(self.s3_bucket, domains_key, tmp.name)
                
                with gzip.open(tmp.name, "rt", encoding="utf-8") as gz:
                    with open(self.local_index_path, "w") as out:
                        shutil.copyfileobj(gz, out)
                
                os.unlink(tmp.name)
            
            # Download domain-IP mapping
            mapping_key = f"{self.s3_prefix}domain-ip-map.json.gz"
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".gz") as tmp:
                    self.s3.download_file(self.s3_bucket, mapping_key, tmp.name)
                    
                    with gzip.open(tmp.name, "rt", encoding="utf-8") as gz:
                        with open(self.local_mapping_path, "w") as out:
                            shutil.copyfileobj(gz, out)
                    
                    os.unlink(tmp.name)
            except ClientError:
                logger.warning("No domain-IP mapping in S3")
            
            self._last_sync = datetime.utcnow()
            logger.info(f"SNI index synced: {self._metadata.total_domains:,} domains")
            
            # Load into memory
            await self._load_index()
            return True
            
        except Exception as e:
            logger.error(f"Failed to sync SNI index: {e}")
            return False
    
    def _is_cache_fresh(self) -> bool:
        """Check if local cache is still valid."""
        if not self.local_index_path.exists():
            return False
        
        mtime = datetime.fromtimestamp(self.local_index_path.stat().st_mtime)
        return datetime.utcnow() - mtime < self.cache_ttl
    
    async def _load_index(self) -> bool:
        """Load the index into memory."""
        if not self.local_index_path.exists():
            return False
        
        try:
            # Load domains
            domains = []
            with open(self.local_index_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        domains.append(line)
            
            self._domains = sorted(domains)
            
            # Load mapping if exists
            if self.local_mapping_path.exists():
                with open(self.local_mapping_path, "r") as f:
                    self._domain_ip_map = json.load(f)
            
            self._loaded = True
            logger.info(f"Loaded {len(self._domains):,} SNI domains into memory")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load SNI index: {e}")
            return False
    
    async def search(
        self,
        query: str,
        search_type: str = "contains",
        max_results: int = 10000
    ) -> SNIS3SearchResult:
        """
        Search SNI data for matching domains.
        
        Args:
            query: Domain or keyword to search (e.g., "rockwellautomation")
            search_type: exact, contains, endswith, startswith
            max_results: Maximum results
            
        Returns:
            SNIS3SearchResult with domains, IPs, and provider info
        """
        result = SNIS3SearchResult(query=query)
        start_time = datetime.utcnow()
        
        if not self._loaded:
            if self.local_index_path.exists():
                await self._load_index()
            else:
                result.error = "Index not loaded. Call sync_from_s3() first."
                return result
        
        if not self._domains:
            result.error = "Domain index is empty"
            return result
        
        try:
            query_lower = query.lower()
            matched: Set[str] = set()
            
            if search_type == "exact":
                reversed_q = self._reverse_domain(query_lower)
                if reversed_q in self._domains:
                    matched.add(query_lower)
                    
            elif search_type == "endswith":
                # Search for *.domain.com
                reversed_prefix = self._reverse_domain(query_lower) + ","
                start_idx = bisect_left(self._domains, reversed_prefix)
                
                for i in range(start_idx, min(start_idx + max_results, len(self._domains))):
                    entry = self._domains[i]
                    if not entry.startswith(reversed_prefix):
                        break
                    matched.add(self._unreverse_domain(entry))
                    
            elif search_type == "contains":
                # Keyword search - must scan all
                for entry in self._domains:
                    if query_lower in entry:
                        matched.add(self._unreverse_domain(entry))
                        if len(matched) >= max_results:
                            break
                            
            elif search_type == "startswith":
                for entry in self._domains:
                    domain = self._unreverse_domain(entry)
                    if domain.startswith(query_lower):
                        matched.add(domain)
                        if len(matched) >= max_results:
                            break
            
            # Categorize results
            domains: Set[str] = set()
            subdomains: Set[str] = set()
            ips: Set[str] = set()
            by_provider: Dict[str, List[str]] = {}
            
            for domain in matched:
                parts = domain.split(".")
                if len(parts) == 2:
                    domains.add(domain)
                elif len(parts) > 2:
                    subdomains.add(domain)
                
                # Get IP/provider info from mapping
                if domain in self._domain_ip_map:
                    info = self._domain_ip_map[domain]
                    if "ips" in info:
                        ips.update(info["ips"])
                    if "provider" in info:
                        provider = info["provider"]
                        if provider not in by_provider:
                            by_provider[provider] = []
                        by_provider[provider].append(domain)
            
            result.domains = sorted(list(domains))
            result.subdomains = sorted(list(subdomains))
            result.ips = sorted(list(ips))
            result.by_provider = by_provider
            result.total_records = len(matched)
            result.index_version = self._metadata.version if self._metadata else ""
            
            logger.info(f"SNI S3 search '{query}': {result.total_records} matches")
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"SNI S3 search error: {e}")
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    async def search_organization(
        self,
        org_name: str,
        primary_domain: Optional[str] = None,
        keywords: Optional[List[str]] = None
    ) -> SNIS3SearchResult:
        """
        Comprehensive organization search.
        
        Combines:
        1. Subdomains of primary domain
        2. Domains containing org name
        3. Domains matching keywords
        """
        result = SNIS3SearchResult(query=org_name)
        start_time = datetime.utcnow()
        
        all_domains: Set[str] = set()
        all_subdomains: Set[str] = set()
        all_ips: Set[str] = set()
        by_provider: Dict[str, List[str]] = {}
        
        try:
            # 1. Subdomains of primary domain
            if primary_domain:
                sub_result = await self.search(primary_domain, search_type="endswith")
                all_subdomains.update(sub_result.subdomains)
                all_ips.update(sub_result.ips)
                for p, doms in sub_result.by_provider.items():
                    by_provider.setdefault(p, []).extend(doms)
            
            # 2. Org name search
            org_result = await self.search(org_name, search_type="contains")
            all_domains.update(org_result.domains)
            all_subdomains.update(org_result.subdomains)
            all_ips.update(org_result.ips)
            for p, doms in org_result.by_provider.items():
                by_provider.setdefault(p, []).extend(doms)
            
            # 3. Keywords
            if keywords:
                for kw in keywords:
                    kw_result = await self.search(kw, search_type="contains")
                    all_domains.update(kw_result.domains)
                    all_subdomains.update(kw_result.subdomains)
                    all_ips.update(kw_result.ips)
                    for p, doms in kw_result.by_provider.items():
                        by_provider.setdefault(p, []).extend(doms)
            
            result.domains = sorted(list(all_domains))
            result.subdomains = sorted(list(all_subdomains))
            result.ips = sorted(list(all_ips))
            result.by_provider = {p: list(set(d)) for p, d in by_provider.items()}
            result.total_records = len(all_domains) + len(all_subdomains)
            result.index_version = self._metadata.version if self._metadata else ""
            
        except Exception as e:
            result.error = str(e)
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    def _reverse_domain(self, domain: str) -> str:
        """Reverse domain: www.example.com -> com,example,www"""
        parts = domain.lower().split(".")
        return ",".join(reversed(parts))
    
    def _unreverse_domain(self, reversed_domain: str) -> str:
        """Unreverse: com,example,www -> www.example.com"""
        parts = reversed_domain.split(",")
        return ".".join(reversed(parts))
    
    async def get_stats(self) -> dict:
        return {
            "loaded": self._loaded,
            "domain_count": len(self._domains),
            "mapping_count": len(self._domain_ip_map),
            "cache_path": str(self.local_cache_dir),
            "cache_exists": self.local_index_path.exists(),
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "metadata": self._metadata.to_dict() if self._metadata else None,
            "s3_bucket": self.s3_bucket,
        }


# =============================================================================
# Index Builder - Downloads from kaeferjaeger.gay and uploads to S3
# =============================================================================

class SNIIndexBuilder:
    """
    Builds the SNI domain index from kaeferjaeger.gay and uploads to S3.
    
    Run weekly to keep data fresh.
    
    Usage:
        builder = SNIIndexBuilder(s3_bucket="my-asm-bucket")
        await builder.build_and_upload()
    """
    
    def __init__(
        self,
        s3_bucket: str,
        s3_prefix: str = DEFAULT_S3_PREFIX,
        aws_region: str = "us-east-1",
    ):
        self.s3_bucket = s3_bucket
        self.s3_prefix = s3_prefix
        self.aws_region = aws_region
        self._s3_client = None
    
    @property
    def s3(self):
        if self._s3_client is None:
            import boto3
            self._s3_client = boto3.client("s3", region_name=self.aws_region)
        return self._s3_client
    
    async def build_and_upload(
        self, 
        providers: Optional[List[str]] = None,
        use_txt_files: bool = True,
        from_s3_prefix: Optional[str] = None
    ) -> dict:
        """
        Download SNI data from source (or S3), process, and upload to S3.
        
        Args:
            providers: List of cloud providers to process
            use_txt_files: If True, use the large .txt files (streaming download)
                          If False, use smaller .json.gz files
            from_s3_prefix: If set, read raw files from this S3 prefix instead of source URL
                           e.g., "sni-ip-ranges/raw/" to read from s3://bucket/sni-ip-ranges/raw/amazon_ipv4_merged_sni.txt
        
        Returns:
            Summary of the build process
        """
        providers = providers or CLOUD_PROVIDERS
        
        logger.info(f"Building SNI index for providers: {providers}")
        if from_s3_prefix:
            logger.info(f"Reading from S3: s3://{self.s3_bucket}/{from_s3_prefix}")
        else:
            logger.info(f"Using {'TXT' if use_txt_files else 'JSON'} source files from kaeferjaeger.gay")
        start_time = datetime.utcnow()
        
        all_domains: Set[str] = set()
        domain_ip_map: Dict[str, Dict[str, Any]] = {}
        by_provider: Dict[str, int] = {}
        
        for provider in providers:
            try:
                if from_s3_prefix:
                    # Read from S3 bucket
                    domains, mapping = await self._read_from_s3(provider, from_s3_prefix)
                elif use_txt_files:
                    # Use streaming download for large .txt files
                    domains, mapping = await self._download_txt_streaming(provider)
                else:
                    # Use the smaller JSON files (original method)
                    domains, mapping = await self._download_json_gz(provider)
                
                all_domains.update(domains)
                domain_ip_map.update(mapping)
                by_provider[provider] = len(domains)
                logger.info(f"{provider}: {len(domains):,} domains")
                
            except Exception as e:
                logger.error(f"Error processing {provider}: {e}")
                import traceback
                traceback.print_exc()
        
        if not all_domains:
            return {"error": "No domains collected", "success": False}
        
        logger.info(f"Total domains collected: {len(all_domains):,}")
        
        # Sort domains for binary search
        sorted_domains = sorted(all_domains)
        
        # Write domains to temp file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            for domain in sorted_domains:
                f.write(domain + "\n")
            domains_temp = f.name
        
        # Compress domains
        domains_gz = domains_temp + ".gz"
        with open(domains_temp, "rb") as f_in:
            with gzip.open(domains_gz, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        domains_size = os.path.getsize(domains_gz)
        
        # Write mapping to temp file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
            json.dump(domain_ip_map, f)
            mapping_temp = f.name
        
        # Compress mapping
        mapping_gz = mapping_temp + ".gz"
        with open(mapping_temp, "rb") as f_in:
            with gzip.open(mapping_gz, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        mapping_size = os.path.getsize(mapping_gz)
        
        # Upload to S3 using multipart upload for large files
        from boto3.s3.transfer import TransferConfig
        
        # Configure multipart upload: 100MB chunks, 10 concurrent threads
        transfer_config = TransferConfig(
            multipart_threshold=100 * 1024 * 1024,  # 100MB threshold
            max_concurrency=10,
            multipart_chunksize=100 * 1024 * 1024,  # 100MB chunks
            use_threads=True
        )
        
        logger.info(f"Uploading domains.txt.gz ({domains_size / 1024 / 1024:.1f} MB)...")
        self.s3.upload_file(
            domains_gz, 
            self.s3_bucket, 
            f"{self.s3_prefix}domains.txt.gz",
            Config=transfer_config
        )
        
        logger.info(f"Uploading domain-ip-map.json.gz ({mapping_size / 1024 / 1024:.1f} MB)...")
        self.s3.upload_file(
            mapping_gz, 
            self.s3_bucket, 
            f"{self.s3_prefix}domain-ip-map.json.gz",
            Config=transfer_config
        )
        
        # Create and upload metadata
        metadata = SNIIndexMetadata(
            version=datetime.utcnow().strftime("%Y%m%d%H%M%S"),
            total_domains=len(sorted_domains),
            total_ips=len(set(ip for info in domain_ip_map.values() for ip in info.get("ips", []))),
            file_size_bytes=domains_size + mapping_size,
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
            by_provider=by_provider,
        )
        
        self.s3.put_object(
            Bucket=self.s3_bucket,
            Key=f"{self.s3_prefix}metadata.json",
            Body=json.dumps(metadata.to_dict(), indent=2),
            ContentType="application/json"
        )
        
        # Cleanup
        os.unlink(domains_temp)
        os.unlink(domains_gz)
        os.unlink(mapping_temp)
        os.unlink(mapping_gz)
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        result = {
            "success": True,
            "total_domains": len(sorted_domains),
            "total_ips": metadata.total_ips,
            "by_provider": by_provider,
            "domains_size_mb": round(domains_size / 1024 / 1024, 2),
            "mapping_size_mb": round(mapping_size / 1024 / 1024, 2),
            "duration_seconds": round(duration, 2),
            "s3_path": f"s3://{self.s3_bucket}/{self.s3_prefix}",
        }
        
        logger.info(f"SNI index uploaded: {result}")
        return result
    
    async def _download_txt_streaming(self, provider: str) -> tuple:
        """
        Stream download large .txt files to avoid memory issues.
        
        The .txt files are ~100-500MB each and contain lines like:
        IP_ADDRESS DOMAIN1 DOMAIN2 DOMAIN3 ...
        
        Returns:
            Tuple of (set of reversed domains, dict of domain->ip mapping)
        """
        url = f"{SNI_SOURCE_BASE}/{provider}/ipv4_merged_sni.txt"
        logger.info(f"Streaming download: {url}")
        
        domains: Set[str] = set()
        mapping: Dict[str, Dict[str, Any]] = {}
        
        # Use longer timeout and streaming for large files
        timeout = httpx.Timeout(
            connect=60.0,      # 60s to connect
            read=600.0,        # 10 minutes read timeout per chunk
            write=60.0,
            pool=60.0
        )
        
        # Create limits for connection pooling
        limits = httpx.Limits(
            max_keepalive_connections=5,
            max_connections=10,
            keepalive_expiry=30.0
        )
        
        line_count = 0
        domain_count = 0
        
        async with httpx.AsyncClient(timeout=timeout, limits=limits) as client:
            async with client.stream("GET", url) as response:
                if response.status_code != 200:
                    raise Exception(f"HTTP {response.status_code} for {url}")
                
                content_length = response.headers.get("content-length")
                if content_length:
                    logger.info(f"File size: {int(content_length) / 1024 / 1024:.1f} MB")
                
                buffer = ""
                bytes_received = 0
                last_log = datetime.utcnow()
                
                async for chunk in response.aiter_text(chunk_size=1024 * 1024):  # 1MB chunks
                    bytes_received += len(chunk.encode('utf-8'))
                    buffer += chunk
                    
                    # Process complete lines
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        line = line.strip()
                        
                        if not line:
                            continue
                        
                        line_count += 1
                        
                        # Parse line: IP DOMAIN1 DOMAIN2 ...
                        parts = line.split()
                        if len(parts) < 2:
                            continue
                        
                        ip = parts[0]
                        
                        for domain in parts[1:]:
                            domain = domain.lower().strip()
                            if domain and "." in domain:
                                reversed_d = self._reverse_domain(domain)
                                domains.add(reversed_d)
                                
                                if domain not in mapping:
                                    mapping[domain] = {
                                        "ips": [],
                                        "provider": provider
                                    }
                                if ip not in mapping[domain]["ips"]:
                                    mapping[domain]["ips"].append(ip)
                                
                                domain_count += 1
                    
                    # Log progress every 30 seconds
                    now = datetime.utcnow()
                    if (now - last_log).total_seconds() > 30:
                        mb_received = bytes_received / 1024 / 1024
                        logger.info(f"  {provider}: {mb_received:.1f} MB, {line_count:,} lines, {domain_count:,} domains")
                        last_log = now
                
                # Process any remaining buffer
                if buffer.strip():
                    line = buffer.strip()
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        for domain in parts[1:]:
                            domain = domain.lower().strip()
                            if domain and "." in domain:
                                reversed_d = self._reverse_domain(domain)
                                domains.add(reversed_d)
                                if domain not in mapping:
                                    mapping[domain] = {"ips": [ip], "provider": provider}
        
        logger.info(f"  {provider} complete: {line_count:,} lines, {len(domains):,} unique domains")
        return domains, mapping
    
    async def _download_json_gz(self, provider: str) -> tuple:
        """
        Download the smaller .json.gz files (original method).
        
        Returns:
            Tuple of (set of reversed domains, dict of domain->ip mapping)
        """
        url = f"{SNI_SOURCE_BASE}/{provider}/ipv4_merged_sni.json.gz"
        logger.info(f"Downloading {url}")
        
        domains: Set[str] = set()
        mapping: Dict[str, Dict[str, Any]] = {}
        
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.get(url)
            
            if response.status_code != 200:
                raise Exception(f"HTTP {response.status_code} for {url}")
            
            # Decompress and parse
            content = gzip.decompress(response.content)
            data = json.loads(content)
            
            # Parse format: {ip: [sni1, sni2, ...]} or {ip: {sni, port, ...}}
            if isinstance(data, dict):
                for ip, snis in data.items():
                    if isinstance(snis, list):
                        for sni in snis:
                            if isinstance(sni, str):
                                domain = sni.lower().strip()
                            elif isinstance(sni, dict):
                                domain = sni.get("sni", "").lower().strip()
                            else:
                                continue
                            
                            if domain and "." in domain:
                                reversed_d = self._reverse_domain(domain)
                                domains.add(reversed_d)
                                
                                if domain not in mapping:
                                    mapping[domain] = {"ips": [], "provider": provider}
                                if ip not in mapping[domain]["ips"]:
                                    mapping[domain]["ips"].append(ip)
                    
                    elif isinstance(snis, str):
                        domain = snis.lower().strip()
                        if domain and "." in domain:
                            reversed_d = self._reverse_domain(domain)
                            domains.add(reversed_d)
                            
                            if domain not in mapping:
                                mapping[domain] = {"ips": [ip], "provider": provider}
        
        return domains, mapping
    
    async def _read_from_s3(self, provider: str, s3_prefix: str) -> tuple:
        """
        Read SNI data from S3 bucket (pre-uploaded raw files).
        
        Expects files at: s3://bucket/{s3_prefix}{provider}_ipv4_merged_sni.txt
        
        Returns:
            Tuple of (set of reversed domains, dict of domain->ip mapping)
        """
        s3_key = f"{s3_prefix}{provider}_ipv4_merged_sni.txt"
        logger.info(f"Reading from S3: s3://{self.s3_bucket}/{s3_key}")
        
        domains: Set[str] = set()
        mapping: Dict[str, Dict[str, Any]] = {}
        
        # Download to temp file and process
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".txt") as tmp:
            tmp_path = tmp.name
        
        try:
            # Download from S3
            logger.info(f"Downloading {s3_key} to {tmp_path}...")
            self.s3.download_file(self.s3_bucket, s3_key, tmp_path)
            
            file_size = os.path.getsize(tmp_path)
            logger.info(f"Downloaded {file_size / 1024 / 1024:.1f} MB")
            
            # Process the file line by line
            line_count = 0
            domain_count = 0
            last_log = datetime.utcnow()
            
            with open(tmp_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    line_count += 1
                    
                    # Parse line: IP DOMAIN1 DOMAIN2 ...
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    
                    ip = parts[0]
                    
                    for domain in parts[1:]:
                        domain = domain.lower().strip()
                        if domain and "." in domain:
                            reversed_d = self._reverse_domain(domain)
                            domains.add(reversed_d)
                            
                            if domain not in mapping:
                                mapping[domain] = {
                                    "ips": [],
                                    "provider": provider
                                }
                            if ip not in mapping[domain]["ips"]:
                                mapping[domain]["ips"].append(ip)
                            
                            domain_count += 1
                    
                    # Log progress every 30 seconds
                    now = datetime.utcnow()
                    if (now - last_log).total_seconds() > 30:
                        logger.info(f"  {provider}: {line_count:,} lines, {domain_count:,} domains")
                        last_log = now
            
            logger.info(f"  {provider} complete: {line_count:,} lines, {len(domains):,} unique domains")
            
        finally:
            # Clean up temp file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        
        return domains, mapping
    
    def _reverse_domain(self, domain: str) -> str:
        parts = domain.lower().split(".")
        return ",".join(reversed(parts))


# =============================================================================
# Singleton and convenience functions
# =============================================================================

_sni_s3_service: Optional[SNIS3Service] = None


def get_sni_s3_service() -> SNIS3Service:
    """Get or create the SNI S3 service singleton."""
    global _sni_s3_service
    if _sni_s3_service is None:
        _sni_s3_service = SNIS3Service()
    return _sni_s3_service


async def search_sni_s3(query: str, search_type: str = "contains") -> SNIS3SearchResult:
    """Quick function to search SNI S3 index."""
    service = get_sni_s3_service()
    return await service.search(query, search_type)
