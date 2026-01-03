"""
Common Crawl S3-backed Service for fast subdomain lookups.

This service uses a pre-processed Common Crawl domain index stored in S3
for fast lookups. The index is updated periodically via a scheduled job.

Architecture:
1. S3 bucket stores the processed CC domain index (sorted, reversed domains)
2. Application downloads index to local cache on startup/refresh
3. Fast binary search on local file for subdomain lookups
4. Background job updates the S3 index monthly (new CC releases)

S3 Structure:
  s3://your-bucket/commoncrawl/
    ├── domains.txt.gz          # Current domain index (gzipped, sorted)
    ├── domains-YYYY-MM.txt.gz  # Archived monthly snapshots
    └── metadata.json           # Index metadata (version, count, updated_at)
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
from typing import List, Optional, Set

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Default S3 paths
DEFAULT_S3_KEY = "commoncrawl/domains.txt.gz"
DEFAULT_METADATA_KEY = "commoncrawl/metadata.json"
DEFAULT_LOCAL_CACHE_DIR = "/app/data/commoncrawl"


@dataclass
class CCIndexMetadata:
    """Metadata about the Common Crawl index."""
    version: str = ""
    cc_release: str = ""  # e.g., "CC-MAIN-2024-10"
    domain_count: int = 0
    file_size_bytes: int = 0
    created_at: str = ""
    updated_at: str = ""
    
    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "cc_release": self.cc_release,
            "domain_count": self.domain_count,
            "file_size_bytes": self.file_size_bytes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "CCIndexMetadata":
        return cls(
            version=data.get("version", ""),
            cc_release=data.get("cc_release", ""),
            domain_count=data.get("domain_count", 0),
            file_size_bytes=data.get("file_size_bytes", 0),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


@dataclass
class CommonCrawlS3Result:
    """Result from S3-backed Common Crawl lookup."""
    domain: str
    subdomains: List[str] = field(default_factory=list)
    source: str = "commoncrawl-s3"
    elapsed_time: float = 0.0
    index_version: str = ""
    error: Optional[str] = None


class CommonCrawlS3Service:
    """
    S3-backed Common Crawl service for fast subdomain lookups.
    
    Usage:
        # Initialize with S3 bucket
        cc = CommonCrawlS3Service(
            s3_bucket="my-asm-bucket",
            aws_region="us-east-1"
        )
        
        # Ensure local cache is up-to-date
        await cc.sync_from_s3()
        
        # Search for subdomains
        result = await cc.search_domain("rockwellautomation.com")
        print(result.subdomains)
    """
    
    def __init__(
        self,
        s3_bucket: Optional[str] = None,
        s3_key: str = DEFAULT_S3_KEY,
        metadata_key: str = DEFAULT_METADATA_KEY,
        aws_region: str = "us-east-1",
        local_cache_dir: str = DEFAULT_LOCAL_CACHE_DIR,
        cache_ttl_hours: int = 24
    ):
        """
        Initialize S3-backed Common Crawl service.
        
        Args:
            s3_bucket: S3 bucket name (reads from CC_S3_BUCKET env if not provided)
            s3_key: S3 key for the domain index file
            metadata_key: S3 key for metadata JSON
            aws_region: AWS region
            local_cache_dir: Local directory to cache the index
            cache_ttl_hours: How long to keep local cache before refreshing
        """
        self.s3_bucket = s3_bucket or os.getenv("CC_S3_BUCKET")
        self.s3_key = s3_key
        self.metadata_key = metadata_key
        self.aws_region = aws_region
        self.local_cache_dir = Path(local_cache_dir)
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        
        self._s3_client = None
        self._domains: List[str] = []
        self._metadata: Optional[CCIndexMetadata] = None
        self._loaded = False
        self._last_sync: Optional[datetime] = None
    
    @property
    def s3(self):
        """Lazy-load S3 client."""
        if self._s3_client is None:
            self._s3_client = boto3.client("s3", region_name=self.aws_region)
        return self._s3_client
    
    @property
    def local_index_path(self) -> Path:
        """Path to local cached index file."""
        return self.local_cache_dir / "domains.txt"
    
    @property
    def local_metadata_path(self) -> Path:
        """Path to local cached metadata."""
        return self.local_cache_dir / "metadata.json"
    
    async def sync_from_s3(self, force: bool = False) -> bool:
        """
        Sync the domain index from S3 to local cache.
        
        Args:
            force: Force re-download even if cache is fresh
            
        Returns:
            True if sync was successful
        """
        if not self.s3_bucket:
            logger.warning("CC_S3_BUCKET not configured, S3 sync disabled")
            return False
        
        # Check if cache is fresh
        if not force and self._is_cache_fresh():
            logger.debug("Local CC index cache is fresh, skipping sync")
            return True
        
        try:
            self.local_cache_dir.mkdir(parents=True, exist_ok=True)
            
            # Download metadata first
            logger.info(f"Syncing CC index from s3://{self.s3_bucket}/{self.s3_key}")
            
            try:
                meta_response = self.s3.get_object(
                    Bucket=self.s3_bucket,
                    Key=self.metadata_key
                )
                meta_content = meta_response["Body"].read().decode("utf-8")
                self._metadata = CCIndexMetadata.from_dict(json.loads(meta_content))
                
                with open(self.local_metadata_path, "w") as f:
                    f.write(meta_content)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchKey":
                    logger.warning("No metadata file in S3, creating default")
                    self._metadata = CCIndexMetadata()
                else:
                    raise
            
            # Download the gzipped index
            with tempfile.NamedTemporaryFile(delete=False, suffix=".gz") as tmp:
                self.s3.download_file(self.s3_bucket, self.s3_key, tmp.name)
                
                # Decompress to local cache
                with gzip.open(tmp.name, "rt", encoding="utf-8") as gz:
                    with open(self.local_index_path, "w") as out:
                        shutil.copyfileobj(gz, out)
                
                os.unlink(tmp.name)
            
            self._last_sync = datetime.utcnow()
            logger.info(f"CC index synced: {self._metadata.domain_count:,} domains")
            
            # Reload into memory
            await self._load_index()
            return True
            
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                logger.warning(f"CC index not found in S3: {self.s3_key}")
            else:
                logger.error(f"S3 sync error: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to sync CC index: {e}")
            return False
    
    def _is_cache_fresh(self) -> bool:
        """Check if local cache is still valid."""
        if not self.local_index_path.exists():
            return False
        
        if self._last_sync is None:
            # Check file modification time
            mtime = datetime.fromtimestamp(self.local_index_path.stat().st_mtime)
            if datetime.utcnow() - mtime > self.cache_ttl:
                return False
        else:
            if datetime.utcnow() - self._last_sync > self.cache_ttl:
                return False
        
        return True
    
    async def _load_index(self) -> bool:
        """Load the domain index into memory for fast lookups."""
        if not self.local_index_path.exists():
            logger.warning("Local CC index not found, call sync_from_s3() first")
            return False
        
        try:
            # Load domains into sorted list for binary search
            domains = []
            with open(self.local_index_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        domains.append(line)
            
            self._domains = sorted(domains)
            self._loaded = True
            logger.info(f"Loaded {len(self._domains):,} domains into memory")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load CC index: {e}")
            return False
    
    async def search_domain(self, domain: str) -> CommonCrawlS3Result:
        """
        Search for subdomains of a domain using binary search.
        
        The index stores domains in reversed format (com,rockwellautomation,www)
        for efficient prefix matching.
        
        Args:
            domain: Base domain to search (e.g., rockwellautomation.com)
            
        Returns:
            CommonCrawlS3Result with discovered subdomains
        """
        result = CommonCrawlS3Result(domain=domain)
        start_time = datetime.utcnow()
        
        # Ensure index is loaded
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
            # Reverse domain for prefix matching
            reversed_prefix = self._reverse_domain(domain) + ","
            
            # Binary search for the range
            subdomains: Set[str] = set()
            
            # Find start position
            start_idx = bisect_left(self._domains, reversed_prefix)
            
            # Iterate through matching entries
            for i in range(start_idx, len(self._domains)):
                entry = self._domains[i]
                if not entry.startswith(reversed_prefix):
                    break
                
                # Convert back to normal domain
                subdomain = self._unreverse_domain(entry)
                if subdomain and subdomain != domain:
                    subdomains.add(subdomain)
            
            result.subdomains = sorted(list(subdomains))
            result.index_version = self._metadata.version if self._metadata else ""
            
            logger.info(f"CC S3 search found {len(result.subdomains)} subdomains for {domain}")
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"CC S3 search error: {e}")
        
        result.elapsed_time = (datetime.utcnow() - start_time).total_seconds()
        return result
    
    def _reverse_domain(self, domain: str) -> str:
        """Reverse domain parts: www.example.com -> com,example,www"""
        parts = domain.lower().split(".")
        return ",".join(reversed(parts))
    
    def _unreverse_domain(self, reversed_domain: str) -> str:
        """Unreverse domain: com,example,www -> www.example.com"""
        parts = reversed_domain.split(",")
        return ".".join(reversed(parts))
    
    async def get_stats(self) -> dict:
        """Get statistics about the loaded index."""
        return {
            "loaded": self._loaded,
            "domain_count": len(self._domains),
            "cache_path": str(self.local_index_path),
            "cache_exists": self.local_index_path.exists(),
            "last_sync": self._last_sync.isoformat() if self._last_sync else None,
            "metadata": self._metadata.to_dict() if self._metadata else None,
            "s3_bucket": self.s3_bucket,
            "s3_key": self.s3_key,
        }


# =============================================================================
# Index Builder - For creating/updating the S3 index
# =============================================================================

class CommonCrawlIndexBuilder:
    """
    Builds and uploads the Common Crawl domain index to S3.
    
    This should be run periodically (monthly) when new CC releases come out.
    Can be run as a Lambda function or ECS task.
    
    Usage:
        builder = CommonCrawlIndexBuilder(
            s3_bucket="my-asm-bucket",
            cc_release="CC-MAIN-2024-10"
        )
        await builder.build_and_upload()
    """
    
    # Common Crawl index API
    CC_INDEX_API = "https://index.commoncrawl.org/{release}-index"
    
    def __init__(
        self,
        s3_bucket: str,
        cc_release: str = "CC-MAIN-2024-10",
        aws_region: str = "us-east-1",
        max_domains: int = 50_000_000,  # Limit for memory/storage
        batch_size: int = 10000
    ):
        self.s3_bucket = s3_bucket
        self.cc_release = cc_release
        self.aws_region = aws_region
        self.max_domains = max_domains
        self.batch_size = batch_size
        self._s3_client = None
    
    @property
    def s3(self):
        if self._s3_client is None:
            self._s3_client = boto3.client("s3", region_name=self.aws_region)
        return self._s3_client
    
    async def build_and_upload(self) -> dict:
        """
        Build the domain index from Common Crawl and upload to S3.
        
        Returns:
            Summary of the build process
        """
        import httpx
        
        logger.info(f"Building CC index from {self.cc_release}")
        start_time = datetime.utcnow()
        
        domains: Set[str] = set()
        
        # Query CC Index for all URLs (paginated)
        # We search for common TLDs to get a broad sample
        tlds = ["com", "org", "net", "io", "co", "gov", "edu"]
        
        async with httpx.AsyncClient(timeout=120.0) as client:
            for tld in tlds:
                if len(domains) >= self.max_domains:
                    break
                
                try:
                    url = self.CC_INDEX_API.format(release=self.cc_release)
                    response = await client.get(
                        url,
                        params={
                            "url": f"*.{tld}/*",
                            "output": "json",
                            "limit": 100000
                        }
                    )
                    
                    if response.status_code == 200:
                        for line in response.text.strip().split("\n"):
                            if not line:
                                continue
                            try:
                                record = json.loads(line)
                                url_str = record.get("url", "")
                                if url_str:
                                    from urllib.parse import urlparse
                                    parsed = urlparse(url_str)
                                    hostname = parsed.netloc.lower()
                                    if ":" in hostname:
                                        hostname = hostname.split(":")[0]
                                    if hostname:
                                        # Store in reversed format for fast prefix search
                                        reversed_domain = self._reverse_domain(hostname)
                                        domains.add(reversed_domain)
                            except Exception:
                                continue
                    
                    logger.info(f"Collected {len(domains):,} domains from .{tld}")
                    
                except Exception as e:
                    logger.warning(f"Error collecting .{tld}: {e}")
                
                await asyncio.sleep(1)  # Rate limiting
        
        if not domains:
            return {"error": "No domains collected", "success": False}
        
        # Sort domains for binary search
        sorted_domains = sorted(domains)
        
        # Write to temp file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
            for domain in sorted_domains:
                f.write(domain + "\n")
            temp_path = f.name
        
        # Compress
        compressed_path = temp_path + ".gz"
        with open(temp_path, "rb") as f_in:
            with gzip.open(compressed_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        # Upload to S3
        file_size = os.path.getsize(compressed_path)
        
        self.s3.upload_file(
            compressed_path,
            self.s3_bucket,
            DEFAULT_S3_KEY
        )
        
        # Create and upload metadata
        metadata = CCIndexMetadata(
            version=datetime.utcnow().strftime("%Y%m%d%H%M%S"),
            cc_release=self.cc_release,
            domain_count=len(sorted_domains),
            file_size_bytes=file_size,
            created_at=datetime.utcnow().isoformat(),
            updated_at=datetime.utcnow().isoformat(),
        )
        
        self.s3.put_object(
            Bucket=self.s3_bucket,
            Key=DEFAULT_METADATA_KEY,
            Body=json.dumps(metadata.to_dict(), indent=2),
            ContentType="application/json"
        )
        
        # Cleanup
        os.unlink(temp_path)
        os.unlink(compressed_path)
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        result = {
            "success": True,
            "domain_count": len(sorted_domains),
            "file_size_mb": round(file_size / 1024 / 1024, 2),
            "cc_release": self.cc_release,
            "duration_seconds": round(duration, 2),
            "s3_path": f"s3://{self.s3_bucket}/{DEFAULT_S3_KEY}"
        }
        
        logger.info(f"CC index uploaded: {result}")
        return result
    
    def _reverse_domain(self, domain: str) -> str:
        parts = domain.lower().split(".")
        return ",".join(reversed(parts))

