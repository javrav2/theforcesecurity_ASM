#!/usr/bin/env python3
"""
Common Crawl Index Update Script

This script downloads domains from Common Crawl and uploads a processed
index to S3 for fast subdomain lookups.

Can be run:
- Manually: python update-index.py
- As a Lambda function
- As an ECS scheduled task
- Via cron/systemd timer

Usage:
    python update-index.py --bucket my-bucket --release CC-MAIN-2024-10

Environment Variables:
    CC_S3_BUCKET: S3 bucket name
    AWS_REGION: AWS region (default: us-east-1)
"""

import argparse
import asyncio
import gzip
import json
import logging
import os
import shutil
import sys
import tempfile
from datetime import datetime
from typing import Set
from urllib.parse import urlparse

import boto3
import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Common Crawl Index API
CC_INDEX_COLLECTIONS = "https://index.commoncrawl.org/collinfo.json"
CC_INDEX_API = "https://index.commoncrawl.org/{release}-index"

# S3 paths
S3_KEY = "commoncrawl/domains.txt.gz"
S3_METADATA_KEY = "commoncrawl/metadata.json"


def get_latest_cc_release() -> str:
    """Get the latest Common Crawl release ID."""
    try:
        import requests
        response = requests.get(CC_INDEX_COLLECTIONS, timeout=30)
        if response.status_code == 200:
            collections = response.json()
            if collections:
                return collections[0]["id"]
    except Exception as e:
        logger.warning(f"Could not get latest CC release: {e}")
    
    # Fallback to a known recent release
    return "CC-MAIN-2024-10"


async def collect_domains_from_cc(
    release: str,
    tlds: list = None,
    max_per_tld: int = 100000,
    max_total: int = 10_000_000
) -> Set[str]:
    """
    Collect domain names from Common Crawl Index API.
    
    Args:
        release: CC release ID (e.g., CC-MAIN-2024-10)
        tlds: TLDs to query (default: common ones)
        max_per_tld: Max domains per TLD
        max_total: Max total domains
        
    Returns:
        Set of reversed domain names (com,example,www format)
    """
    if tlds is None:
        tlds = [
            "com", "org", "net", "io", "co", "gov", "edu", "mil",
            "us", "uk", "de", "fr", "jp", "cn", "au", "ca", "in"
        ]
    
    domains: Set[str] = set()
    url = CC_INDEX_API.format(release=release)
    
    logger.info(f"Collecting domains from {release}")
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        for tld in tlds:
            if len(domains) >= max_total:
                logger.info(f"Reached max total domains: {max_total:,}")
                break
            
            try:
                logger.info(f"Querying .{tld} domains...")
                
                response = await client.get(
                    url,
                    params={
                        "url": f"*.{tld}/*",
                        "output": "json",
                        "limit": max_per_tld
                    }
                )
                
                if response.status_code == 200:
                    tld_count = 0
                    for line in response.text.strip().split("\n"):
                        if not line:
                            continue
                        try:
                            record = json.loads(line)
                            url_str = record.get("url", "")
                            if url_str:
                                parsed = urlparse(url_str)
                                hostname = parsed.netloc.lower()
                                
                                # Remove port
                                if ":" in hostname:
                                    hostname = hostname.split(":")[0]
                                
                                if hostname and "." in hostname:
                                    # Reverse for fast prefix search
                                    parts = hostname.split(".")
                                    reversed_domain = ",".join(reversed(parts))
                                    domains.add(reversed_domain)
                                    tld_count += 1
                        except Exception:
                            continue
                    
                    logger.info(f"  .{tld}: {tld_count:,} domains (total: {len(domains):,})")
                else:
                    logger.warning(f"  .{tld}: HTTP {response.status_code}")
                
            except httpx.TimeoutException:
                logger.warning(f"  .{tld}: Timeout")
            except Exception as e:
                logger.warning(f"  .{tld}: Error - {e}")
            
            # Rate limiting
            await asyncio.sleep(1)
    
    logger.info(f"Total unique domains collected: {len(domains):,}")
    return domains


def upload_to_s3(
    domains: Set[str],
    bucket: str,
    release: str,
    region: str = "us-east-1"
) -> dict:
    """
    Upload processed domain index to S3.
    
    Args:
        domains: Set of reversed domain names
        bucket: S3 bucket name
        release: CC release ID
        region: AWS region
        
    Returns:
        Upload summary
    """
    s3 = boto3.client("s3", region_name=region)
    
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
    
    file_size = os.path.getsize(compressed_path)
    
    # Upload index
    logger.info(f"Uploading to s3://{bucket}/{S3_KEY}")
    s3.upload_file(compressed_path, bucket, S3_KEY)
    
    # Also save a dated backup
    dated_key = f"commoncrawl/domains-{datetime.utcnow().strftime('%Y-%m')}.txt.gz"
    s3.upload_file(compressed_path, bucket, dated_key)
    
    # Create and upload metadata
    metadata = {
        "version": datetime.utcnow().strftime("%Y%m%d%H%M%S"),
        "cc_release": release,
        "domain_count": len(sorted_domains),
        "file_size_bytes": file_size,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat(),
    }
    
    s3.put_object(
        Bucket=bucket,
        Key=S3_METADATA_KEY,
        Body=json.dumps(metadata, indent=2),
        ContentType="application/json"
    )
    
    # Cleanup
    os.unlink(temp_path)
    os.unlink(compressed_path)
    
    return {
        "success": True,
        "domain_count": len(sorted_domains),
        "file_size_mb": round(file_size / 1024 / 1024, 2),
        "cc_release": release,
        "s3_path": f"s3://{bucket}/{S3_KEY}",
        "backup_path": f"s3://{bucket}/{dated_key}",
    }


async def main():
    parser = argparse.ArgumentParser(
        description="Update Common Crawl domain index in S3"
    )
    parser.add_argument(
        "--bucket",
        default=os.getenv("CC_S3_BUCKET"),
        help="S3 bucket name (or set CC_S3_BUCKET env var)"
    )
    parser.add_argument(
        "--release",
        default=None,
        help="CC release ID (e.g., CC-MAIN-2024-10). Default: latest"
    )
    parser.add_argument(
        "--region",
        default=os.getenv("AWS_REGION", "us-east-1"),
        help="AWS region"
    )
    parser.add_argument(
        "--max-domains",
        type=int,
        default=10_000_000,
        help="Maximum domains to collect"
    )
    
    args = parser.parse_args()
    
    if not args.bucket:
        print("Error: --bucket or CC_S3_BUCKET environment variable required")
        sys.exit(1)
    
    # Get release
    release = args.release or get_latest_cc_release()
    logger.info(f"Using CC release: {release}")
    
    # Collect domains
    domains = await collect_domains_from_cc(
        release=release,
        max_total=args.max_domains
    )
    
    if not domains:
        logger.error("No domains collected!")
        sys.exit(1)
    
    # Upload to S3
    result = upload_to_s3(
        domains=domains,
        bucket=args.bucket,
        release=release,
        region=args.region
    )
    
    logger.info(f"Upload complete: {json.dumps(result, indent=2)}")


# Lambda handler
def lambda_handler(event, context):
    """AWS Lambda entry point."""
    bucket = event.get("bucket") or os.getenv("CC_S3_BUCKET")
    release = event.get("release")
    
    if not bucket:
        return {"error": "No bucket specified"}
    
    result = asyncio.run(main())
    return result


if __name__ == "__main__":
    asyncio.run(main())

