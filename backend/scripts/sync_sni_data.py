#!/usr/bin/env python3
"""
SNI IP Ranges Data Sync Script

Downloads SSL/TLS certificate data from kaeferjaeger.gay's cloud provider scans.
This data can be used to discover cloud-hosted assets.

Source: https://kaeferjaeger.gay/?dir=sni-ip-ranges

Cloud providers scanned:
- Amazon AWS
- Google Cloud
- Microsoft Azure
- Oracle Cloud
- DigitalOcean

Usage:
    python sync_sni_data.py [--force] [--providers aws,google,azure]
    
    --force     Force re-download even if data is recent
    --providers Comma-separated list of providers to sync (default: all)
    
To sync to S3 instead of local storage:
    export SNI_S3_BUCKET=my-bucket
    export SNI_S3_PREFIX=sni-ip-ranges/
    python sync_sni_data.py

Schedule this script to run weekly to keep data fresh:
    0 0 * * 0 /path/to/venv/bin/python /app/scripts/sync_sni_data.py >> /var/log/sni_sync.log 2>&1
"""

import argparse
import asyncio
import logging
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.sni_scanner_service import (
    SNIScannerService,
    CLOUD_PROVIDERS,
    get_sni_service,
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def sync_sni_data(
    providers: list = None,
    force: bool = False,
    upload_to_s3: bool = False,
    s3_bucket: str = None,
    s3_prefix: str = "sni-ip-ranges/"
):
    """
    Sync SNI data from kaeferjaeger.gay.
    
    Args:
        providers: List of providers to sync (default: all)
        force: Force re-download even if data exists and is recent
        upload_to_s3: Whether to upload to S3 after download
        s3_bucket: S3 bucket name
        s3_prefix: S3 key prefix
    """
    logger.info("=" * 60)
    logger.info("SNI IP Ranges Data Sync")
    logger.info("=" * 60)
    logger.info(f"Source: https://kaeferjaeger.gay/?dir=sni-ip-ranges")
    logger.info(f"Force: {force}")
    logger.info(f"Providers: {providers or 'all'}")
    
    # Get or create service
    service = get_sni_service()
    
    # Sync data
    if providers:
        # Validate providers
        invalid = [p for p in providers if p not in CLOUD_PROVIDERS]
        if invalid:
            logger.error(f"Invalid providers: {invalid}")
            logger.info(f"Valid providers: {list(CLOUD_PROVIDERS.keys())}")
            return
        
        results = {}
        for provider in providers:
            logger.info(f"\nSyncing {provider}...")
            result = await service.download_provider_data(provider, force)
            results[provider] = result
            
            if result.get("files_downloaded", 0) > 0:
                logger.info(f"  Downloaded {result['files_downloaded']} files")
                logger.info(f"  Size: {result['total_size_bytes']:,} bytes")
            if result.get("files_skipped", 0) > 0:
                logger.info(f"  Skipped {result['files_skipped']} files (recent)")
            if result.get("errors"):
                for err in result["errors"]:
                    logger.error(f"  Error: {err}")
    else:
        logger.info("\nSyncing all providers...")
        results = await service.sync_all_providers(force)
        
        for provider, result in results.get("providers", {}).items():
            logger.info(f"\n{provider}:")
            if result.get("files_downloaded", 0) > 0:
                logger.info(f"  Downloaded: {result['files_downloaded']} files")
            if result.get("files_skipped", 0) > 0:
                logger.info(f"  Skipped: {result['files_skipped']} files")
            if result.get("errors"):
                for err in result["errors"]:
                    logger.error(f"  Error: {err}")
        
        logger.info(f"\nTotal: {results.get('total_files_downloaded', 0)} files, "
                   f"{results.get('total_size_bytes', 0):,} bytes")
    
    # Upload to S3 if requested
    if upload_to_s3:
        s3_bucket = s3_bucket or os.environ.get("SNI_S3_BUCKET")
        if not s3_bucket:
            logger.error("S3 bucket not specified. Set SNI_S3_BUCKET or use --s3-bucket")
            return
        
        await upload_sni_to_s3(service.data_dir, s3_bucket, s3_prefix)
    
    # Print stats
    logger.info("\n" + "=" * 60)
    logger.info("Final Stats:")
    logger.info("=" * 60)
    
    stats = service.get_stats()
    logger.info(f"Data directory: {stats['data_dir']}")
    
    for provider, pstats in stats.get("providers", {}).items():
        if pstats.get("files"):
            total_size = pstats.get("total_size_bytes", 0)
            logger.info(f"\n{pstats['name']}:")
            for f in pstats["files"]:
                logger.info(f"  {f['name']}: {f['size_bytes']:,} bytes, "
                           f"modified {f['last_modified']}")
    
    logger.info("\n✓ Sync complete!")


async def upload_sni_to_s3(local_dir: str, bucket: str, prefix: str):
    """Upload SNI data to S3 for distributed access."""
    try:
        import boto3
        from pathlib import Path
        
        logger.info(f"\nUploading to S3: s3://{bucket}/{prefix}")
        
        s3 = boto3.client('s3')
        
        for provider in CLOUD_PROVIDERS:
            provider_dir = Path(local_dir) / provider
            if not provider_dir.exists():
                continue
            
            for file in provider_dir.glob("*"):
                if file.is_file():
                    s3_key = f"{prefix}{provider}/{file.name}"
                    logger.info(f"  Uploading {file.name} -> {s3_key}")
                    s3.upload_file(str(file), bucket, s3_key)
        
        logger.info("✓ S3 upload complete!")
        
    except ImportError:
        logger.error("boto3 not installed. Install with: pip install boto3")
    except Exception as e:
        logger.error(f"S3 upload failed: {e}")


async def search_test(org_name: str, domain: str = None, keywords: list = None):
    """Test search functionality."""
    logger.info("\n" + "=" * 60)
    logger.info(f"Test Search: {org_name}")
    logger.info("=" * 60)
    
    service = get_sni_service()
    
    result = await service.search_organization(
        org_name=org_name,
        primary_domain=domain,
        keywords=keywords
    )
    
    if result.success:
        logger.info(f"\nResults for '{org_name}':")
        logger.info(f"  Total records: {result.total_records}")
        logger.info(f"  Domains: {len(result.domains)}")
        logger.info(f"  Subdomains: {len(result.subdomains)}")
        logger.info(f"  IPs: {len(result.ips)}")
        logger.info(f"  By provider: {result.by_cloud_provider}")
        logger.info(f"  Elapsed time: {result.elapsed_time:.2f}s")
        
        if result.domains[:10]:
            logger.info(f"\nSample domains:")
            for d in result.domains[:10]:
                logger.info(f"    {d}")
        
        if result.subdomains[:10]:
            logger.info(f"\nSample subdomains:")
            for s in result.subdomains[:10]:
                logger.info(f"    {s}")
    else:
        logger.error(f"Search failed: {result.error}")


def main():
    parser = argparse.ArgumentParser(
        description="Sync SNI IP Ranges data for cloud asset discovery"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force re-download even if data is recent"
    )
    parser.add_argument(
        "--providers", "-p",
        type=str,
        help="Comma-separated list of providers (amazon,google,microsoft,oracle,digitalocean)"
    )
    parser.add_argument(
        "--upload-s3",
        action="store_true",
        help="Upload to S3 after download"
    )
    parser.add_argument(
        "--s3-bucket",
        type=str,
        help="S3 bucket for upload"
    )
    parser.add_argument(
        "--test-search",
        type=str,
        metavar="ORG_NAME",
        help="Test search functionality with given organization name"
    )
    parser.add_argument(
        "--test-domain",
        type=str,
        help="Primary domain for test search"
    )
    parser.add_argument(
        "--test-keywords",
        type=str,
        help="Comma-separated keywords for test search"
    )
    
    args = parser.parse_args()
    
    if args.test_search:
        # Run test search
        keywords = args.test_keywords.split(",") if args.test_keywords else None
        asyncio.run(search_test(
            org_name=args.test_search,
            domain=args.test_domain,
            keywords=keywords
        ))
    else:
        # Run sync
        providers = args.providers.split(",") if args.providers else None
        asyncio.run(sync_sni_data(
            providers=providers,
            force=args.force,
            upload_to_s3=args.upload_s3,
            s3_bucket=args.s3_bucket
        ))


if __name__ == "__main__":
    main()

