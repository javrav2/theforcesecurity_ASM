#!/usr/bin/env python3
"""
SNI IP Ranges Index Builder

Downloads SSL/TLS certificate data from kaeferjaeger.gay's cloud provider scans,
processes it into a searchable index, and uploads to S3.

Source: https://kaeferjaeger.gay/?dir=sni-ip-ranges

Cloud providers:
- Amazon AWS
- Google Cloud
- Microsoft Azure
- Oracle Cloud
- DigitalOcean

Usage:
    python update-index.py --bucket my-asm-bucket
    python update-index.py --bucket my-asm-bucket --providers amazon,microsoft
    
Schedule weekly:
    0 0 * * 0 /path/to/venv/bin/python /app/aws/sni-ip-ranges/update-index.py --bucket my-bucket
"""

import argparse
import asyncio
import logging
import os
import sys

# Add parent directories to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../backend"))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def build_index(
    s3_bucket: str,
    providers: list = None,
    s3_prefix: str = "sni-ip-ranges/",
    use_txt_files: bool = True,
    from_s3_prefix: str = None
):
    """Build and upload SNI index to S3."""
    from backend.app.services.sni_s3_service import SNIIndexBuilder, CLOUD_PROVIDERS
    
    logger.info("=" * 60)
    logger.info("SNI IP Ranges Index Builder")
    logger.info("=" * 60)
    logger.info(f"S3 Bucket: {s3_bucket}")
    logger.info(f"Output Prefix: {s3_prefix}")
    logger.info(f"Providers: {providers or 'all'}")
    
    if from_s3_prefix:
        logger.info(f"Source: S3 (s3://{s3_bucket}/{from_s3_prefix})")
    else:
        logger.info(f"Source: https://kaeferjaeger.gay/?dir=sni-ip-ranges")
        logger.info(f"Source files: {'TXT (large, streaming)' if use_txt_files else 'JSON.GZ (smaller)'}")
    
    if providers:
        invalid = [p for p in providers if p not in CLOUD_PROVIDERS]
        if invalid:
            logger.error(f"Invalid providers: {invalid}")
            logger.info(f"Valid: {CLOUD_PROVIDERS}")
            return
    
    builder = SNIIndexBuilder(
        s3_bucket=s3_bucket,
        s3_prefix=s3_prefix
    )
    
    result = await builder.build_and_upload(
        providers=providers, 
        use_txt_files=use_txt_files,
        from_s3_prefix=from_s3_prefix
    )
    
    if result.get("success"):
        logger.info("\n" + "=" * 60)
        logger.info("SUCCESS!")
        logger.info("=" * 60)
        logger.info(f"Total domains: {result['total_domains']:,}")
        logger.info(f"Total IPs: {result['total_ips']:,}")
        logger.info(f"By provider:")
        for p, count in result.get("by_provider", {}).items():
            logger.info(f"  {p}: {count:,}")
        logger.info(f"Domains file: {result['domains_size_mb']} MB")
        logger.info(f"Mapping file: {result['mapping_size_mb']} MB")
        logger.info(f"Duration: {result['duration_seconds']} seconds")
        logger.info(f"S3 Path: {result['s3_path']}")
    else:
        logger.error(f"Build failed: {result.get('error')}")


async def test_search(s3_bucket: str, query: str, domain: str = None):
    """Test search functionality."""
    from backend.app.services.sni_s3_service import SNIS3Service
    
    logger.info("\n" + "=" * 60)
    logger.info(f"Test Search: {query}")
    logger.info("=" * 60)
    
    service = SNIS3Service(s3_bucket=s3_bucket)
    
    # Sync from S3
    synced = await service.sync_from_s3()
    if not synced:
        logger.error("Failed to sync from S3")
        return
    
    # Search
    if domain:
        result = await service.search_organization(
            org_name=query,
            primary_domain=domain
        )
    else:
        result = await service.search(query, search_type="contains")
    
    if result.error:
        logger.error(f"Search error: {result.error}")
        return
    
    logger.info(f"\nResults for '{query}':")
    logger.info(f"  Total: {result.total_records}")
    logger.info(f"  Domains: {len(result.domains)}")
    logger.info(f"  Subdomains: {len(result.subdomains)}")
    logger.info(f"  IPs: {len(result.ips)}")
    logger.info(f"  Elapsed: {result.elapsed_time:.2f}s")
    
    if result.by_provider:
        logger.info(f"  By provider:")
        for p, doms in result.by_provider.items():
            logger.info(f"    {p}: {len(doms)}")
    
    if result.domains[:10]:
        logger.info(f"\nSample domains:")
        for d in result.domains[:10]:
            logger.info(f"  {d}")
    
    if result.subdomains[:10]:
        logger.info(f"\nSample subdomains:")
        for s in result.subdomains[:10]:
            logger.info(f"  {s}")


def main():
    parser = argparse.ArgumentParser(
        description="Build SNI IP Ranges index and upload to S3"
    )
    parser.add_argument(
        "--bucket", "-b",
        type=str,
        required=True,
        help="S3 bucket name"
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default="sni-ip-ranges/",
        help="S3 key prefix (default: sni-ip-ranges/)"
    )
    parser.add_argument(
        "--providers", "-p",
        type=str,
        help="Comma-separated list of providers (amazon,google,microsoft,oracle,digitalocean)"
    )
    parser.add_argument(
        "--test-search",
        type=str,
        metavar="QUERY",
        help="Test search with given query instead of building"
    )
    parser.add_argument(
        "--test-domain",
        type=str,
        help="Primary domain for test search"
    )
    parser.add_argument(
        "--use-txt",
        action="store_true",
        default=True,
        help="Use large .txt files with streaming (default: True)"
    )
    parser.add_argument(
        "--use-json",
        action="store_true",
        help="Use smaller .json.gz files instead of .txt"
    )
    parser.add_argument(
        "--from-s3",
        type=str,
        metavar="PREFIX",
        help="Read raw files from S3 instead of source URL (e.g., 'sni-ip-ranges/raw/')"
    )
    
    args = parser.parse_args()
    
    # Determine which source files to use
    use_txt = not args.use_json
    
    if args.test_search:
        asyncio.run(test_search(
            s3_bucket=args.bucket,
            query=args.test_search,
            domain=args.test_domain
        ))
    else:
        providers = args.providers.split(",") if args.providers else None
        asyncio.run(build_index(
            s3_bucket=args.bucket,
            providers=providers,
            s3_prefix=args.prefix,
            use_txt_files=use_txt,
            from_s3_prefix=args.from_s3
        ))


if __name__ == "__main__":
    main()
