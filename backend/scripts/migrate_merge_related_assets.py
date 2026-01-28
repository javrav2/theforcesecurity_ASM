#!/usr/bin/env python3
"""
Migration script to merge related assets.

This script:
1. Merges IP assets into their parent domain assets
2. Merges duplicate domain records
3. Consolidates findings, ports, and other data

Run with:
    python scripts/migrate_merge_related_assets.py [--org-id ORG_ID] [--dry-run]

The merge follows this model:
- Domain/subdomain is the canonical asset
- IP addresses are attributes on the domain, not separate assets
- Findings found on an IP are linked to the domain that resolves to it
"""

import sys
import os
import argparse
import logging

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.db.database import SessionLocal
from app.models.asset import Asset, AssetType
from app.models.organization import Organization
from app.services.asset_merge_service import get_asset_merge_service

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def run_migration(org_id: int = None, dry_run: bool = True):
    """Run the asset merge migration."""
    db = SessionLocal()
    
    try:
        # Get organizations to process
        if org_id:
            orgs = db.query(Organization).filter(Organization.id == org_id).all()
        else:
            orgs = db.query(Organization).all()
        
        if not orgs:
            logger.error("No organizations found")
            return
        
        total_results = {
            "organizations_processed": 0,
            "ip_merges": 0,
            "domain_merges": 0,
            "errors": 0,
        }
        
        for org in orgs:
            logger.info(f"\n{'='*60}")
            logger.info(f"Processing organization: {org.name} (ID: {org.id})")
            logger.info(f"{'='*60}")
            
            service = get_asset_merge_service(db)
            
            # Preview what will be merged
            preview = service.find_mergeable_assets(org.id)
            
            logger.info(f"\nMergeable assets found:")
            logger.info(f"  - IP to Domain merges: {len(preview['ip_to_domain_merges'])}")
            logger.info(f"  - Duplicate domains: {len(preview['duplicate_domains'])}")
            logger.info(f"  - Total mergeable: {preview['total_mergeable']}")
            
            if preview['ip_to_domain_merges']:
                logger.info(f"\nIP to Domain merges preview:")
                for merge in preview['ip_to_domain_merges'][:10]:  # Show first 10
                    logger.info(f"  - IP {merge['ip_value']} -> Domain {merge['domain_value']}")
                    logger.info(f"    ({merge['ip_vulns_count']} vulns, {merge['ip_ports_count']} ports)")
                if len(preview['ip_to_domain_merges']) > 10:
                    logger.info(f"  ... and {len(preview['ip_to_domain_merges']) - 10} more")
            
            if preview['duplicate_domains']:
                logger.info(f"\nDuplicate domains preview:")
                for dup in preview['duplicate_domains'][:10]:
                    logger.info(f"  - {dup['value']}: {dup['count']} records (IDs: {dup['asset_ids']})")
            
            if dry_run:
                logger.info(f"\n[DRY RUN] No changes made. Run with --execute to apply changes.")
                continue
            
            # Execute merges
            logger.info(f"\nExecuting merges...")
            
            # IP to domain merges
            ip_merge_count = 0
            for merge in preview['ip_to_domain_merges']:
                try:
                    result = service.merge_ip_into_domain(
                        merge['ip_asset_id'],
                        merge['domain_asset_id'],
                        delete_ip_asset=True
                    )
                    ip_merge_count += 1
                    logger.info(f"  ✓ Merged IP {merge['ip_value']} -> {merge['domain_value']}")
                except Exception as e:
                    logger.error(f"  ✗ Error merging IP {merge['ip_value']}: {e}")
                    total_results["errors"] += 1
            
            # Duplicate domain merges
            domain_merge_count = 0
            for dup in preview['duplicate_domains']:
                try:
                    result = service.merge_duplicate_domains(dup['asset_ids'])
                    domain_merge_count += 1
                    logger.info(f"  ✓ Merged {dup['count']} duplicates of {dup['value']}")
                except Exception as e:
                    logger.error(f"  ✗ Error merging duplicates for {dup['value']}: {e}")
                    total_results["errors"] += 1
            
            total_results["organizations_processed"] += 1
            total_results["ip_merges"] += ip_merge_count
            total_results["domain_merges"] += domain_merge_count
            
            logger.info(f"\nOrganization {org.name} complete:")
            logger.info(f"  - IP merges: {ip_merge_count}")
            logger.info(f"  - Domain merges: {domain_merge_count}")
        
        # Summary
        logger.info(f"\n{'='*60}")
        logger.info("MIGRATION SUMMARY")
        logger.info(f"{'='*60}")
        logger.info(f"Organizations processed: {total_results['organizations_processed']}")
        logger.info(f"IP to Domain merges: {total_results['ip_merges']}")
        logger.info(f"Duplicate domain merges: {total_results['domain_merges']}")
        logger.info(f"Errors: {total_results['errors']}")
        
        if dry_run:
            logger.info("\n[DRY RUN] No changes were made.")
            logger.info("Run with --execute to apply the merges.")
        else:
            logger.info("\n✓ Migration complete!")
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        db.rollback()
        raise
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(description="Merge related assets")
    parser.add_argument("--org-id", type=int, help="Organization ID to process (default: all)")
    parser.add_argument("--dry-run", action="store_true", default=True,
                       help="Preview changes without applying (default)")
    parser.add_argument("--execute", action="store_true",
                       help="Actually apply the merges")
    
    args = parser.parse_args()
    
    dry_run = not args.execute
    
    if not dry_run:
        confirm = input("This will merge assets and cannot be undone. Type 'yes' to continue: ")
        if confirm.lower() != 'yes':
            print("Aborted.")
            return
    
    run_migration(org_id=args.org_id, dry_run=dry_run)


if __name__ == "__main__":
    main()
