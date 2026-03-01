#!/usr/bin/env python3
"""
Bulk import domains and subdomains into the ASM inventory.

Usage:
    python scripts/bulk_import_domains.py --file domains.txt --org-id 1
    
    Or with inline data:
    python scripts/bulk_import_domains.py --org-id 1 < domains.txt
"""

import argparse
import sys
import os
from typing import List, Tuple
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import Session
from app.core.database import SessionLocal, engine
from app.models.asset import Asset, AssetType, AssetStatus


def parse_host_port(line: str) -> Tuple[str, int]:
    """Parse a hostname:port line and return (hostname, port)."""
    line = line.strip()
    if not line:
        return None, None
    
    # Handle IPv6 addresses with brackets
    if line.startswith('['):
        # IPv6 format: [::1]:port
        bracket_end = line.find(']')
        if bracket_end != -1 and len(line) > bracket_end + 1 and line[bracket_end + 1] == ':':
            host = line[1:bracket_end]
            port = int(line[bracket_end + 2:])
            return host, port
        return line, None
    
    # Standard hostname:port format
    if ':' in line:
        parts = line.rsplit(':', 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = None
        return host, port
    
    return line, None


def determine_asset_type(hostname: str) -> AssetType:
    """Determine if hostname is a domain or subdomain."""
    parts = hostname.lower().split('.')
    
    # Filter out empty parts
    parts = [p for p in parts if p]
    
    if len(parts) <= 2:
        # e.g., example.com, ab.com
        return AssetType.DOMAIN
    
    # Check for common TLDs that have two parts
    two_part_tlds = ['co.uk', 'com.au', 'co.nz', 'com.br', 'co.in', 'co.jp', 
                     'com.mx', 'co.za', 'com.ar', 'com.tw', 'com.cn', 'co.kr',
                     'com.co', 'com.ph', 'com.ve', 'com.pe', 'com.do', 'com.pr',
                     'com.bd', 'com.my', 'co.th', 'co.il', 'co.cr', 'com.vn']
    
    tld = '.'.join(parts[-2:])
    if tld in two_part_tlds:
        if len(parts) <= 3:
            return AssetType.DOMAIN
        return AssetType.SUBDOMAIN
    
    return AssetType.SUBDOMAIN


def extract_root_domain(hostname: str) -> str:
    """Extract the root domain from a hostname."""
    parts = hostname.lower().split('.')
    parts = [p for p in parts if p]
    
    if len(parts) <= 2:
        return hostname.lower()
    
    # Check for two-part TLDs
    two_part_tlds = ['co.uk', 'com.au', 'co.nz', 'com.br', 'co.in', 'co.jp',
                     'com.mx', 'co.za', 'com.ar', 'com.tw', 'com.cn', 'co.kr',
                     'com.co', 'com.ph', 'com.ve', 'com.pe', 'com.do', 'com.pr',
                     'com.bd', 'com.my', 'co.th', 'co.il', 'co.cr', 'com.vn']
    
    tld = '.'.join(parts[-2:])
    if tld in two_part_tlds:
        return '.'.join(parts[-3:])
    
    return '.'.join(parts[-2:])


def bulk_import_assets(
    db: Session,
    lines: List[str],
    organization_id: int,
    discovery_source: str = "bulk_import",
    batch_size: int = 100
) -> Tuple[int, int, int]:
    """
    Import assets from a list of hostname:port lines.
    
    Returns: (created_count, skipped_count, error_count)
    """
    created = 0
    skipped = 0
    errors = 0
    
    assets_to_create = []
    seen_values = set()
    
    # Get existing asset values for this org to check duplicates
    existing_values = set(
        db.query(Asset.value).filter(
            Asset.organization_id == organization_id
        ).all()
    )
    existing_values = {v[0].lower() for v in existing_values}
    
    print(f"Found {len(existing_values)} existing assets in organization {organization_id}")
    
    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        try:
            hostname, port = parse_host_port(line)
            if not hostname:
                continue
            
            hostname_lower = hostname.lower()
            
            # Skip duplicates within this import
            if hostname_lower in seen_values:
                skipped += 1
                continue
            
            # Skip if already exists in database
            if hostname_lower in existing_values:
                skipped += 1
                continue
            
            seen_values.add(hostname_lower)
            
            asset_type = determine_asset_type(hostname)
            root_domain = extract_root_domain(hostname)
            
            # Build endpoints list with port info
            endpoints = []
            if port:
                protocol = "https" if port == 443 else "http" if port == 80 else "unknown"
                endpoints.append({
                    "port": port,
                    "protocol": protocol,
                    "url": f"{protocol}://{hostname}:{port}" if port not in [80, 443] else f"{protocol}://{hostname}"
                })
            
            asset = Asset(
                name=hostname,
                asset_type=asset_type,
                value=hostname_lower,
                organization_id=organization_id,
                root_domain=root_domain,
                status=AssetStatus.DISCOVERED,
                discovery_source=discovery_source,
                endpoints=endpoints,
                is_monitored=True,
                is_public=True,
                in_scope=True,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                metadata_={"original_entry": line, "import_port": port} if port else {}
            )
            
            assets_to_create.append(asset)
            
            # Batch insert
            if len(assets_to_create) >= batch_size:
                db.bulk_save_objects(assets_to_create)
                db.commit()
                created += len(assets_to_create)
                print(f"  Imported {created} assets...")
                assets_to_create = []
                
        except Exception as e:
            errors += 1
            print(f"  Error processing line {i+1} '{line}': {e}")
    
    # Insert remaining assets
    if assets_to_create:
        db.bulk_save_objects(assets_to_create)
        db.commit()
        created += len(assets_to_create)
    
    return created, skipped, errors


def main():
    parser = argparse.ArgumentParser(description='Bulk import domains/subdomains into ASM inventory')
    parser.add_argument('--file', '-f', type=str, help='File containing hostname:port entries (one per line)')
    parser.add_argument('--org-id', '-o', type=int, required=True, help='Organization ID to associate assets with')
    parser.add_argument('--source', '-s', type=str, default='bulk_import', help='Discovery source label')
    parser.add_argument('--batch-size', '-b', type=int, default=100, help='Batch size for database inserts')
    parser.add_argument('--dry-run', '-d', action='store_true', help='Parse and validate without inserting')
    
    args = parser.parse_args()
    
    # Read input
    if args.file:
        with open(args.file, 'r') as f:
            lines = f.readlines()
    else:
        print("Reading from stdin (paste your list, then Ctrl+D to finish)...")
        lines = sys.stdin.readlines()
    
    print(f"\nParsed {len(lines)} lines")
    
    # Filter empty lines and comments
    valid_lines = [l for l in lines if l.strip() and not l.strip().startswith('#')]
    print(f"Found {len(valid_lines)} valid entries")
    
    if args.dry_run:
        print("\n=== DRY RUN - No changes will be made ===\n")
        
        # Show sample of what would be imported
        print("Sample entries (first 10):")
        for i, line in enumerate(valid_lines[:10]):
            hostname, port = parse_host_port(line)
            if hostname:
                asset_type = determine_asset_type(hostname)
                root_domain = extract_root_domain(hostname)
                print(f"  {hostname}:{port} -> {asset_type.value}, root: {root_domain}")
        
        if len(valid_lines) > 10:
            print(f"  ... and {len(valid_lines) - 10} more")
        
        return
    
    # Connect to database and import
    print(f"\nConnecting to database...")
    db = SessionLocal()
    
    try:
        print(f"Importing assets to organization {args.org_id}...")
        created, skipped, errors = bulk_import_assets(
            db=db,
            lines=valid_lines,
            organization_id=args.org_id,
            discovery_source=args.source,
            batch_size=args.batch_size
        )
        
        print(f"\n=== Import Complete ===")
        print(f"  Created: {created}")
        print(f"  Skipped (duplicates): {skipped}")
        print(f"  Errors: {errors}")
        
    finally:
        db.close()


if __name__ == '__main__':
    main()
