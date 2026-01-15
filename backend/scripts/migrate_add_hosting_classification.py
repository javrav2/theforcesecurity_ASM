#!/usr/bin/env python3
"""
Migration script to add hosting classification columns to the assets table.

This adds the following columns for IP address classification:
- hosting_type: Type of hosting (owned, cloud, cdn, third_party, unknown)
- hosting_provider: Cloud/CDN provider name (azure, aws, gcp, cloudflare, etc.)
- is_ephemeral_ip: Boolean indicating if the IP could change (cloud/CDN = ephemeral)
- resolved_from: Domain/subdomain this IP was resolved from via DNS

These columns help distinguish between:
1. Owned infrastructure (in org's CIDR blocks) - safe to scan directly
2. Cloud-hosted infrastructure (Azure, AWS, GCP) - ephemeral IPs, scan by hostname
3. CDN infrastructure (Cloudflare, Akamai) - shared IPs, never scan directly

Run this script on your EC2 instance:
    docker compose exec backend python scripts/migrate_add_hosting_classification.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import engine, SessionLocal


def check_column_exists(connection, table: str, column: str) -> bool:
    """Check if a column exists in a table."""
    result = connection.execute(text(f"""
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name = '{table}' AND column_name = '{column}'
    """))
    return result.fetchone() is not None


def migrate():
    """Add hosting classification columns to the assets table."""
    print("=" * 60)
    print("Asset Hosting Classification Migration Script")
    print("=" * 60)
    print("\nThis migration adds fields to classify IP addresses as owned vs cloud-hosted.")
    print("This helps prevent scanning cloud IPs that could belong to someone else.\n")
    
    with engine.connect() as conn:
        # Check and add hosting_type column
        if not check_column_exists(conn, 'assets', 'hosting_type'):
            print("Adding column: hosting_type")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN hosting_type VARCHAR(50)
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_hosting_type ON assets (hosting_type)"))
            print("  ✓ Added hosting_type column (owned, cloud, cdn, third_party, unknown)")
        else:
            print("  - hosting_type column already exists")
        
        # Check and add hosting_provider column
        if not check_column_exists(conn, 'assets', 'hosting_provider'):
            print("Adding column: hosting_provider")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN hosting_provider VARCHAR(100)
            """))
            print("  ✓ Added hosting_provider column (azure, aws, gcp, cloudflare, etc.)")
        else:
            print("  - hosting_provider column already exists")
        
        # Check and add is_ephemeral_ip column
        if not check_column_exists(conn, 'assets', 'is_ephemeral_ip'):
            print("Adding column: is_ephemeral_ip")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN is_ephemeral_ip BOOLEAN DEFAULT TRUE
            """))
            print("  ✓ Added is_ephemeral_ip column (default TRUE for safety)")
        else:
            print("  - is_ephemeral_ip column already exists")
        
        # Check and add resolved_from column
        if not check_column_exists(conn, 'assets', 'resolved_from'):
            print("Adding column: resolved_from")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN resolved_from VARCHAR(255)
            """))
            print("  ✓ Added resolved_from column (domain this IP was resolved from)")
        else:
            print("  - resolved_from column already exists")
        
        conn.commit()
        
        # Print summary
        print("\n" + "-" * 60)
        print("Column Summary:")
        print("-" * 60)
        print("""
hosting_type:
  - 'owned': IP is in org's CIDR blocks (from WhoisXML) - SAFE to scan directly
  - 'cloud': IP is in Azure/AWS/GCP range - EPHEMERAL, scan by hostname only
  - 'cdn': IP is in Cloudflare/Akamai range - SHARED, never scan directly
  - 'unknown': Unable to classify - assume ephemeral for safety

hosting_provider:
  - azure, aws, gcp, digitalocean, oracle, cloudflare, akamai, linode, etc.

is_ephemeral_ip:
  - TRUE: IP could change at any time (cloud/CDN hosted)
  - FALSE: IP is static (owned infrastructure)

resolved_from:
  - The domain or subdomain that this IP was resolved from via DNS
  - Example: "app.rockwellautomation.com" for IP 52.96.179.120
        """)
    
    print("\n" + "=" * 60)
    print("Migration complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Re-run discovery to classify existing IP assets")
    print("2. Or run: UPDATE assets SET hosting_type = 'unknown' WHERE asset_type = 'ip_address' AND hosting_type IS NULL")
    print("=" * 60)


if __name__ == "__main__":
    migrate()
