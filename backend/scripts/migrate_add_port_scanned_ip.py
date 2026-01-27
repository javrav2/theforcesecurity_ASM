#!/usr/bin/env python3
"""
Migration script to add scanned_ip column to port_services table.

This column tracks the IP address where each port was discovered,
which is especially useful for domain assets that resolve to IPs.

Run with: docker exec asm_backend python scripts/migrate_add_port_scanned_ip.py
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import engine


def migrate():
    """Add scanned_ip column to port_services table."""
    
    with engine.connect() as conn:
        # Check if column already exists
        check_query = text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'port_services' 
            AND column_name = 'scanned_ip'
        """)
        result = conn.execute(check_query)
        if result.fetchone():
            print("✓ Column 'scanned_ip' already exists in port_services table")
            return
        
        # Add the column
        print("Adding 'scanned_ip' column to port_services table...")
        alter_query = text("""
            ALTER TABLE port_services 
            ADD COLUMN scanned_ip VARCHAR(45)
        """)
        conn.execute(alter_query)
        conn.commit()
        print("✓ Successfully added 'scanned_ip' column to port_services table")
        
        # Optionally: Backfill scanned_ip from asset IP addresses for existing records
        # This helps populate the field for existing port data
        print("\nBackfilling scanned_ip for existing port records...")
        backfill_query = text("""
            UPDATE port_services ps
            SET scanned_ip = a.ip_address
            FROM assets a
            WHERE ps.asset_id = a.id
            AND a.ip_address IS NOT NULL
            AND ps.scanned_ip IS NULL
            AND a.asset_type IN ('IP_ADDRESS')
        """)
        result = conn.execute(backfill_query)
        conn.commit()
        print(f"✓ Backfilled {result.rowcount} port records with IP addresses")


if __name__ == "__main__":
    print("=" * 60)
    print("Port Services scanned_ip Migration")
    print("=" * 60)
    try:
        migrate()
        print("\n✓ Migration completed successfully!")
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        sys.exit(1)
