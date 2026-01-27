#!/usr/bin/env python3
"""
Migration script to add discovery keyword columns to the organizations table.

This adds the following columns for persisting Common Crawl and SNI search keywords:
- commoncrawl_org_name: Organization name for TLD search (e.g., "rockwellautomation")
- commoncrawl_keywords: JSON array of keywords for wildcard search (e.g., ["rockwell", "allen-bradley"])
- sni_keywords: JSON array of keywords for SNI cloud asset discovery

Run this script on your EC2 instance:
    docker compose exec backend python scripts/migrate_add_discovery_keywords.py
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
    """Add discovery keyword columns to the organizations table."""
    print("=" * 60)
    print("Organizations Table Migration - Discovery Keywords")
    print("=" * 60)
    
    with engine.connect() as conn:
        # Check and add commoncrawl_org_name column
        if not check_column_exists(conn, 'organizations', 'commoncrawl_org_name'):
            print("Adding column: commoncrawl_org_name")
            conn.execute(text("""
                ALTER TABLE organizations 
                ADD COLUMN commoncrawl_org_name VARCHAR(255)
            """))
            print("  ✓ Added commoncrawl_org_name column")
        else:
            print("  - commoncrawl_org_name column already exists")
        
        # Check and add commoncrawl_keywords column
        if not check_column_exists(conn, 'organizations', 'commoncrawl_keywords'):
            print("Adding column: commoncrawl_keywords")
            conn.execute(text("""
                ALTER TABLE organizations 
                ADD COLUMN commoncrawl_keywords JSON DEFAULT '[]'::json
            """))
            print("  ✓ Added commoncrawl_keywords column")
        else:
            print("  - commoncrawl_keywords column already exists")
        
        # Check and add sni_keywords column
        if not check_column_exists(conn, 'organizations', 'sni_keywords'):
            print("Adding column: sni_keywords")
            conn.execute(text("""
                ALTER TABLE organizations 
                ADD COLUMN sni_keywords JSON DEFAULT '[]'::json
            """))
            print("  ✓ Added sni_keywords column")
        else:
            print("  - sni_keywords column already exists")
        
        conn.commit()
    
    print("\n" + "=" * 60)
    print("Migration complete!")
    print("=" * 60)
    print("\nYou can now configure discovery keywords in the Discovery page.")
    print("Keywords will be automatically used for Common Crawl and SNI searches.")


if __name__ == "__main__":
    migrate()
