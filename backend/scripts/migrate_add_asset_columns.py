#!/usr/bin/env python3
"""
Migration script to add missing columns to the assets table.

This adds the following columns that were added in recent updates:
- is_live: Boolean field indicating if the asset responded to probes
- endpoints: JSON field for discovered URL endpoints
- parameters: JSON field for discovered URL parameters
- js_files: JSON field for discovered JavaScript files

Run this script on your EC2 instance:
    docker compose exec backend python scripts/migrate_add_asset_columns.py
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
    """Add missing columns to the assets table."""
    print("=" * 60)
    print("Asset Table Migration Script")
    print("=" * 60)
    
    with engine.connect() as conn:
        # Check and add is_live column
        if not check_column_exists(conn, 'assets', 'is_live'):
            print("Adding column: is_live")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN is_live BOOLEAN DEFAULT FALSE
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_is_live ON assets (is_live)"))
            print("  ✓ Added is_live column")
        else:
            print("  - is_live column already exists")
        
        # Check and add endpoints column
        if not check_column_exists(conn, 'assets', 'endpoints'):
            print("Adding column: endpoints")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN endpoints JSON DEFAULT '[]'::json
            """))
            print("  ✓ Added endpoints column")
        else:
            print("  - endpoints column already exists")
        
        # Check and add parameters column
        if not check_column_exists(conn, 'assets', 'parameters'):
            print("Adding column: parameters")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN parameters JSON DEFAULT '[]'::json
            """))
            print("  ✓ Added parameters column")
        else:
            print("  - parameters column already exists")
        
        # Check and add js_files column
        if not check_column_exists(conn, 'assets', 'js_files'):
            print("Adding column: js_files")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN js_files JSON DEFAULT '[]'::json
            """))
            print("  ✓ Added js_files column")
        else:
            print("  - js_files column already exists")
        
        # Check and add in_scope column
        if not check_column_exists(conn, 'assets', 'in_scope'):
            print("Adding column: in_scope")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN in_scope BOOLEAN DEFAULT TRUE
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_in_scope ON assets (in_scope)"))
            print("  ✓ Added in_scope column")
        else:
            print("  - in_scope column already exists")
        
        # Check and add is_owned column
        if not check_column_exists(conn, 'assets', 'is_owned'):
            print("Adding column: is_owned")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN is_owned BOOLEAN DEFAULT FALSE
            """))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_assets_is_owned ON assets (is_owned)"))
            print("  ✓ Added is_owned column")
        else:
            print("  - is_owned column already exists")
        
        # Check and add netblock_id column
        if not check_column_exists(conn, 'assets', 'netblock_id'):
            print("Adding column: netblock_id")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN netblock_id INTEGER REFERENCES netblocks(id)
            """))
            print("  ✓ Added netblock_id column")
        else:
            print("  - netblock_id column already exists")
        
        # Check and add asn column
        if not check_column_exists(conn, 'assets', 'asn'):
            print("Adding column: asn")
            conn.execute(text("""
                ALTER TABLE assets 
                ADD COLUMN asn VARCHAR(50)
            """))
            print("  ✓ Added asn column")
        else:
            print("  - asn column already exists")
        
        conn.commit()
    
    print("\n" + "=" * 60)
    print("Migration complete!")
    print("=" * 60)


if __name__ == "__main__":
    migrate()

