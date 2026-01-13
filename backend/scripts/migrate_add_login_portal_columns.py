#!/usr/bin/env python3
"""
Migration script to add login portal detection columns to assets table.

Run with:
    docker exec asm_backend python /app/scripts/migrate_add_login_portal_columns.py
"""

import os
import sys

# Add the app directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, text
from app.core.config import settings


def run_migration():
    """Add login portal columns to assets table."""
    engine = create_engine(settings.DATABASE_URL)
    
    migrations = [
        # Login portal detection flag
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS has_login_portal BOOLEAN DEFAULT FALSE",
        
        # List of detected login portals on this asset
        "ALTER TABLE assets ADD COLUMN IF NOT EXISTS login_portals JSON DEFAULT '[]'::json",
        
        # Create index for faster filtering
        "CREATE INDEX IF NOT EXISTS idx_assets_has_login_portal ON assets(has_login_portal) WHERE has_login_portal = TRUE",
    ]
    
    with engine.connect() as conn:
        for migration in migrations:
            try:
                print(f"Running: {migration[:60]}...")
                conn.execute(text(migration))
                conn.commit()
                print("  ✓ Success")
            except Exception as e:
                if "already exists" in str(e).lower():
                    print(f"  ⚠ Already exists, skipping")
                else:
                    print(f"  ✗ Error: {e}")
    
    print("\n✓ Migration complete!")
    print("\nNew columns added:")
    print("  - has_login_portal: Boolean flag indicating asset has login pages")
    print("  - login_portals: JSON array of detected login URLs on this asset")


if __name__ == "__main__":
    run_migration()
