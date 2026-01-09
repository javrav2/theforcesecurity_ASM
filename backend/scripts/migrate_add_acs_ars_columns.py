#!/usr/bin/env python3
"""
Migration script to add ACS/ARS scoring and classification columns to assets table.

Run with:
    python -m scripts.migrate_add_acs_ars_columns

Or via Docker:
    sudo docker exec asm_backend python -m scripts.migrate_add_acs_ars_columns
"""

import sys
import os

# Add the parent directory to the path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import engine


def run_migration():
    """Add new ACS/ARS and classification columns to assets table."""
    
    # New columns to add with their SQL definitions
    new_columns = [
        # ACS/ARS scoring
        ("acs_score", "INTEGER DEFAULT 5"),
        ("acs_drivers", "JSON DEFAULT '{}'"),
        ("ars_score", "INTEGER DEFAULT 0"),
        
        # Asset Classification
        ("system_type", "VARCHAR(100)"),
        ("operating_system", "VARCHAR(200)"),
        ("device_class", "VARCHAR(100)"),
        ("device_subclass", "VARCHAR(200)"),
        ("is_public", "BOOLEAN DEFAULT TRUE"),
        ("is_licensed", "BOOLEAN DEFAULT TRUE"),
        
        # Scan tracking
        ("last_scan_id", "VARCHAR(100)"),
        ("last_scan_name", "VARCHAR(255)"),
        ("last_scan_date", "TIMESTAMP"),
        ("last_scan_target", "VARCHAR(500)"),
        ("last_authenticated_scan_status", "VARCHAR(50)"),
    ]
    
    with engine.connect() as conn:
        # Check which columns already exist
        result = conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'assets'
        """))
        existing_columns = {row[0] for row in result}
        
        print(f"Existing columns in assets table: {len(existing_columns)}")
        
        # Add missing columns
        added = 0
        for col_name, col_def in new_columns:
            if col_name not in existing_columns:
                try:
                    sql = f"ALTER TABLE assets ADD COLUMN {col_name} {col_def}"
                    print(f"Adding column: {col_name}")
                    conn.execute(text(sql))
                    added += 1
                except Exception as e:
                    print(f"  Warning: Could not add {col_name}: {e}")
            else:
                print(f"Column already exists: {col_name}")
        
        conn.commit()
        
        print(f"\nMigration complete! Added {added} new columns.")
        
        # Verify
        result = conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'assets'
            ORDER BY ordinal_position
        """))
        print("\nCurrent assets columns:")
        for row in result:
            print(f"  - {row[0]}")


if __name__ == "__main__":
    print("Running ACS/ARS migration...")
    run_migration()
