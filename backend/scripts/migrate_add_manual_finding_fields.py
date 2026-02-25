#!/usr/bin/env python3
"""
Migration script to add manual pentest finding fields to vulnerabilities table.

Run with:
    python -m scripts.migrate_add_manual_finding_fields

Or via Docker:
    sudo docker exec asm_backend python -m scripts.migrate_add_manual_finding_fields
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import engine


def run_migration():
    """Add manual finding fields to vulnerabilities table."""
    
    new_columns = [
        ("is_manual", "BOOLEAN DEFAULT FALSE"),
        ("impact", "TEXT"),
        ("affected_component", "VARCHAR(500)"),
        ("steps_to_reproduce", "TEXT"),
    ]
    
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'vulnerabilities'
        """))
        existing_columns = {row[0] for row in result}
        
        print(f"Existing columns in vulnerabilities table: {len(existing_columns)}")
        
        added = 0
        for col_name, col_def in new_columns:
            if col_name not in existing_columns:
                try:
                    sql = f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_def}"
                    print(f"Adding column: {col_name}")
                    conn.execute(text(sql))
                    added += 1
                except Exception as e:
                    print(f"  Warning: Could not add {col_name}: {e}")
            else:
                print(f"Column already exists: {col_name}")
        
        if added > 0:
            print("\nCreating index on is_manual column...")
            try:
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_vulnerabilities_is_manual ON vulnerabilities (is_manual)"
                ))
            except Exception as e:
                print(f"  Warning: Could not create index: {e}")
        
        conn.commit()
        
        print(f"\nMigration complete! Added {added} new columns.")
        
        result = conn.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'vulnerabilities'
            ORDER BY ordinal_position
        """))
        print("\nCurrent vulnerabilities columns:")
        for row in result:
            print(f"  - {row[0]}")


if __name__ == "__main__":
    print("Running manual finding fields migration...")
    run_migration()
