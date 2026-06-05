"""
One-time fix: drop the incorrectly-structured oracle schema and let
apply_oracle_migrations() recreate it with the correct column names.

Safe to run only when the oracle schema has no real data worth keeping
(new installations where the Go service hasn't successfully ingested CVEs yet).

Run with:
    docker exec asm_backend python scripts/fix_oracle_schema.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import engine


def main():
    print("Checking oracle schema...")
    with engine.connect() as conn:
        # Check if the wrong column name exists
        result = conn.execute(text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'oracle' AND table_name = 'cves'
            AND column_name IN ('published', 'published_at')
        """))
        cols = [r[0] for r in result]

        if 'published_at' in cols:
            print("oracle.cves already has 'published_at' — schema is correct, nothing to do.")
            return

        if 'published' in cols:
            print("Found wrong column 'published' — dropping oracle schema for rebuild...")
            conn.execute(text("DROP SCHEMA IF EXISTS oracle CASCADE"))
            conn.commit()
            print("Dropped. Recreating via apply_oracle_migrations()...")
        else:
            print("oracle.cves doesn't exist yet — will be created fresh.")
            conn.commit()

    # Re-run the migration to create correct schema
    import importlib, app.main as m
    m.apply_oracle_migrations()
    print("Done. Oracle schema is now correct.")


if __name__ == "__main__":
    main()
