"""
Migration: add Oracle analysis columns to vulnerabilities table.

Promotes the most-queried Oracle fields out of metadata_["oracle"] JSON
into real columns so they can be indexed, filtered, and sorted efficiently.
The full analysis payload remains in metadata_["oracle"] for rich display.

Run with:
    python scripts/migrate_add_oracle_columns.py

Or via Docker:
    sudo docker exec asm_backend python scripts/migrate_add_oracle_columns.py

After running, also backfill existing rows from the JSON blob:
    python scripts/migrate_add_oracle_columns.py --backfill
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import engine


NEW_COLUMNS = [
    # Core OPES signal — most useful for dashboards / priority queues
    ("oracle_opes_score",      "FLOAT"),
    ("oracle_opes_category",   "VARCHAR(50)"),
    ("oracle_opes_label",      "VARCHAR(100)"),
    ("oracle_opes_confidence", "VARCHAR(20)"),
    # Attack surface classification
    ("oracle_attack_path",     "VARCHAR(100)"),
    ("oracle_lateral_mvmt",    "VARCHAR(50)"),
    # Mode and freshness metadata
    ("oracle_mode",            "VARCHAR(30)"),
    ("oracle_enriched_at",     "TIMESTAMP WITH TIME ZONE"),
    ("oracle_analysis_status", "VARCHAR(30)"),
    # Link back to oracle.findings for joins
    ("oracle_finding_id",      "VARCHAR(100)"),
]

INDEXES = [
    ("ix_vuln_oracle_opes_score",    "oracle_opes_score"),
    ("ix_vuln_oracle_opes_category", "oracle_opes_category"),
    ("ix_vuln_oracle_mode",          "oracle_mode"),
    ("ix_vuln_oracle_enriched_at",   "oracle_enriched_at"),
]


def run_migration(backfill: bool = False) -> None:
    with engine.connect() as conn:
        result = conn.execute(text(
            "SELECT column_name FROM information_schema.columns "
            "WHERE table_name = 'vulnerabilities'"
        ))
        existing = {row[0] for row in result}

        added = 0
        for col_name, col_def in NEW_COLUMNS:
            if col_name not in existing:
                try:
                    conn.execute(text(
                        f"ALTER TABLE vulnerabilities ADD COLUMN {col_name} {col_def}"
                    ))
                    print(f"  + {col_name} {col_def}")
                    added += 1
                except Exception as e:
                    print(f"  ! {col_name}: {e}")
            else:
                print(f"  = {col_name} (already exists)")

        for idx_name, col_name in INDEXES:
            try:
                conn.execute(text(
                    f"CREATE INDEX IF NOT EXISTS {idx_name} ON vulnerabilities ({col_name})"
                ))
                print(f"  index {idx_name}")
            except Exception as e:
                print(f"  ! index {idx_name}: {e}")

        conn.commit()
        print(f"\nSchema migration complete — {added} columns added.")

        if backfill:
            print("\nBackfilling from metadata_[\"oracle\"] JSON blob...")
            conn.execute(text("""
                UPDATE vulnerabilities
                SET
                    oracle_opes_score      = (metadata->>'oracle')::jsonb->>'opes_score',
                    oracle_opes_category   = (metadata->>'oracle')::jsonb->>'opes_category',
                    oracle_opes_label      = (metadata->>'oracle')::jsonb->>'opes_label',
                    oracle_opes_confidence = (metadata->>'oracle')::jsonb->>'opes_confidence',
                    oracle_attack_path     = (metadata->>'oracle')::jsonb->>'attack_path_class',
                    oracle_lateral_mvmt    = (metadata->>'oracle')::jsonb->>'lateral_movement_potential',
                    oracle_mode            = (metadata->>'oracle')::jsonb->>'mode',
                    oracle_enriched_at     = ((metadata->>'oracle')::jsonb->>'enriched_at')::timestamptz,
                    oracle_analysis_status = (metadata->>'oracle')::jsonb->>'analysis_status',
                    oracle_finding_id      = (metadata->>'oracle')::jsonb->>'finding_id'
                WHERE metadata ? 'oracle'
            """))
            conn.commit()
            result = conn.execute(text(
                "SELECT COUNT(*) FROM vulnerabilities WHERE oracle_mode IS NOT NULL"
            ))
            n = result.scalar()
            print(f"Backfill complete — {n} rows updated.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--backfill", action="store_true",
                        help="Also populate columns from existing metadata JSON")
    args = parser.parse_args()

    print("Oracle columns migration...")
    run_migration(backfill=args.backfill)
