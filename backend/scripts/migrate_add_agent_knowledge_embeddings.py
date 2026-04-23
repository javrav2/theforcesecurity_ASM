"""
Migration: add ``embedding`` and ``embedding_model`` columns to
``agent_knowledge`` to support hybrid (keyword + embedding) RAG retrieval.

Idempotent. Safe to rerun.

    docker exec asm_backend python scripts/migrate_add_agent_knowledge_embeddings.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text

from app.db.database import SessionLocal


COLUMNS = [
    ("embedding", "JSONB"),
    ("embedding_model", "VARCHAR(128)"),
]


def run_migration():
    db = SessionLocal()
    try:
        for name, coltype in COLUMNS:
            exists = db.execute(text(
                """
                SELECT EXISTS (
                    SELECT FROM information_schema.columns
                    WHERE table_name = 'agent_knowledge'
                      AND column_name = :name
                )
                """
            ), {"name": name}).scalar()
            if exists:
                print(f"column agent_knowledge.{name} already exists")
                continue
            db.execute(text(
                f"ALTER TABLE agent_knowledge ADD COLUMN {name} {coltype} NULL"
            ))
            db.commit()
            print(f"added column agent_knowledge.{name}")
        print("Migration complete.")
    except Exception as exc:
        db.rollback()
        print(f"Migration failed: {exc}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    run_migration()
