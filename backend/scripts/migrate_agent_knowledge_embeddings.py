"""
Migration: add embedding + embedding_model columns to agent_knowledge.

Both columns are nullable — safe to run on a live instance with no downtime.
Idempotent: skips columns that already exist.

Usage:
    python scripts/migrate_agent_knowledge_embeddings.py
"""
import os
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sqlalchemy import create_engine, text

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.error("DATABASE_URL not set")
    sys.exit(1)

engine = create_engine(DATABASE_URL)

COLUMNS = [
    ("embedding",       "jsonb"),        # JSON list of floats; null = keyword-only search
    ("embedding_model", "varchar(128)"), # e.g. "text-embedding-3-small"
]


def run():
    with engine.connect() as conn:
        for col, col_type in COLUMNS:
            exists = conn.execute(text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_name = 'agent_knowledge' AND column_name = :c"
            ), {"c": col}).fetchone()

            if exists:
                logger.info(f"✓ agent_knowledge.{col} already exists — skipping")
            else:
                conn.execute(text(
                    f"ALTER TABLE agent_knowledge ADD COLUMN {col} {col_type}"
                ))
                conn.commit()
                logger.info(f"✓ Added agent_knowledge.{col} ({col_type})")


if __name__ == "__main__":
    logger.info("Running agent_knowledge embedding migration...")
    run()
    logger.info("Done.")
