"""
Migration: add commoncrawl_enum to the scantype PostgreSQL enum and
ensure the commoncrawl project-settings module exists for all orgs.

Safe to run multiple times (idempotent).

Usage:
    python scripts/migrate_commoncrawl_enum.py
"""
import os
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.error("DATABASE_URL not set")
    sys.exit(1)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


def add_enum_value():
    """Add commoncrawl_enum to the scantype PostgreSQL enum type."""
    with engine.connect() as conn:
        # Check if the value already exists
        result = conn.execute(text("""
            SELECT 1
            FROM pg_enum e
            JOIN pg_type t ON t.oid = e.enumtypid
            WHERE t.typname = 'scantype'
              AND e.enumlabel = 'commoncrawl_enum'
        """))
        if result.fetchone():
            logger.info("✓ scantype enum already has 'commoncrawl_enum' — skipping")
            return

        # PostgreSQL requires COMMIT before ALTER TYPE
        conn.execute(text("COMMIT"))
        conn.execute(text("ALTER TYPE scantype ADD VALUE 'commoncrawl_enum'"))
        logger.info("✓ Added 'commoncrawl_enum' to scantype enum")


def ensure_commoncrawl_settings():
    """Create the commoncrawl project-settings row for every existing org."""
    from app.models.organization import Organization
    from app.models.project_settings import ProjectSettings

    db = SessionLocal()
    try:
        orgs = db.query(Organization).filter(Organization.is_active == True).all()
        created = 0
        for org in orgs:
            ProjectSettings.ensure_defaults(db, org.id)
            created += 1
        logger.info(f"✓ Ensured commoncrawl settings for {created} organization(s)")
    finally:
        db.close()


if __name__ == "__main__":
    logger.info("Running CommonCrawl migration...")
    add_enum_value()
    ensure_commoncrawl_settings()
    logger.info("Migration complete.")
