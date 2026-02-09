#!/usr/bin/env python3
"""
Migration script to add project_settings table (per-org scan/agent config).

Run:
    docker compose exec backend python scripts/migrate_add_project_settings.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import engine, SessionLocal
from app.models.project_settings import ProjectSettings, ALL_MODULES, get_default_config


def table_exists(conn, table: str) -> bool:
    result = conn.execute(text("""
        SELECT 1 FROM information_schema.tables
        WHERE table_name = :name
    """), {"name": table})
    return result.fetchone() is not None


def migrate():
    print("=" * 60)
    print("Migration: project_settings table")
    print("=" * 60)

    with engine.connect() as conn:
        if table_exists(conn, "project_settings"):
            print("  - project_settings table already exists")
            conn.commit()
            return
        print("Creating table project_settings...")
        conn.execute(text("""
            CREATE TABLE project_settings (
                id SERIAL PRIMARY KEY,
                organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                module VARCHAR(64) NOT NULL,
                config JSONB NOT NULL DEFAULT '{}',
                updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                UNIQUE(organization_id, module)
            )
        """))
        conn.execute(text("CREATE INDEX ix_project_settings_organization_id ON project_settings(organization_id)"))
        conn.execute(text("CREATE INDEX ix_project_settings_module ON project_settings(module)"))
        conn.commit()
        print("  ✓ project_settings table created")

    # Seed default rows for existing organizations
    db = SessionLocal()
    try:
        from app.models.organization import Organization
        orgs = db.query(Organization).all()
        for org in orgs:
            ProjectSettings.ensure_defaults(db, org.id)
            print(f"  ✓ Default settings for org {org.id} ({org.name})")
    finally:
        db.close()


if __name__ == "__main__":
    migrate()
    print("Done.")
