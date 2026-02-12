"""
Migration script to add agent_notes table for session-scoped agent findings.

Run from project root:
    python backend/scripts/migrate_add_agent_notes_table.py
Or inside the backend container:
    docker exec asm_backend python scripts/migrate_add_agent_notes_table.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import SessionLocal


def run_migration():
    """Add the agent_notes table."""
    db = SessionLocal()
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'agent_notes'
            );
        """))
        exists = result.scalar()
        if exists:
            print("agent_notes table already exists")
        else:
            db.execute(text("""
                CREATE TABLE agent_notes (
                    id SERIAL PRIMARY KEY,
                    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                    session_id VARCHAR(255),
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    category VARCHAR(50) NOT NULL,
                    content TEXT NOT NULL,
                    target VARCHAR(512),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            db.execute(text("CREATE INDEX idx_agent_notes_organization_id ON agent_notes(organization_id)"))
            db.execute(text("CREATE INDEX idx_agent_notes_session_id ON agent_notes(session_id)"))
            db.execute(text("CREATE INDEX idx_agent_notes_created_at ON agent_notes(created_at)"))
            db.commit()
            print("Created agent_notes table successfully")
        print("Migration complete.")
    except Exception as e:
        db.rollback()
        print(f"Migration failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    run_migration()
