"""
Migration script to add agent_knowledge table for org-scoped RAG.

Run from project root:
    python backend/scripts/migrate_add_agent_knowledge_table.py
Or inside the backend container:
    docker exec asm_backend python scripts/migrate_add_agent_knowledge_table.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text
from app.db.database import SessionLocal


def run_migration():
    """Add the agent_knowledge table."""
    db = SessionLocal()
    try:
        result = db.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'agent_knowledge'
            );
        """))
        exists = result.scalar()
        if exists:
            print("agent_knowledge table already exists")
        else:
            db.execute(text("""
                CREATE TABLE agent_knowledge (
                    id SERIAL PRIMARY KEY,
                    organization_id INTEGER REFERENCES organizations(id) ON DELETE CASCADE,
                    title VARCHAR(512) NOT NULL,
                    content TEXT NOT NULL,
                    tags JSONB DEFAULT '[]',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            db.execute(text("CREATE INDEX idx_agent_knowledge_organization_id ON agent_knowledge(organization_id)"))
            db.commit()
            print("Created agent_knowledge table successfully")
        print("Migration complete.")
    except Exception as e:
        db.rollback()
        print(f"Migration failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    run_migration()
