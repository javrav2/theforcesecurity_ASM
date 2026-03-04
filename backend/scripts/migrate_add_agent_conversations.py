"""
Migration: Add agent_conversations table for persistent chat history.

Run inside the backend container:
    python -m scripts.migrate_add_agent_conversations
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sqlalchemy import inspect, text
from app.db.database import engine
from app.models.agent_conversation import AgentConversation  # noqa: F401

TABLE = "agent_conversations"

DDL = """
CREATE TABLE IF NOT EXISTS agent_conversations (
    id              SERIAL PRIMARY KEY,
    session_id      VARCHAR(64) NOT NULL UNIQUE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id INTEGER NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    title           VARCHAR(255),
    mode            VARCHAR(20) DEFAULT 'assist',
    current_phase   VARCHAR(30) DEFAULT 'informational',
    is_active       BOOLEAN DEFAULT TRUE,
    messages        JSONB DEFAULT '[]'::jsonb,
    execution_summary TEXT,
    todo_list       JSONB DEFAULT '[]'::jsonb,
    created_at      TIMESTAMP DEFAULT now(),
    updated_at      TIMESTAMP DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_agent_conversations_session_id
    ON agent_conversations (session_id);
CREATE INDEX IF NOT EXISTS ix_agent_conversations_user_org
    ON agent_conversations (user_id, organization_id);
"""


def migrate():
    inspector = inspect(engine)
    if TABLE in inspector.get_table_names():
        print(f"Table '{TABLE}' already exists — skipping.")
        return

    print(f"Creating table '{TABLE}'...")
    with engine.begin() as conn:
        for stmt in DDL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                conn.execute(text(stmt))
    print("Done.")


if __name__ == "__main__":
    migrate()
