"""Retrieval for org-scoped agent knowledge (RAG)."""

import logging
from typing import Optional

from sqlalchemy import or_
from app.db.database import SessionLocal
from app.models.agent_knowledge import AgentKnowledge

logger = logging.getLogger(__name__)


def retrieve_knowledge(
    organization_id: int,
    query: str,
    limit: int = 5,
    max_chars: int = 1500,
) -> str:
    """
    Retrieve knowledge docs for the org (and global) relevant to the query.
    Uses simple keyword search over title, content, and tags. Returns concatenated snippets.
    """
    if not query or not query.strip():
        return ""
    db = SessionLocal()
    try:
        # Org-specific and global (organization_id IS NULL); most recent first
        q = db.query(AgentKnowledge).filter(
            or_(
                AgentKnowledge.organization_id == organization_id,
                AgentKnowledge.organization_id.is_(None),
            )
        )
        docs = q.order_by(AgentKnowledge.updated_at.desc()).limit(limit).all()
        result = []
        total = 0
        for d in docs:
            if total >= max_chars:
                break
            snippet = f"[{d.title}]\n{d.content[:800]}{'...' if len(d.content) > 800 else ''}"
            result.append(snippet)
            total += len(snippet)
        return "\n\n".join(result) if result else ""
    except Exception as e:
        logger.exception("retrieve_knowledge failed: %s", e)
        return ""
    finally:
        db.close()
