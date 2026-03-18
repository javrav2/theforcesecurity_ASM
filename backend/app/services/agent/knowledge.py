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
    Uses keyword search over title and content, falling back to most recent docs.
    Returns concatenated snippets.
    """
    if not query or not query.strip():
        return ""
    db = SessionLocal()
    try:
        base_filter = or_(
            AgentKnowledge.organization_id == organization_id,
            AgentKnowledge.organization_id.is_(None),
        )

        # Extract meaningful keywords (3+ chars, skip common words)
        _stop_words = {"the", "and", "for", "are", "but", "not", "you", "all",
                        "can", "had", "her", "was", "one", "our", "out", "has",
                        "with", "this", "that", "from", "they", "been", "have",
                        "what", "when", "will", "how", "than", "its", "also"}
        keywords = [
            w for w in query.lower().split()
            if len(w) >= 3 and w not in _stop_words
        ]

        docs = []
        if keywords:
            # Try keyword-matched docs first (title or content contains any keyword)
            keyword_filters = []
            for kw in keywords[:5]:  # Cap at 5 keywords to keep query reasonable
                keyword_filters.append(AgentKnowledge.title.ilike(f"%{kw}%"))
                keyword_filters.append(AgentKnowledge.content.ilike(f"%{kw}%"))
            q = db.query(AgentKnowledge).filter(
                base_filter,
                or_(*keyword_filters),
            )
            docs = q.order_by(AgentKnowledge.updated_at.desc()).limit(limit).all()

        # Fall back to most recent docs if keyword search returned nothing
        if not docs:
            q = db.query(AgentKnowledge).filter(base_filter)
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
