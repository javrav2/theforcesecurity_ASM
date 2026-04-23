"""
Embedding helpers for the agent knowledge base.

The goal here is to keep things simple and resilient. If an OpenAI key is
configured we use ``text-embedding-3-small``; otherwise we fall back to a
cheap hashed bag-of-words vector so semantic retrieval still works (weakly)
in offline dev environments.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import re
from typing import Optional

logger = logging.getLogger(__name__)


_HASH_DIM = 256  # fallback vector size
_DEFAULT_OPENAI_MODEL = "text-embedding-3-small"


def _have_openai() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY"))


def embedding_model_id() -> str:
    if _have_openai():
        return _DEFAULT_OPENAI_MODEL
    return f"hash-bow-{_HASH_DIM}"


def _hash_embedding(text: str, dim: int = _HASH_DIM) -> list[float]:
    vec = [0.0] * dim
    tokens = _tokenize(text)
    if not tokens:
        return vec
    for tok in tokens:
        h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if (h >> 8) & 1 else -1.0
        vec[idx] += sign
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _tokenize(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-zA-Z0-9_\-]{2,}", (text or "").lower())]


def embed(text: str) -> tuple[list[float], str]:
    """Return (vector, model_id)."""
    text = (text or "").strip()
    if not text:
        return [], embedding_model_id()

    if _have_openai():
        try:
            from openai import OpenAI
            client = OpenAI()
            resp = client.embeddings.create(
                model=_DEFAULT_OPENAI_MODEL, input=text[:8000]
            )
            vec = resp.data[0].embedding
            return list(vec), _DEFAULT_OPENAI_MODEL
        except Exception as exc:
            logger.warning("OpenAI embedding failed, falling back to hash: %s", exc)

    return _hash_embedding(text), embedding_model_id()


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def chunk_text(text: str, max_chars: int = 1200, overlap: int = 150) -> list[str]:
    """Paragraph-aware chunking with overlap. Keeps MVP-level quality."""
    if not text:
        return []
    text = text.strip()
    if len(text) <= max_chars:
        return [text]

    paragraphs = re.split(r"\n{2,}", text)
    chunks: list[str] = []
    buf = ""
    for p in paragraphs:
        if not p.strip():
            continue
        if len(buf) + len(p) + 2 <= max_chars:
            buf = (buf + "\n\n" + p) if buf else p
            continue
        if buf:
            chunks.append(buf)
            tail = buf[-overlap:] if overlap and len(buf) > overlap else ""
            buf = tail + ("\n\n" + p if tail else p)
        else:
            # Single paragraph is bigger than max_chars - hard wrap it.
            for i in range(0, len(p), max_chars):
                chunks.append(p[i : i + max_chars])
            buf = ""
    if buf:
        chunks.append(buf)
    return chunks


def reindex_doc(doc) -> Optional[list[float]]:
    """Compute and store an embedding on an AgentKnowledge row."""
    try:
        vec, model = embed(f"{doc.title}\n\n{doc.content}")
        doc.embedding = vec
        doc.embedding_model = model
        return vec
    except Exception as exc:
        logger.warning("reindex_doc failed for id=%s: %s", getattr(doc, "id", None), exc)
        return None
