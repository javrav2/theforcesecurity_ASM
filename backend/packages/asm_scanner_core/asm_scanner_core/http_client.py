"""HTTP client for submitting findings to the ASM platform (standalone / OpenClaw workers)."""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from asm_scanner_core.findings import Finding

logger = logging.getLogger(__name__)

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


class ASMIngestClient:
    """
    Batched POST to /api/v1/ingest/findings.

    Environment (if args omitted):
      ASM_API_URL, ASM_API_KEY, ASM_AGENT_ID
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        batch_size: int = 100,
        ingest_path: str = "/api/v1/ingest/findings",
    ):
        self.api_url = (api_url or os.environ.get("ASM_API_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("ASM_API_KEY", "")
        self.agent_id = agent_id or os.environ.get("ASM_AGENT_ID", "asm-agent")
        self.batch_size = max(1, batch_size)
        self.ingest_path = ingest_path
        self._buffer: List[Finding] = []

    def submit(self, finding: Finding) -> None:
        self._buffer.append(finding)
        if len(self._buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> Optional[Dict[str, Any]]:
        if not self._buffer:
            return None
        batch = self._buffer[:]
        self._buffer.clear()
        payload = {
            "agent_id": self.agent_id,
            "agent_type": "external_scanner",
            "scan_context": "asm-scanner-core",
            "findings": [f.to_dict() for f in batch],
        }
        if not self.api_url:
            logger.info("[dry-run] would submit %s findings", len(batch))
            return {"dry_run": True, "count": len(batch)}
        return self._post(self.ingest_path, payload)

    def _post(self, path: str, payload: dict, retries: int = 3) -> Optional[Dict[str, Any]]:
        if not _HAS_HTTPX:
            logger.error("httpx not installed; cannot submit findings")
            return None
        url = f"{self.api_url}{path}"
        headers = {"Content-Type": "application/json", "X-API-Key": self.api_key}
        body = json.dumps(payload, default=str).encode("utf-8")
        for attempt in range(retries):
            try:
                with httpx.Client(timeout=60.0) as client:
                    r = client.post(url, content=body, headers=headers)
                    r.raise_for_status()
                    return r.json()
            except Exception as e:
                wait = 2**attempt
                logger.warning("ingest POST failed (%s/%s): %s, retry in %ss", attempt + 1, retries, e, wait)
                time.sleep(wait)
        return None
