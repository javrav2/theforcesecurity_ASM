"""
API Key Rotator Service
=======================

Rotates multiple API keys per (organization, service) to stay below
per-key rate limits and quotas, and to survive individual key failures
(401, 429, 5xx, network errors).

Design
------
The existing ``APIConfig`` model already allows multiple rows per
``(organization_id, service_name)``. This service is the runtime layer
on top of it:

    * ``lease(service, organization_id)`` returns the "best" key:
        - ``is_active`` and ``is_valid``
        - not circuit-broken (``last_error`` cleared or expired)
        - daily quota not exhausted (if ``rate_limit_per_day`` set)
        - least recently used of the candidates

    * The returned ``KeyLease`` is an async context manager that:
        - increments usage on success
        - records errors and opens a circuit breaker on hard failures

    * ``lease_env_fallback(env_var)`` returns a lease backed by a single
      env var so existing call-sites can migrate gradually.

Thread / async safety
---------------------
All DB writes go through short-lived sessions. An in-process lock
prevents the same process from handing out the same key twice in a tight
burst; across processes / workers we rely on the database's
``last_used`` timestamp to spread load.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import AsyncIterator, Iterable, Optional

from sqlalchemy import and_

from app.db.database import SessionLocal
from app.models.api_config import APIConfig

logger = logging.getLogger(__name__)


# Circuit-breaker open duration after a hard failure (401/403/auth).
AUTH_FAILURE_COOLDOWN = timedelta(hours=6)
# Soft backoff on 429 / rate-limited responses.
RATE_LIMIT_COOLDOWN = timedelta(minutes=10)
# Generic transient error backoff.
TRANSIENT_COOLDOWN = timedelta(minutes=2)


@dataclass
class KeyLease:
    """A single checked-out API key. Call ``record_success`` or ``record_failure``."""

    service: str
    organization_id: Optional[int]
    api_key: str
    api_user: Optional[str] = None
    api_secret: Optional[str] = None
    config_id: Optional[int] = None  # None => env-fallback lease
    source: str = "db"  # "db" | "env"
    rate_limit_per_second: Optional[int] = None
    rate_limit_per_day: Optional[int] = None
    # Bookkeeping used by the rotator
    _consumed: bool = field(default=False, repr=False)

    def record_success(self) -> None:
        """Mark the lease as successfully used and bump counters."""
        if self._consumed or self.source != "db" or self.config_id is None:
            self._consumed = True
            return
        db = SessionLocal()
        try:
            row = db.query(APIConfig).filter(APIConfig.id == self.config_id).first()
            if row:
                row.last_used = datetime.utcnow()
                row.usage_count = (row.usage_count or 0) + 1
                row.daily_usage = (row.daily_usage or 0) + 1
                row.last_error = None
                db.commit()
        except Exception as exc:  # pragma: no cover - best-effort bookkeeping
            logger.warning("record_success failed: %s", exc)
        finally:
            db.close()
            self._consumed = True

    def record_failure(self, error: str, kind: str = "transient") -> None:
        """Record a failure and open the circuit breaker if warranted.

        ``kind``:
            - "auth":  401/403 -> long cool-down, mark invalid
            - "rate":  429     -> short cool-down, stay valid
            - "transient": 5xx / timeouts -> brief cool-down
        """
        if self._consumed or self.source != "db" or self.config_id is None:
            self._consumed = True
            return
        db = SessionLocal()
        try:
            row = db.query(APIConfig).filter(APIConfig.id == self.config_id).first()
            if not row:
                return
            row.last_error = (error or "")[:2000]
            row.last_used = datetime.utcnow()
            if kind == "auth":
                row.is_valid = False
                logger.warning(
                    "API key %s#%d marked invalid after auth failure: %s",
                    self.service, self.config_id, error,
                )
            elif kind == "rate":
                logger.info(
                    "API key %s#%d rate-limited, cooling down: %s",
                    self.service, self.config_id, error,
                )
            else:
                logger.info(
                    "API key %s#%d transient failure: %s",
                    self.service, self.config_id, error,
                )
            db.commit()
        except Exception as exc:  # pragma: no cover
            logger.warning("record_failure failed: %s", exc)
        finally:
            db.close()
            self._consumed = True


class APIKeyRotator:
    """Picks one of N configured keys per (org, service) with health tracking."""

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def lease(
        self,
        service: str,
        organization_id: Optional[int] = None,
        env_fallback: Optional[str] = None,
    ) -> Optional[KeyLease]:
        """
        Return a healthy key lease for ``service`` or ``None`` if no key is
        available. Use ``env_fallback`` (env var name) to transparently fall
        back to a single-key env configuration.
        """
        async with self._lock:
            lease = await asyncio.to_thread(self._pick_from_db, service, organization_id)
            if lease:
                return lease

        if env_fallback:
            val = os.environ.get(env_fallback)
            if val:
                return KeyLease(
                    service=service,
                    organization_id=organization_id,
                    api_key=val,
                    source="env",
                )
        return None

    @asynccontextmanager
    async def lease_ctx(
        self,
        service: str,
        organization_id: Optional[int] = None,
        env_fallback: Optional[str] = None,
    ) -> AsyncIterator[Optional[KeyLease]]:
        """Async context manager variant: auto-records success if no error."""
        lease = await self.lease(service, organization_id, env_fallback=env_fallback)
        try:
            yield lease
            if lease and not lease._consumed:
                lease.record_success()
        except Exception as exc:
            if lease and not lease._consumed:
                # Best-effort classification; callers with finer detail should
                # call record_failure(..., kind=...) themselves.
                kind = self._classify_exception(exc)
                lease.record_failure(str(exc), kind=kind)
            raise

    def _pick_from_db(
        self, service: str, organization_id: Optional[int]
    ) -> Optional[KeyLease]:
        db = SessionLocal()
        try:
            q = db.query(APIConfig).filter(
                and_(
                    APIConfig.service_name == service,
                    APIConfig.is_active == True,  # noqa: E712
                    APIConfig.is_valid == True,   # noqa: E712
                )
            )
            if organization_id is not None:
                q = q.filter(APIConfig.organization_id == organization_id)

            candidates = q.all()
            if not candidates:
                return None

            now = datetime.utcnow()
            for row in candidates:
                self._maybe_reset_daily(row, now)

            healthy = [r for r in candidates if not self._is_cooling_down(r, now)]
            if not healthy:
                return None

            healthy = [r for r in healthy if not self._quota_exhausted(r)]
            if not healthy:
                return None

            def _score(r: APIConfig):
                last = r.last_used or datetime.min
                return (r.daily_usage or 0, last)

            row = sorted(healthy, key=_score)[0]
            db.commit()

            return KeyLease(
                service=service,
                organization_id=row.organization_id,
                api_key=row.get_api_key() or "",
                api_user=row.api_user,
                api_secret=row.get_api_secret(),
                config_id=row.id,
                source="db",
                rate_limit_per_second=row.rate_limit_per_second,
                rate_limit_per_day=row.rate_limit_per_day,
            )
        except Exception as exc:
            logger.warning("APIKeyRotator._pick_from_db failed: %s", exc)
            return None
        finally:
            db.close()

    @staticmethod
    def _maybe_reset_daily(row: APIConfig, now: datetime) -> None:
        if not row.daily_usage_reset:
            row.daily_usage_reset = now
            row.daily_usage = 0
            return
        if (now - row.daily_usage_reset) >= timedelta(hours=24):
            row.daily_usage = 0
            row.daily_usage_reset = now

    @staticmethod
    def _is_cooling_down(row: APIConfig, now: datetime) -> bool:
        if not row.last_error or not row.last_used:
            return False
        err_lower = row.last_error.lower()
        if any(s in err_lower for s in ("401", "403", "unauthorized", "forbidden", "invalid")):
            return (now - row.last_used) < AUTH_FAILURE_COOLDOWN
        if "429" in err_lower or "rate" in err_lower or "quota" in err_lower:
            return (now - row.last_used) < RATE_LIMIT_COOLDOWN
        return (now - row.last_used) < TRANSIENT_COOLDOWN

    @staticmethod
    def _quota_exhausted(row: APIConfig) -> bool:
        if not row.rate_limit_per_day:
            return False
        return (row.daily_usage or 0) >= row.rate_limit_per_day

    @staticmethod
    def _classify_exception(exc: BaseException) -> str:
        msg = str(exc).lower()
        if any(s in msg for s in ("401", "403", "unauthorized", "forbidden", "invalid key")):
            return "auth"
        if "429" in msg or "rate limit" in msg or "too many requests" in msg or "quota" in msg:
            return "rate"
        return "transient"


_GLOBAL_ROTATOR: Optional[APIKeyRotator] = None


def get_rotator() -> APIKeyRotator:
    """Return a process-wide rotator instance."""
    global _GLOBAL_ROTATOR
    if _GLOBAL_ROTATOR is None:
        _GLOBAL_ROTATOR = APIKeyRotator()
    return _GLOBAL_ROTATOR


async def lease_keys(
    service: str,
    organization_id: Optional[int] = None,
    env_fallback: Optional[str] = None,
    max_keys: int = 1,
) -> list[KeyLease]:
    """
    Convenience: return up to ``max_keys`` concurrent leases for a service.

    Useful for fan-out patterns where you want to round-robin across every
    valid key in parallel (e.g. spawn one crt.sh worker per configured key).
    """
    rotator = get_rotator()
    seen_ids: set[int] = set()
    leases: list[KeyLease] = []
    for _ in range(max_keys):
        lease = await rotator.lease(service, organization_id, env_fallback=env_fallback)
        if not lease:
            break
        key_id = lease.config_id or id(lease)
        if key_id in seen_ids:
            break
        seen_ids.add(key_id)
        leases.append(lease)
    return leases
