"""JTI revocation list.

Phase 1.3 requires every JWT to carry a `jti` claim so an admin can
invalidate a stolen token before its natural expiry.

Two implementations:

* `InMemoryRevocationStore` — process-local `set[str]`. Default. Fine
  for single-process dev / tests.
* `RedisRevocationStore` — Redis `SETEX` per revoked jti with TTL
  matching the token's remaining lifetime. This is the multi-worker
  production path; enabled when `SENTINEL_REDIS_URL` is set.

The store is looked up by `get_revocation_store()` which caches the
first instantiated store for the process. Tests reset it explicitly.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class RevocationStore(Protocol):
    async def revoke(self, jti: str, ttl_seconds: int) -> None: ...
    async def is_revoked(self, jti: str) -> bool: ...


class InMemoryRevocationStore:
    """Simple set-backed store. Not multi-process safe."""

    def __init__(self) -> None:
        self._revoked: set[str] = set()
        self._lock = threading.Lock()

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        with self._lock:
            self._revoked.add(jti)

    async def is_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked


class RedisRevocationStore:
    """Redis-backed store. `revoke` uses SETEX with the token's TTL."""

    KEY_PREFIX = "sentinel:jwt:revoked:"

    def __init__(self, redis_url: str) -> None:
        self._url = redis_url
        self._client: Any = None

    async def _get(self) -> Any:
        if self._client is None:
            import redis.asyncio as redis_async  # local import — optional dep
            self._client = redis_async.from_url(
                self._url, encoding="utf-8", decode_responses=True,
            )
        return self._client

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        client = await self._get()
        await client.setex(self.KEY_PREFIX + jti, max(1, ttl_seconds), "1")

    async def is_revoked(self, jti: str) -> bool:
        client = await self._get()
        return bool(await client.exists(self.KEY_PREFIX + jti))


_STORE: RevocationStore | None = None
_STORE_LOCK = threading.Lock()


def get_revocation_store() -> RevocationStore:
    global _STORE
    with _STORE_LOCK:
        if _STORE is not None:
            return _STORE
        redis_url = os.getenv("SENTINEL_REDIS_URL") or os.getenv("REDIS_URL")
        if redis_url:
            logger.info("Revocation store: Redis at %s", redis_url)
            _STORE = RedisRevocationStore(redis_url)
        else:
            logger.info("Revocation store: in-memory (single-process)")
            _STORE = InMemoryRevocationStore()
        return _STORE


def reset_revocation_store() -> None:
    """Test helper — clear the singleton so a fresh store is created."""
    global _STORE
    with _STORE_LOCK:
        _STORE = None
