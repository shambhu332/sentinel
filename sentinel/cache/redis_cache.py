"""Redis-backed LLM response cache and rate limiter.

Falls back to a no-op in-memory cache when Redis is not configured so local
dev never requires a running Redis instance.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


def _cache_key(
    messages: list[dict[str, str]],
    model: str,
    temperature: float,
    namespace: str = "",
) -> str:
    payload = json.dumps(
        {"m": messages, "model": model, "t": temperature, "ns": namespace},
        sort_keys=True,
    )
    return f"llm:v1:{hashlib.sha256(payload.encode()).hexdigest()}"


class LLMCache:
    """LLM response cache backed by Redis (or no-op when Redis is absent)."""

    def __init__(self, redis_url: str = "") -> None:
        self._client: Any = None
        self._noop = True
        if redis_url:
            try:
                import redis.asyncio as aioredis  # type: ignore[import-untyped]
                self._client = aioredis.from_url(redis_url, decode_responses=True)
                self._noop = False
                logger.info("[llm-cache] Redis cache enabled at %s", redis_url)
            except ImportError:
                logger.warning("[llm-cache] redis package not installed — LLM cache disabled")

    async def get(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        *,
        namespace: str = "",
    ) -> dict[str, Any] | None:
        if self._noop or temperature != 0.0:
            # Only cache deterministic (temperature=0) calls.
            return None
        try:
            raw = await self._client.get(_cache_key(messages, model, temperature, namespace))
            if raw:
                logger.debug("[llm-cache] HIT model=%s", model)
                return json.loads(raw)
        except Exception as e:  # noqa: BLE001
            logger.debug("[llm-cache] get error: %s", e)
        return None

    async def set(
        self,
        messages: list[dict[str, str]],
        model: str,
        temperature: float,
        result: dict[str, Any],
        ttl: int = 86400,
        *,
        namespace: str = "",
    ) -> None:
        if self._noop or temperature != 0.0:
            return
        try:
            await self._client.setex(
                _cache_key(messages, model, temperature, namespace),
                ttl,
                json.dumps(result),
            )
            logger.debug("[llm-cache] SET model=%s ttl=%ds", model, ttl)
        except Exception as e:  # noqa: BLE001
            logger.debug("[llm-cache] set error: %s", e)

    async def rate_limit_check(
        self, key: str, max_requests: int, window_seconds: int
    ) -> bool:
        """Return True if request is allowed, False if rate-limited."""
        if self._noop:
            return True
        try:
            now = time.time()
            pipe = self._client.pipeline()
            pipe.zremrangebyscore(key, 0, now - window_seconds)
            pipe.zcard(key)
            pipe.zadd(key, {str(now): now})
            pipe.expire(key, window_seconds)
            results = await pipe.execute()
            current_count = results[1]
            return int(current_count) < max_requests
        except Exception as e:  # noqa: BLE001
            logger.debug("[llm-cache] rate_limit error: %s", e)
            return True  # Fail open on Redis errors

    async def close(self) -> None:
        if self._client:
            try:
                await self._client.aclose()
            except Exception:  # noqa: BLE001
                pass


_cache_singleton: LLMCache | None = None


def get_llm_cache() -> LLMCache:
    """Return the process-level LLM cache singleton."""
    global _cache_singleton
    if _cache_singleton is None:
        from sentinel.core.config import get_settings
        settings = get_settings()
        _cache_singleton = LLMCache(redis_url=settings.redis_url)
    return _cache_singleton
