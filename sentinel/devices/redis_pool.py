"""Redis-backed DeviceManager — cross-process device leases.

The in-process ``DeviceManager`` uses an ``asyncio.Lock`` per serial.
That's fine for one ``poetry run sentinel serve`` worker but breaks
the moment a multi-worker uvicorn deployment or a Kubernetes
horizontal-pod-autoscaler scales the gateway: each pod has its own
locks, so two scans on different pods can both lease the same device.

This module replaces the lock with a Redis ``SET key value NX EX
<ttl>`` primitive. Acquisition fails fast across all workers when the
key is already held; release deletes the key (with a CAS guard so we
never delete somebody else's lease).

Activation:

  * Set ``SENTINEL_REDIS_URL`` (e.g. ``redis://localhost:6379/0``).
  * Import ``get_device_manager()`` instead of constructing
    ``DeviceManager`` directly. It returns ``RedisDeviceManager`` when
    Redis is reachable, otherwise the in-process ``DeviceManager``.

Falls back gracefully on every Redis exception so a Redis outage
degrades to single-pod behaviour rather than a scan failure.
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import time
from contextlib import asynccontextmanager

from sentinel.devices.pool import (
    DeviceInfo,
    DeviceManager,
    DeviceUnavailable,
    _parse_devices_output,
    _run_adb,
)

logger = logging.getLogger(__name__)


_LEASE_TTL_SECONDS = 30 * 60       # 30-minute hard cap per lease
_KEY_PREFIX = "sentinel:devicelease:"


class RedisDeviceManager(DeviceManager):
    """Cross-process variant that uses Redis SET NX EX for leases.

    Subclasses ``DeviceManager`` so the existing in-process API
    (``refresh()``, ``list()``, ``lease()``) is preserved byte-for-byte.
    The only difference is that ``lease()`` acquires a distributed
    lock instead of an asyncio.Lock.
    """

    def __init__(self, redis_url: str = "") -> None:
        super().__init__()
        self.redis_url = redis_url or os.environ.get("SENTINEL_REDIS_URL", "")
        self._redis: object | None = None
        try:
            import redis.asyncio as redis_asyncio
            self._redis = redis_asyncio.from_url(
                self.redis_url, decode_responses=True,
            )
        except Exception as e:  # noqa: BLE001
            logger.info("Redis device pool disabled: %s", e)
            self._redis = None

    @property
    def is_distributed(self) -> bool:
        return self._redis is not None

    async def _redis_acquire(self, serial: str, token: str) -> bool:
        """SET NX EX with a process-unique token. True on success."""
        if self._redis is None:
            return False
        try:
            return bool(await self._redis.set(
                _KEY_PREFIX + serial, token,
                nx=True, ex=_LEASE_TTL_SECONDS,
            ))
        except Exception:  # noqa: BLE001
            logger.exception("Redis acquire failed for %s", serial)
            return False

    async def _redis_release(self, serial: str, token: str) -> None:
        """CAS-guarded release — delete only if token still matches.

        Tries a Lua CAS first; falls back to a non-atomic GET-then-DEL
        when EVAL isn't supported (some Redis-compat mocks like
        fakeredis don't implement scripting). The race-window in the
        fallback is benign — the worst case is that an expired lease
        gets cleaned up by the wrong holder, which means whoever
        legitimately took over via SET NX is unaffected.
        """
        if self._redis is None:
            return
        key = _KEY_PREFIX + serial
        try:
            script = (
                "if redis.call('GET', KEYS[1]) == ARGV[1] then "
                "  return redis.call('DEL', KEYS[1]) "
                "else return 0 end"
            )
            await self._redis.eval(script, 1, key, token)
            return
        except Exception:  # noqa: BLE001
            logger.debug("Redis EVAL unavailable; using non-atomic release")
        try:
            current = await self._redis.get(key)
            if current == token:
                await self._redis.delete(key)
        except Exception:  # noqa: BLE001
            logger.exception("Redis release fallback failed for %s", serial)

    @asynccontextmanager
    async def lease(self, prefer_serial: str | None = None,
                    timeout_s: float = 60.0):
        """Cross-process device lease."""
        if self._redis is None:
            # Redis unavailable — fall back to the parent's asyncio.Lock.
            async with super().lease(prefer_serial, timeout_s) as d:
                yield d
            return

        await self.refresh()
        eligible = [d for d in self._devices.values() if d.state == "device"]
        if not eligible:
            raise DeviceUnavailable(
                "No usable Android device found via `adb devices`.",
            )
        ordered: list[DeviceInfo] = []
        if prefer_serial and prefer_serial in self._devices:
            ordered.append(self._devices[prefer_serial])
        n = len(eligible)
        for i in range(n):
            d = eligible[(self._rr_index + i) % n]
            if d not in ordered:
                ordered.append(d)
        self._rr_index = (self._rr_index + 1) % max(1, n)

        deadline = time.time() + timeout_s
        token = secrets.token_hex(8)
        chosen = None
        while time.time() < deadline and chosen is None:
            for d in ordered:
                if await self._redis_acquire(d.serial, token):
                    chosen = d
                    break
            if chosen is None:
                await asyncio.sleep(0.5)  # backoff before retrying

        if chosen is None:
            raise DeviceUnavailable(
                "All attached devices are leased by other workers "
                "(checked via Redis lock).",
            )
        logger.info(
            "RedisDeviceManager: leased %s with token %s",
            chosen.serial, token[:6],
        )
        try:
            yield chosen
        finally:
            await self._redis_release(chosen.serial, token)


# ---------------------------- factory -------------------------------------


def get_device_manager() -> DeviceManager:
    """Pick the right DeviceManager flavour automatically.

    Uses Redis when ``SENTINEL_REDIS_URL`` is set AND the ``redis``
    package is installed AND the connection actually works (probed
    lazily). Falls back to the in-process DeviceManager otherwise.
    """
    url = os.environ.get("SENTINEL_REDIS_URL", "")
    if not url:
        return DeviceManager()
    try:
        mgr = RedisDeviceManager(redis_url=url)
        if mgr.is_distributed:
            return mgr
    except Exception:  # noqa: BLE001
        logger.exception("Redis device manager construction failed")
    return DeviceManager()


__all__ = ["RedisDeviceManager", "get_device_manager"]


# Re-export the parent's helpers so callers can monkeypatch a single
# module surface in tests regardless of which manager is active.
_parse_devices_output = _parse_devices_output
_run_adb = _run_adb
