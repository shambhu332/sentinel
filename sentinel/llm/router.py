"""LLM router — multi-provider with local-first priority and circuit breakers.

Provider priority (local → cloud):
  1. Local vLLM / TensorRT-LLM  (SENTINEL_LOCAL_LLM_URL — preferred, no egress)
  2. Groq                        (GROQ_API_KEY — Llama 3.3 70B, ~14k RPD)
  3. Cerebras                    (CEREBRAS_API_KEY — Llama 3.3 70B, 1M tok/day)
  4. Ollama                      (OLLAMA_HOST — local always-on fallback)

Configuration (.env):
  SENTINEL_LOCAL_LLM_URL   — OpenAI-compatible local endpoint (e.g. http://localhost:8080)
  SENTINEL_LOCAL_LLM_MODEL — model name served by local endpoint (default: local-model)
  GROQ_API_KEY             — enables Groq path
  CEREBRAS_API_KEY         — enables Cerebras path
  OLLAMA_HOST              — local Ollama endpoint (default: http://127.0.0.1:11434)
  REDIS_URL                — enables deterministic LLM response caching

Use --private CLI flag to force local-only (skips Groq + Cerebras).

Deterministic security calls use temperature=0.0 and are cached in Redis (if
REDIS_URL is configured). Remediation / report calls use temperature=0.3 and
are never cached.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
from abc import ABC, abstractmethod
from typing import Any

import httpx

from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)


# ---------- Constants ----------

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
CEREBRAS_URL = "https://api.cerebras.ai/v1/chat/completions"

DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
DEFAULT_CEREBRAS_MODEL = "llama-3.3-70b"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"

GROQ_MODEL = os.environ.get("GROQ_MODEL", DEFAULT_GROQ_MODEL)
CEREBRAS_MODEL = os.environ.get("CEREBRAS_MODEL", DEFAULT_CEREBRAS_MODEL)
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL_NAME", DEFAULT_OLLAMA_MODEL)

MAX_RETRIES = 2
RETRY_BACKOFF = [1.0, 3.0]
TIMEOUT_CLOUD = 60.0
TIMEOUT_LOCAL = 300.0

CIRCUIT_BREAK_THRESHOLD = 3
CIRCUIT_RESET_SECONDS = 120


_THINK_TAG_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


# ---------- Errors ----------

class RouterError(Exception):
    """All providers exhausted."""


# ---------- Provider abstraction ----------

class LLMProvider(ABC):
    """Abstract LLM provider."""

    name: str = "abstract"
    model: str = ""

    def __init__(self) -> None:
        self._consecutive_failures = 0
        self._circuit_open_until: float = 0.0

    @abstractmethod
    def is_enabled(self) -> bool:
        """Whether this provider can be used (e.g. has API key / reachable URL)."""

    @abstractmethod
    async def query(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> dict[str, Any] | None:
        """Make the API call. Return result dict or None on failure."""

    def is_circuit_open(self) -> bool:
        return time.monotonic() < self._circuit_open_until

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= CIRCUIT_BREAK_THRESHOLD:
            self._circuit_open_until = time.monotonic() + CIRCUIT_RESET_SECONDS
            logger.warning(
                "[%s] circuit breaker tripped — skipping for %ds",
                self.name, CIRCUIT_RESET_SECONDS,
            )

    def disable_for_session(self, reason: str) -> None:
        self._circuit_open_until = time.monotonic() + 86_400
        logger.error("[%s] permanently disabled this session: %s", self.name, reason)


# ---------- Providers ----------

class LocalVLLMProvider(LLMProvider):
    """Local vLLM / TensorRT-LLM via OpenAI-compatible /v1/chat/completions.

    Preferred over all cloud providers. Set SENTINEL_LOCAL_LLM_URL to enable.
    """

    name = "local-vllm"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self.base_url = settings.local_llm_url.rstrip("/")
        self.model = settings.local_llm_model

    def is_enabled(self) -> bool:
        return bool(self.base_url)

    async def query(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> dict[str, Any] | None:
        if not self.base_url:
            return None

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = await client.post(
                    f"{self.base_url}/v1/chat/completions",
                    json=payload,
                    timeout=TIMEOUT_LOCAL,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "content": data["choices"][0]["message"]["content"],
                        "model": self.model,
                        "provider": self.name,
                    }
                if resp.status_code >= 500 and attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
                    continue
                logger.warning("[local-vllm] %d: %s", resp.status_code, resp.text[:200])
                return None
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                logger.warning("[local-vllm] connection error: %s", e)
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
        return None


class GroqProvider(LLMProvider):
    """Groq Cloud — Llama 3.3 70B at ~300 tok/s."""

    name = "groq"
    model = GROQ_MODEL

    def is_enabled(self) -> bool:
        return bool(get_settings().groq_api_key.get_secret_value().strip())

    async def query(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> dict[str, Any] | None:
        settings = get_settings()
        api_key = settings.groq_api_key.get_secret_value().strip()
        if not api_key:
            return None

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = await client.post(
                    GROQ_URL, json=payload, headers=headers, timeout=TIMEOUT_CLOUD,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "content": data["choices"][0]["message"]["content"],
                        "model": self.model,
                        "provider": self.name,
                    }
                if resp.status_code == 429:
                    logger.warning("Groq 429 (rate limit), attempt %d", attempt + 1)
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
                        continue
                    return None
                if resp.status_code == 404:
                    logger.error(
                        "Groq 404: model '%s' not available. Check GROQ_MODEL.", self.model,
                    )
                    return None
                if resp.status_code >= 500:
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
                        continue
                    return None
                logger.warning("Groq %d: %s", resp.status_code, resp.text[:200])
                return None
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                logger.warning("Groq network error: %s", e)
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
        return None


class CerebrasProvider(LLMProvider):
    """Cerebras Cloud — Llama 3.3 70B, 1M tokens/day."""

    name = "cerebras"
    model = CEREBRAS_MODEL

    def is_enabled(self) -> bool:
        return get_settings().has_cerebras_key()

    async def query(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> dict[str, Any] | None:
        settings = get_settings()
        if not settings.has_cerebras_key():
            return None

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Authorization": f"Bearer {settings.cerebras_api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }

        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = await client.post(
                    CEREBRAS_URL, json=payload, headers=headers, timeout=TIMEOUT_CLOUD,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "content": data["choices"][0]["message"]["content"],
                        "model": self.model,
                        "provider": self.name,
                    }
                if resp.status_code == 429:
                    logger.warning("Cerebras 429 (rate limit), attempt %d", attempt + 1)
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
                        continue
                    return None
                if resp.status_code == 404:
                    self.disable_for_session(
                        f"model '{self.model}' not available "
                        f"(set CEREBRAS_MODEL in .env to an accessible model)",
                    )
                    return None
                if resp.status_code >= 500:
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
                        continue
                    return None
                logger.warning("Cerebras %d: %s", resp.status_code, resp.text[:200])
                return None
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                logger.warning("Cerebras network error: %s", e)
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
        return None


class OllamaProvider(LLMProvider):
    """Local Ollama — always-on fallback."""

    name = "ollama"
    model = OLLAMA_MODEL

    def is_enabled(self) -> bool:
        return True

    async def query(
        self,
        client: httpx.AsyncClient,
        messages: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
        json_mode: bool,
    ) -> dict[str, Any] | None:
        settings = get_settings()
        host = settings.ollama_host.replace("localhost", "127.0.0.1")

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "stream": False,
            "keep_alive": "30m",
        }
        if json_mode:
            payload["format"] = "json"

        try:
            resp = await client.post(
                f"{host.rstrip('/')}/api/chat", json=payload, timeout=TIMEOUT_LOCAL,
            )
            if resp.status_code != 200:
                logger.warning("Ollama %d: %s", resp.status_code, resp.text[:200])
                return None
            data = resp.json()
            return {
                "content": data.get("message", {}).get("content", ""),
                "model": self.model,
                "provider": self.name,
            }
        except Exception as e:
            logger.warning("Ollama error (%s @ %s, model=%s): %s",
                           type(e).__name__, host, self.model, e)
            return None


# ---------- Router ----------

class FreeProviderRouter:
    """Multi-provider LLM router with local-first priority and Redis caching.

    Provider order:
      1. Local vLLM/TensorRT-LLM (SENTINEL_LOCAL_LLM_URL)
      2. Groq (GROQ_API_KEY)
      3. Cerebras (CEREBRAS_API_KEY)
      4. Ollama (local always-on fallback)

    Deterministic calls (temperature=0.0) are cached in Redis when REDIS_URL
    is set. Subsequent identical prompts skip the LLM entirely.

    Pass force_local=True to skip cloud providers (--private mode).
    """

    # Providers that have no external rate limit — sleep between calls is
    # unnecessary when these answer, so triager can skip the inter-call delay.
    _LOCAL_PROVIDER_NAMES: frozenset[str] = frozenset({"local-vllm", "ollama"})

    def __init__(self, force_local: bool = False) -> None:
        self._force_local = force_local
        self._client: httpx.AsyncClient | None = None
        self._providers: list[LLMProvider] = [
            LocalVLLMProvider(),
            GroqProvider(),
            CerebrasProvider(),
            OllamaProvider(),
        ]
        self._last_provider_name: str | None = None
        from sentinel.cache.redis_cache import get_llm_cache
        self._cache = get_llm_cache()

    @property
    def last_provider_is_local(self) -> bool:
        """True when the last successful query was answered by a local provider.

        Local providers (local-vllm, ollama) have no external rate limit, so
        callers like LLMTriager can skip the inter-call sleep when this is True.
        """
        return self._last_provider_name in self._LOCAL_PROVIDER_NAMES

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient()
        return self._client

    def _eligible_providers(self) -> list[LLMProvider]:
        result: list[LLMProvider] = []
        for p in self._providers:
            if self._force_local and p.name not in ("local-vllm", "ollama"):
                continue
            if not p.is_enabled():
                continue
            if p.is_circuit_open():
                logger.debug("[%s] circuit open, skipping", p.name)
                continue
            result.append(p)
        return result

    async def query(
        self,
        messages: list[dict[str, str]],
        tier: str = "T2",
        temperature: float = 0.0,
        max_tokens: int = 4096,
        json_mode: bool = False,
    ) -> dict[str, Any]:
        """Query with automatic failover and Redis cache. Returns content/model/provider."""
        eligible = self._eligible_providers()

        if not eligible:
            raise RouterError(
                "No LLM providers available. "
                "Set SENTINEL_LOCAL_LLM_URL, GROQ_API_KEY, CEREBRAS_API_KEY, or run Ollama."
            )

        # Check cache for deterministic calls (temperature=0.0).
        first_model = eligible[0].model if eligible else ""
        cached = await self._cache.get(messages, first_model, temperature)
        if cached is not None:
            cached["cached"] = True
            return cached

        client = await self._get_client()
        last_error: Exception | None = None

        for provider in eligible:
            try:
                result = await provider.query(
                    client, messages, temperature, max_tokens, json_mode,
                )
                if result is not None:
                    provider.record_success()
                    self._last_provider_name = provider.name
                    logger.debug("[router] %s answered (model=%s)",
                                 provider.name, result.get("model"))
                    await self._cache.set(messages, result.get("model", ""), temperature, result)
                    return result
                provider.record_failure()
            except Exception as e:  # noqa: BLE001
                provider.record_failure()
                last_error = e
                logger.warning("[router] %s raised %s: %s",
                               provider.name, type(e).__name__, e)

        tried = [p.name for p in eligible]
        if last_error is not None:
            raise RouterError(
                f"All LLM providers failed (tried: {tried}). "
                f"Last error: {type(last_error).__name__}: {last_error}"
            )
        raise RouterError(f"All LLM providers failed (tried: {tried})")

    async def query_json(
        self,
        messages: list[dict[str, str]],
        tier: str = "T2",
    ) -> dict[str, Any]:
        """Query with JSON mode, strip markdown fences and reasoning tags."""
        result = await self.query(messages=messages, tier=tier, json_mode=True)
        content = result["content"].strip()

        content = _THINK_TAG_RE.sub("", content).strip()

        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        if content and not content.startswith("{"):
            match = re.search(r"\{.*\}", content, re.DOTALL)
            if match:
                content = match.group(0)

        try:
            result["content"] = json.loads(content)
        except json.JSONDecodeError as e:
            raise RouterError(f"Invalid JSON from LLM: {e}") from e
        return result

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        await self._cache.close()

    async def __aenter__(self) -> FreeProviderRouter:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
