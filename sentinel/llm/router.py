"""FreeProviderRouter — multi-provider LLM interface with automatic failover.

Provider priority (highest quality first):
  1. Groq (Llama 3.3 70B) — best quality on free tier, ~14k RPD
  2. Cerebras (llama3.1-8b) — fast fallback, 1M tokens/day
  3. Ollama (qwen2.5-coder:7b) — local, always-on emergency fallback

The router tries each provider in order. The first one that returns a
usable response wins. Each provider has its own circuit breaker so a
rate-limited or down provider gets skipped temporarily without retries.

Configuration (.env):
  GROQ_API_KEY        — enables Groq path (recommended)
  CEREBRAS_API_KEY    — enables Cerebras path
  OLLAMA_HOST         — local Ollama endpoint, e.g. http://127.0.0.1:11434

Per-provider model overrides (optional):
  GROQ_MODEL          — default: llama-3.3-70b-versatile
  CEREBRAS_MODEL      — default: llama3.1-8b
  OLLAMA_MODEL_NAME   — default: qwen2.5-coder:7b-instruct-q4_K_M

Use --private CLI flag to force local-only (skips Groq + Cerebras).
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
DEFAULT_CEREBRAS_MODEL = "llama3.1-8b"
DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"

# Model overrides via env (optional).
GROQ_MODEL = os.environ.get("GROQ_MODEL", DEFAULT_GROQ_MODEL)
CEREBRAS_MODEL = os.environ.get("CEREBRAS_MODEL", DEFAULT_CEREBRAS_MODEL)
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL_NAME", DEFAULT_OLLAMA_MODEL)

MAX_RETRIES = 2
RETRY_BACKOFF = [1.0, 3.0]
TIMEOUT_CLOUD = 60.0
TIMEOUT_LOCAL = 120.0

# Circuit breaker: after this many consecutive failures, the provider is
# marked dead for CIRCUIT_RESET_SECONDS. Stops us from beating on a dead
# endpoint and slowing every scan.
CIRCUIT_BREAK_THRESHOLD = 3
CIRCUIT_RESET_SECONDS = 120  # 2 minutes


# Models in the Qwen-3 / DeepSeek-R1 family emit <think>...</think>
# reasoning blocks before their answer. Strip them for JSON parsing.
_THINK_TAG_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


# ---------- Errors ----------

class RouterError(Exception):
    """All providers exhausted."""


# ---------- Provider abstraction ----------

class LLMProvider(ABC):
    """Abstract LLM provider. Each backend implements query() and is_enabled()."""

    name: str = "abstract"
    model: str = ""

    def __init__(self) -> None:
        self._consecutive_failures = 0
        self._circuit_open_until: float = 0.0

    @abstractmethod
    def is_enabled(self) -> bool:
        """Whether this provider can be used (e.g., has API key)."""

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
        """True if circuit breaker is currently tripped."""
        return time.monotonic() < self._circuit_open_until

    def record_success(self) -> None:
        """Reset failure count on successful call."""
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

    def record_failure(self) -> None:
        """Increment failure count; trip circuit if threshold hit."""
        self._consecutive_failures += 1
        if self._consecutive_failures >= CIRCUIT_BREAK_THRESHOLD:
            self._circuit_open_until = time.monotonic() + CIRCUIT_RESET_SECONDS
            logger.warning(
                "[%s] circuit breaker tripped — skipping for %ds",
                self.name, CIRCUIT_RESET_SECONDS,
            )


class GroqProvider(LLMProvider):
    """Groq Cloud — Llama 3.3 70B at ~300 tok/s on free tier.

    Reads GROQ_API_KEY through Settings (loaded from .env), not os.environ.
    pydantic-settings does NOT push values back into os.environ, so reading
    via Settings is the only reliable way.
    """

    name = "groq"
    model = GROQ_MODEL

    def is_enabled(self) -> bool:
        settings = get_settings()
        return bool(settings.groq_api_key.get_secret_value().strip())

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
                    GROQ_URL, json=payload, headers=headers,
                    timeout=TIMEOUT_CLOUD,
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
                        "Groq 404: model '%s' not available. "
                        "Check GROQ_MODEL or your account access.", self.model,
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
    """Cerebras Cloud — fast Llama 3.1 8B inference, 1M tokens/day free."""

    name = "cerebras"
    model = CEREBRAS_MODEL

    def is_enabled(self) -> bool:
        settings = get_settings()
        return settings.has_cerebras_key()

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
                    CEREBRAS_URL, json=payload, headers=headers,
                    timeout=TIMEOUT_CLOUD,
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
                    logger.error(
                        "Cerebras 404: model '%s' not available. "
                        "Check CEREBRAS_MODEL or your account access.", self.model,
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
    """Local Ollama — always-on fallback, slower but private."""

    name = "ollama"
    model = OLLAMA_MODEL

    def is_enabled(self) -> bool:
        # Always considered enabled — connection error trips the circuit breaker
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
        # Defensive: replace 'localhost' with '127.0.0.1' to avoid IPv6 issues
        host = settings.ollama_host.replace("localhost", "127.0.0.1")

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "stream": False,
        }
        if json_mode:
            payload["format"] = "json"

        try:
            resp = await client.post(
                f"{host.rstrip('/')}/api/chat",
                json=payload, timeout=TIMEOUT_LOCAL,
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
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            logger.warning("Ollama error: %s", e)
            return None


# ---------- Router ----------

class FreeProviderRouter:
    """Multi-provider LLM router with priority-based failover.

    Default provider order (highest quality first):
      1. Groq (Llama 3.3 70B)
      2. Cerebras (Llama 3.1 8B)
      3. Ollama (local Qwen 2.5 Coder)

    Each provider has an independent circuit breaker. If Groq is rate-limited
    or down, we skip it for 2 minutes instead of retrying every call.

    Pass force_local=True to skip cloud providers (privacy mode).
    """

    def __init__(self, force_local: bool = False) -> None:
        self._force_local = force_local
        self._client: httpx.AsyncClient | None = None
        self._providers: list[LLMProvider] = [
            GroqProvider(),
            CerebrasProvider(),
            OllamaProvider(),
        ]

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient()
        return self._client

    def _eligible_providers(self) -> list[LLMProvider]:
        """Return providers we should try, in order, given current state."""
        result: list[LLMProvider] = []
        for p in self._providers:
            if self._force_local and p.name != "ollama":
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
        """Query with automatic failover. Returns dict with content/model/provider."""
        client = await self._get_client()
        eligible = self._eligible_providers()

        if not eligible:
            raise RouterError(
                "No LLM providers available. "
                "Configure GROQ_API_KEY, CEREBRAS_API_KEY, or run Ollama locally."
            )

        last_error: Exception | None = None
        for provider in eligible:
            try:
                result = await provider.query(
                    client, messages, temperature, max_tokens, json_mode,
                )
                if result is not None:
                    provider.record_success()
                    logger.debug("[router] %s answered (model=%s)",
                                 provider.name, result.get("model"))
                    return result
                provider.record_failure()
            except Exception as e:  # noqa: BLE001
                provider.record_failure()
                last_error = e
                logger.warning("[router] %s raised %s: %s",
                               provider.name, type(e).__name__, e)

        # All providers exhausted
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
        """Query with JSON mode, parse response, strip markdown fences and reasoning tags."""
        result = await self.query(messages=messages, tier=tier, json_mode=True)
        content = result["content"].strip()

        # Strip <think>...</think> reasoning blocks (Qwen-3, DeepSeek-R1, etc.)
        content = _THINK_TAG_RE.sub("", content).strip()

        # Strip markdown code fences
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()

        # Last-resort: extract first JSON object if there's stray prose
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

    async def __aenter__(self) -> FreeProviderRouter:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
