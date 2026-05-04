"""FreeProviderRouter — unified LLM interface with automatic failover.

Primary: Cerebras Cloud (free tier, configurable model)
Fallback: Local Ollama (qwen2.5-coder:7b, works offline)

Configuration:
- CEREBRAS_API_KEY env var enables the cloud path
- CEREBRAS_MODEL env var overrides the default model name
- OLLAMA_HOST env var sets the local Ollama endpoint
  (use 127.0.0.1, NOT localhost — see _try_ollama for why)

Verified models on a default Cerebras free-tier account:
  - llama3.1-8b — always available, fast, good for triage tasks
  - qwen-3-235b-a22b-instruct-2507 — much higher quality, but rate-limited
    (often returns 429); also emits <think>...</think> tags which
    query_json() strips automatically.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Any

import httpx

from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)


CEREBRAS_URL = "https://api.cerebras.ai/v1/chat/completions"

# Default to llama3.1-8b — always available on the free tier, fast,
# sufficient quality for triage decisions (which are essentially yes/no
# verdicts on small code snippets, not generation tasks).
# Override with CEREBRAS_MODEL env var if you have access to bigger models:
#   CEREBRAS_MODEL=qwen-3-235b-a22b-instruct-2507
DEFAULT_CEREBRAS_MODEL = "llama3.1-8b"
CEREBRAS_MODEL = os.environ.get("CEREBRAS_MODEL", DEFAULT_CEREBRAS_MODEL)

OLLAMA_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"

MAX_RETRIES = 3
RETRY_BACKOFF = [1.0, 3.0, 8.0]
TIMEOUT_CLOUD = 60.0
TIMEOUT_LOCAL = 120.0

# Some Cerebras models (Qwen-3 family) emit <think>...</think> reasoning
# blocks before their answer. Strip them before JSON parsing.
_THINK_TAG_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


class RouterError(Exception):
    """All providers exhausted."""


class FreeProviderRouter:
    def __init__(self, force_local: bool = False) -> None:
        self._force_local = force_local
        self._client: httpx.AsyncClient | None = None
        self._cerebras_failures = 0
        self._max_cerebras_failures = 5

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient()
        return self._client

    async def _try_cerebras(
        self, messages: list[dict[str, str]], temperature: float, max_tokens: int,
        json_mode: bool,
    ) -> dict[str, Any] | None:
        settings = get_settings()
        if not settings.has_cerebras_key():
            return None

        payload: dict[str, Any] = {
            "model": CEREBRAS_MODEL,
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

        client = await self._get_client()
        for attempt in range(MAX_RETRIES):
            try:
                resp = await client.post(
                    CEREBRAS_URL, json=payload, headers=headers,
                    timeout=TIMEOUT_CLOUD,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    self._cerebras_failures = 0
                    return {
                        "content": data["choices"][0]["message"]["content"],
                        "model": CEREBRAS_MODEL,
                        "provider": "cerebras",
                    }
                if resp.status_code == 429:
                    # Rate limited — back off and retry
                    logger.warning("Cerebras 429 (rate limit), retry %d", attempt + 1)
                    await asyncio.sleep(RETRY_BACKOFF[min(attempt, 2)])
                    continue
                if resp.status_code == 404:
                    # Model not found — retrying is pointless, fail fast
                    logger.error(
                        "Cerebras 404: model '%s' not available. "
                        "Check CEREBRAS_MODEL or your account access.",
                        CEREBRAS_MODEL,
                    )
                    self._cerebras_failures = self._max_cerebras_failures  # trip CB
                    return None
                if resp.status_code >= 500:
                    await asyncio.sleep(RETRY_BACKOFF[min(attempt, 2)])
                    continue
                # Other 4xx — log and bail (don't retry)
                logger.warning("Cerebras %d: %s", resp.status_code, resp.text[:200])
                self._cerebras_failures += 1
                return None
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                logger.warning("Cerebras network error: %s", e)
                await asyncio.sleep(RETRY_BACKOFF[min(attempt, 2)])

        self._cerebras_failures += 1
        return None

    async def _try_ollama(
        self, messages: list[dict[str, str]], temperature: float, max_tokens: int,
        json_mode: bool,
    ) -> dict[str, Any] | None:
        """Call local Ollama.

        IMPORTANT: OLLAMA_HOST should be set to 'http://127.0.0.1:11434',
        NOT 'http://localhost:11434'. On systems where IPv6 resolves first,
        httpx tries the IPv6 socket, gets refused, then fails the whole
        connection without trying IPv4. Using the IP literal sidesteps DNS.
        """
        settings = get_settings()
        # Defensive: if config still has 'localhost', force it to 127.0.0.1
        host = settings.ollama_host.replace("localhost", "127.0.0.1")

        payload: dict[str, Any] = {
            "model": OLLAMA_MODEL,
            "messages": messages,
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "stream": False,
        }
        if json_mode:
            payload["format"] = "json"

        client = await self._get_client()
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
                "model": OLLAMA_MODEL,
                "provider": "ollama",
            }
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            logger.warning("Ollama error: %s", e)
            return None

    async def query(
        self, messages: list[dict[str, str]], tier: str = "T2",
        temperature: float = 0.0, max_tokens: int = 4096, json_mode: bool = False,
    ) -> dict[str, Any]:
        """Query with automatic failover. Returns dict with content/model/provider."""
        if not self._force_local and self._cerebras_failures < self._max_cerebras_failures:
            result = await self._try_cerebras(messages, temperature, max_tokens, json_mode)
            if result is not None:
                return result

        result = await self._try_ollama(messages, temperature, max_tokens, json_mode)
        if result is not None:
            return result

        raise RouterError("All LLM providers failed")

    async def query_json(
        self, messages: list[dict[str, str]], tier: str = "T2",
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
