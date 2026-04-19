"""FreeProviderRouter — unified LLM interface with automatic failover.

Primary: Cerebras Cloud (free tier, Llama 3.3 70B at 2000 tok/sec)
Fallback: Local Ollama (qwen2.5-coder:7b, works offline)

All agents call this router. They never know which provider answers.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import httpx

from sentinel.core.config import get_settings

logger = logging.getLogger(__name__)

CEREBRAS_URL = "https://api.cerebras.ai/v1/chat/completions"
OLLAMA_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"
MAX_RETRIES = 3
RETRY_BACKOFF = [1.0, 3.0, 8.0]
TIMEOUT_CLOUD = 60.0
TIMEOUT_LOCAL = 120.0


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
            "model": "llama-3.3-70b",
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
                        "model": "llama-3.3-70b",
                        "provider": "cerebras",
                    }
                if resp.status_code == 429:
                    await asyncio.sleep(RETRY_BACKOFF[min(attempt, 2)])
                    continue
                if resp.status_code >= 500:
                    await asyncio.sleep(RETRY_BACKOFF[min(attempt, 2)])
                    continue
                # 4xx client error — do not retry
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
        settings = get_settings()
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
                f"{settings.ollama_host.rstrip('/')}/api/chat",
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
        # Try Cerebras first unless forced local or circuit breaker tripped
        if not self._force_local and self._cerebras_failures < self._max_cerebras_failures:
            result = await self._try_cerebras(messages, temperature, max_tokens, json_mode)
            if result is not None:
                return result

        # Fallback to Ollama
        result = await self._try_ollama(messages, temperature, max_tokens, json_mode)
        if result is not None:
            return result

        raise RouterError("All LLM providers failed")

    async def query_json(
        self, messages: list[dict[str, str]], tier: str = "T2",
    ) -> dict[str, Any]:
        """Query with JSON mode, parse response, strip markdown fences."""
        result = await self.query(messages=messages, tier=tier, json_mode=True)
        content = result["content"].strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        try:
            result["content"] = json.loads(content.strip())
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