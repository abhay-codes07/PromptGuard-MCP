"""OpenAI adapter — wraps the Chat Completions API."""

from __future__ import annotations

import os
from typing import Any

import openai

from promptguard.adapters.base import LLMAdapter
from promptguard.models import ChatResponse, Message


class OpenAIAdapter(LLMAdapter):
    """Adapter targeting OpenAI Chat Completions via the official SDK.

    Reads ``OPENAI_API_KEY`` from the environment by default.
    """

    DEFAULT_MODEL = "gpt-4o-mini"
    DEFAULT_MAX_TOKENS = 1024

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        client: openai.AsyncOpenAI | None = None,
    ) -> None:
        resolved_key = api_key or os.environ.get("OPENAI_API_KEY")
        if client is None and not resolved_key:
            raise ValueError("OPENAI_API_KEY not set. Pass api_key=... or set the env var.")
        self._client = client or openai.AsyncOpenAI(api_key=resolved_key)
        self._model = model
        self._max_tokens = max_tokens

    @property
    def name(self) -> str:
        return "openai"

    async def chat(self, messages: list[Message], **kwargs: Any) -> ChatResponse:
        """Send messages to OpenAI. All roles passed through as-is."""
        chat_messages = [{"role": m.role, "content": m.content} for m in messages]

        request: dict[str, Any] = {
            "model": kwargs.get("model", self._model),
            "max_tokens": kwargs.get("max_tokens", self._max_tokens),
            "messages": chat_messages,
        }
        if "temperature" in kwargs:
            request["temperature"] = kwargs["temperature"]

        response = await self._client.chat.completions.create(**request)
        choice = response.choices[0]

        return ChatResponse(
            content=choice.message.content or "",
            raw=response.model_dump() if hasattr(response, "model_dump") else {},
            model=response.model,
            finish_reason=choice.finish_reason,
        )
