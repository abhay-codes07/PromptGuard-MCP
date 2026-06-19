"""Anthropic adapter — wraps the Messages API into the LLMAdapter interface."""

from __future__ import annotations

import os
from typing import Any

import anthropic

from promptguard.adapters.base import LLMAdapter
from promptguard.models import ChatResponse, Message


class AnthropicAdapter(LLMAdapter):
    """Adapter targeting Anthropic's Claude models via the official SDK.

    Reads ``ANTHROPIC_API_KEY`` from the environment by default. Pass
    ``api_key`` explicitly only in tests.
    """

    DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
    DEFAULT_MAX_TOKENS = 1024

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        client: anthropic.AsyncAnthropic | None = None,
    ) -> None:
        """Build the adapter without making any network calls.

        Args:
            api_key: Override ``ANTHROPIC_API_KEY``. Useful for tests.
            model: Model id to use by default.
            max_tokens: Default completion length cap.
            client: Pre-built async client (mainly for dependency injection in tests).
        """
        resolved_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if client is None and not resolved_key:
            raise ValueError("ANTHROPIC_API_KEY not set. Pass api_key=... or set the env var.")
        self._client = client or anthropic.AsyncAnthropic(api_key=resolved_key)
        self._model = model
        self._max_tokens = max_tokens

    @property
    def name(self) -> str:
        return "anthropic"

    async def chat(self, messages: list[Message], **kwargs: Any) -> ChatResponse:
        """Send messages to Claude. System messages are passed via the ``system`` arg."""
        system_parts = [m.content for m in messages if m.role == "system"]
        chat_messages = [
            {"role": m.role, "content": m.content}
            for m in messages
            if m.role in ("user", "assistant")
        ]

        request: dict[str, Any] = {
            "model": kwargs.get("model", self._model),
            "max_tokens": kwargs.get("max_tokens", self._max_tokens),
            "messages": chat_messages,
        }
        if system_parts:
            request["system"] = "\n\n".join(system_parts)
        if "temperature" in kwargs:
            request["temperature"] = kwargs["temperature"]

        response = await self._client.messages.create(**request)

        # Concatenate text blocks. Anthropic SDK returns a structured list.
        text_parts: list[str] = []
        for block in response.content:
            if hasattr(block, "text"):
                text_parts.append(block.text)
        content = "".join(text_parts)

        return ChatResponse(
            content=content,
            raw=response.model_dump() if hasattr(response, "model_dump") else {},
            model=response.model,
            finish_reason=response.stop_reason,
        )
