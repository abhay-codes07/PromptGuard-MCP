"""Generic HTTP adapter for arbitrary chat endpoints.

This is the workhorse for ``promptguard audit <url>`` against third-party LLM
applications you don't control. You give it a URL, an optional auth header, and
a request/response template, and it sends adversarial prompts to that endpoint.
"""

from __future__ import annotations

from typing import Any

import httpx

from promptguard.adapters.base import LLMAdapter
from promptguard.models import ChatResponse, Message


class HTTPAdapter(LLMAdapter):
    """Adapter for arbitrary HTTP chat endpoints.

    The endpoint is expected to accept a JSON POST and return JSON. The default
    request body shape is ``{"messages": [{"role": ..., "content": ...}]}`` and
    response is read from ``response_path`` (a dotted path into the JSON, e.g.
    ``"choices.0.message.content"`` or simply ``"reply"``).

    For non-trivial endpoints, pass ``request_template`` (a dict where
    ``{messages}`` is interpolated) and ``response_path`` accordingly.
    """

    def __init__(
        self,
        url: str,
        *,
        auth_header: str | None = None,
        request_template: dict[str, Any] | None = None,
        response_path: str = "choices.0.message.content",
        model_id: str | None = None,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Build the adapter.

        Args:
            url: Full URL to POST to.
            auth_header: Value for the ``Authorization`` header (e.g. ``"Bearer sk-..."``).
            request_template: Custom request body. Use ``"{messages}"`` as a
                placeholder where the chat history should be injected. If
                omitted, defaults to ``{"messages": ...}``.
            response_path: Dotted path into the JSON response to extract the
                assistant's text. ``0`` indexes into lists.
            model_id: Optional model identifier to record in the report.
            timeout: HTTP timeout in seconds.
            client: Pre-built httpx client (mainly for tests with ``respx``).
        """
        self._url = url
        self._auth_header = auth_header
        self._request_template = request_template
        self._response_path = response_path
        self._model_id = model_id
        self._timeout = timeout
        self._client = client
        self._owns_client = client is None

    @property
    def name(self) -> str:
        return f"http({self._url})"

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-create the httpx client on first use."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        """Close the underlying client if we own it."""
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _build_request_body(self, messages: list[Message]) -> dict[str, Any]:
        """Build the JSON body, interpolating messages into the template."""
        msg_payload = [{"role": m.role, "content": m.content} for m in messages]

        if self._request_template is None:
            return {"messages": msg_payload}

        # Walk the template and replace any string equal to "{messages}".
        def _walk(node: Any) -> Any:
            if isinstance(node, dict):
                return {k: _walk(v) for k, v in node.items()}
            if isinstance(node, list):
                return [_walk(v) for v in node]
            if node == "{messages}":
                return msg_payload
            return node

        return _walk(self._request_template)

    def _extract_response(self, data: Any) -> str:
        """Walk ``self._response_path`` through ``data``."""
        for part in self._response_path.split("."):
            data = data[int(part)] if part.isdigit() else data[part]
        if not isinstance(data, str):
            raise ValueError(
                f"response_path {self._response_path!r} resolved to non-string: {type(data)}"
            )
        return data

    async def chat(self, messages: list[Message], **kwargs: Any) -> ChatResponse:
        """POST the messages to the target endpoint and parse the response."""
        client = await self._get_client()
        headers = {"Content-Type": "application/json"}
        if self._auth_header:
            headers["Authorization"] = self._auth_header

        body = self._build_request_body(messages)
        response = await client.post(self._url, json=body, headers=headers)
        response.raise_for_status()
        raw_json = response.json()

        try:
            content = self._extract_response(raw_json)
        except (KeyError, IndexError, ValueError) as exc:
            raise ValueError(
                f"Failed to extract response via path {self._response_path!r}: {exc}"
            ) from exc

        return ChatResponse(
            content=content,
            raw=raw_json if isinstance(raw_json, dict) else {"data": raw_json},
            model=self._model_id,
            finish_reason=None,
        )
