"""Tests for HTTPAdapter using respx to mock httpx."""

from __future__ import annotations

import httpx
import pytest
import respx

from promptguard.adapters.http import HTTPAdapter
from promptguard.models import Message


@pytest.mark.asyncio
async def test_http_adapter_default_extraction() -> None:
    mock_url = "https://example.invalid/chat"
    mock_response = {
        "choices": [{"message": {"content": "Hello from the mock!"}}],
        "model": "mock-model",
    }

    async with httpx.AsyncClient() as client:
        adapter = HTTPAdapter(mock_url, client=client, model_id="mock-model")
        with respx.mock(assert_all_called=True) as router:
            router.post(mock_url).respond(200, json=mock_response)
            result = await adapter.chat([Message(role="user", content="hi")])
        assert result.content == "Hello from the mock!"
        assert result.model == "mock-model"


@pytest.mark.asyncio
async def test_http_adapter_custom_template_and_path() -> None:
    mock_url = "https://example.invalid/v2/respond"
    mock_response = {"data": {"reply": "Custom path response"}}

    async with httpx.AsyncClient() as client:
        adapter = HTTPAdapter(
            mock_url,
            client=client,
            request_template={"input": "{messages}", "stream": False},
            response_path="data.reply",
        )
        with respx.mock(assert_all_called=True) as router:
            route = router.post(mock_url).respond(200, json=mock_response)
            await adapter.chat([Message(role="user", content="ping")])
            request_body = route.calls[0].request.read().decode()
            assert "ping" in request_body
            assert "stream" in request_body


@pytest.mark.asyncio
async def test_http_adapter_auth_header_passed() -> None:
    mock_url = "https://example.invalid/chat"
    async with httpx.AsyncClient() as client:
        adapter = HTTPAdapter(mock_url, client=client, auth_header="Bearer test-token")
        with respx.mock() as router:
            route = router.post(mock_url).respond(
                200, json={"choices": [{"message": {"content": "ok"}}]}
            )
            await adapter.chat([Message(role="user", content="hi")])
            assert route.calls[0].request.headers["Authorization"] == "Bearer test-token"


@pytest.mark.asyncio
async def test_http_adapter_bad_response_path_raises() -> None:
    mock_url = "https://example.invalid/chat"
    async with httpx.AsyncClient() as client:
        adapter = HTTPAdapter(mock_url, client=client, response_path="nonexistent.path")
        with respx.mock() as router:
            router.post(mock_url).respond(200, json={"different": "shape"})
            with pytest.raises(ValueError, match="Failed to extract response"):
                await adapter.chat([Message(role="user", content="hi")])


def test_anthropic_adapter_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from promptguard.adapters.anthropic import AnthropicAdapter

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        AnthropicAdapter()


def test_openai_adapter_requires_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from promptguard.adapters.openai import OpenAIAdapter

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        OpenAIAdapter()
