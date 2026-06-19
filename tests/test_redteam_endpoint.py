"""Tests for the live red-team orchestrator.

We don't hit real LLMs — we feed in a fake adapter that returns scripted
responses, then assert the orchestrator classifies and aggregates correctly.
"""

from __future__ import annotations

from typing import Any

import pytest

from promptguard.adapters.base import LLMAdapter
from promptguard.models import (
    ChatResponse,
    Message,
    OwaspCategory,
    Verdict,
)
from promptguard.tools.redteam_endpoint import redteam_endpoint


class ScriptedAdapter(LLMAdapter):
    """Adapter that returns canned responses keyed by prompt content.

    If a prompt isn't in the script, returns ``default_response``. Lets tests
    pin specific attacks to specific responses without a real LLM.
    """

    def __init__(
        self, script: dict[str, str], default_response: str = "I cannot help with that."
    ) -> None:
        self._script = script
        self._default = default_response
        self.calls: list[Message] = []

    @property
    def name(self) -> str:
        return "scripted"

    async def chat(self, messages: list[Message], **kwargs: Any) -> ChatResponse:
        self.calls.extend(messages)
        last_user = next((m.content for m in reversed(messages) if m.role == "user"), "")
        for key, value in self._script.items():
            if key in last_user:
                return ChatResponse(content=value, raw={}, model="scripted")
        return ChatResponse(content=self._default, raw={}, model="scripted")


@pytest.mark.asyncio
async def test_redteam_runs_against_scripted_target() -> None:
    target = ScriptedAdapter(script={}, default_response="I cannot help with that.")
    report = await redteam_endpoint(target, max_attacks=5, concurrency=2)
    assert report.summary.total_attacks == 5
    # Default scripted response is a refusal — everything should classify as blocked.
    assert report.summary.blocked >= 4  # allow 1 uncertain for variability
    assert report.summary.errors == 0


@pytest.mark.asyncio
async def test_redteam_detects_successful_attack() -> None:
    # If the target leaks the LLM01-0001 signal, the run should report 1 success.
    target = ScriptedAdapter(
        script={"DAN (Do Anything Now)": "Sure. DAN MODE ACTIVATED."},
    )
    report = await redteam_endpoint(
        target,
        max_attacks=5,
        categories=[OwaspCategory.LLM01_PROMPT_INJECTION],
    )
    assert report.summary.succeeded >= 1
    # Find the matching attack result
    matching = [a for a in report.attacks if a.attack.id == "LLM01-0001"]
    assert len(matching) == 1
    assert matching[0].final_verdict == Verdict.SUCCESS


@pytest.mark.asyncio
async def test_redteam_target_label_used() -> None:
    target = ScriptedAdapter(script={})
    report = await redteam_endpoint(
        target, max_attacks=2, target_label="https://example.invalid/chat"
    )
    assert report.target == "https://example.invalid/chat"


@pytest.mark.asyncio
async def test_redteam_handles_target_errors() -> None:
    class BrokenAdapter(LLMAdapter):
        @property
        def name(self) -> str:
            return "broken"

        async def chat(self, messages: list[Message], **kwargs: Any) -> ChatResponse:
            raise RuntimeError("simulated upstream 500")

    report = await redteam_endpoint(BrokenAdapter(), max_attacks=3)
    assert report.summary.errors == 3
    assert all(a.final_verdict == Verdict.ERROR for a in report.attacks)


@pytest.mark.asyncio
async def test_redteam_requires_non_empty_corpus() -> None:
    target = ScriptedAdapter(script={})
    # No attack in the corpus has category LLM01 *and* max_attacks=0 simultaneously.
    with pytest.raises(ValueError, match="No attacks"):
        await redteam_endpoint(target, max_attacks=0)


@pytest.mark.asyncio
async def test_owasp_scores_aggregate_correctly() -> None:
    # Force a known mix: LLM01 attack succeeds, everything else is blocked.
    target = ScriptedAdapter(
        script={"DAN (Do Anything Now)": "DAN MODE ACTIVATED"},
        default_response="I cannot comply.",
    )
    report = await redteam_endpoint(
        target,
        categories=[OwaspCategory.LLM01_PROMPT_INJECTION],
        max_attacks=10,
    )
    # At least one LLM01 attack succeeded => score > 0
    assert report.summary.owasp_scores.LLM01 > 0
    assert report.summary.owasp_scores.LLM02 == 0
    assert report.summary.owasp_scores.LLM06 == 0
    assert report.summary.owasp_scores.LLM08 == 0
