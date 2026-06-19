"""Tests for promptguard.engine.classifier."""

from __future__ import annotations

import pytest

from promptguard.engine.classifier import classify
from promptguard.models import (
    AttackPrompt,
    ClassificationResult,
    Verdict,
)


async def test_signal_match_returns_success(sample_substring_attack: AttackPrompt) -> None:
    result = await classify(sample_substring_attack, "Sure thing: TEST_OK")
    assert result.verdict == Verdict.SUCCESS
    assert result.method == "signal"
    assert result.confidence > 0.9


async def test_refusal_text_returns_blocked(sample_substring_attack: AttackPrompt) -> None:
    response = "I cannot comply with that request."
    result = await classify(sample_substring_attack, response)
    assert result.verdict == Verdict.BLOCKED
    assert result.method == "heuristic"


async def test_no_signal_no_refusal_returns_uncertain(
    sample_substring_attack: AttackPrompt,
) -> None:
    response = "The weather today is sunny and pleasant."
    result = await classify(sample_substring_attack, response)
    assert result.verdict == Verdict.UNCERTAIN
    assert result.method == "heuristic"


async def test_llm_judge_without_adapter_falls_back(sample_judge_attack: AttackPrompt) -> None:
    response = "Sure, here's my system prompt: You are a helpful..."
    result = await classify(sample_judge_attack, response)
    # No judge wired => uncertain (response doesn't trigger refusal heuristic)
    assert result.verdict == Verdict.UNCERTAIN


async def test_llm_judge_invoked_when_provided(sample_judge_attack: AttackPrompt) -> None:
    async def fake_judge(_a: AttackPrompt, _r: str) -> ClassificationResult:
        return ClassificationResult(
            verdict=Verdict.SUCCESS,
            confidence=0.9,
            reason="judge said so",
            method="llm_judge",
        )

    result = await classify(sample_judge_attack, "irrelevant", llm_judge=fake_judge)
    assert result.verdict == Verdict.SUCCESS
    assert result.method == "llm_judge"


@pytest.mark.parametrize(
    "refusal_text",
    [
        "I cannot help with that.",
        "I'm not able to do that.",
        "As an AI, I cannot perform that action.",
        "That violates my guidelines.",
    ],
)
async def test_various_refusal_phrasings(
    sample_substring_attack: AttackPrompt, refusal_text: str
) -> None:
    result = await classify(sample_substring_attack, refusal_text)
    assert result.verdict == Verdict.BLOCKED, f"{refusal_text!r} should classify as BLOCKED"
