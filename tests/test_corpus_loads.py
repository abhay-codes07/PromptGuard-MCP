"""Test that every YAML entry in the corpus loads and validates."""

from __future__ import annotations

from promptguard.corpus import corpus_stats, load_by_category, load_corpus
from promptguard.models import OwaspCategory


def test_corpus_loads_without_error() -> None:
    prompts = load_corpus()
    assert len(prompts) > 0, "corpus should not be empty"


def test_every_category_has_at_least_one_prompt() -> None:
    for category in OwaspCategory:
        prompts = load_by_category(category)
        assert prompts, f"no prompts found for {category.value}"


def test_corpus_stats_totals_match() -> None:
    stats = corpus_stats()
    assert stats["total"] == sum(v for k, v in stats.items() if k != "total")
    assert stats["total"] == len(load_corpus())


def test_every_prompt_has_id_in_correct_format() -> None:
    for prompt in load_corpus():
        assert "-" in prompt.id, f"id {prompt.id!r} should contain a dash"
        assert prompt.id.startswith("LLM"), f"id {prompt.id!r} should start with LLM"


def test_every_prompt_has_non_empty_text() -> None:
    for prompt in load_corpus():
        assert prompt.prompt.strip(), f"prompt {prompt.id} has empty text"
        assert prompt.success_signal.strip(), f"prompt {prompt.id} has empty success_signal"
