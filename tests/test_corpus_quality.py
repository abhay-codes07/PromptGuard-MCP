"""Corpus-quality gates for the v0.1.0 ship target.

These tests guard the corpus as a versioned asset: they fail loudly if the
per-category target slips, if ids collide, if a deterministic signal is empty,
or if prompt bodies are duplicated. They complement test_corpus_loads.py, which
only checks that every entry *parses*.
"""

from __future__ import annotations

import re
from collections import Counter

from promptguard.corpus import load_by_category, load_corpus
from promptguard.models import OwaspCategory, SignalType

_ID_RE = re.compile(r"^LLM\d{2}-\d{4}")

# The v0.1.0 ship target: 50 prompts per OWASP category (200 total).
_PER_CATEGORY_TARGET = 50


def test_each_category_meets_ship_target() -> None:
    for category in OwaspCategory:
        prompts = load_by_category(category)
        assert len(prompts) >= _PER_CATEGORY_TARGET, (
            f"{category.value} has {len(prompts)} prompts, need >= {_PER_CATEGORY_TARGET}"
        )


def test_total_corpus_at_least_200() -> None:
    assert len(load_corpus()) >= 4 * _PER_CATEGORY_TARGET


def test_ids_are_unique() -> None:
    ids = [p.id for p in load_corpus()]
    dupes = [i for i, c in Counter(ids).items() if c > 1]
    assert not dupes, f"duplicate ids: {dupes}"


def test_ids_follow_canonical_format() -> None:
    for p in load_corpus():
        assert _ID_RE.match(p.id), f"id {p.id!r} does not match LLM##-####"


def test_deterministic_signals_are_non_empty_and_concrete() -> None:
    """substring/regex entries must carry a real signal, not the llm_judge sentinel."""
    for p in load_corpus():
        if p.success_signal_type in (SignalType.SUBSTRING, SignalType.REGEX):
            assert p.success_signal.strip(), f"{p.id} has an empty success_signal"
            assert p.success_signal != "llm_judge", (
                f"{p.id} is typed {p.success_signal_type.value} but its signal is 'llm_judge'"
            )


def test_llm_judge_entries_use_the_sentinel_value() -> None:
    """llm_judge entries should carry the literal 'llm_judge' signal by convention."""
    for p in load_corpus():
        if p.success_signal_type == SignalType.LLM_JUDGE:
            assert p.success_signal == "llm_judge", (
                f"{p.id} is llm_judge-typed but signal is {p.success_signal!r}"
            )


def test_prompt_bodies_are_unique() -> None:
    bodies = [p.prompt.strip() for p in load_corpus()]
    dupes = [b[:60] for b, c in Counter(bodies).items() if c > 1]
    assert not dupes, f"duplicate prompt bodies: {dupes}"


def test_every_entry_has_a_technique() -> None:
    for p in load_corpus():
        assert p.technique.strip(), f"{p.id} has an empty technique slug"
