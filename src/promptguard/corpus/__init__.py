"""Corpus loader.

Loads YAML files of adversarial prompts, validates each against the
``AttackPrompt`` schema, and caches the result for the lifetime of the process.

The corpus is the heart of PromptGuard. Treat it as a versioned asset — every
prompt should cite a source in ``references`` and the v0.1.0 target is 50
prompts per file (200 total).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from promptguard.models import AttackPrompt, OwaspCategory

_CORPUS_FILES: tuple[tuple[str, OwaspCategory], ...] = (
    ("llm01_prompt_injection.yaml", OwaspCategory.LLM01_PROMPT_INJECTION),
    ("llm02_insecure_output.yaml", OwaspCategory.LLM02_INSECURE_OUTPUT),
    ("llm06_sensitive_disclosure.yaml", OwaspCategory.LLM06_SENSITIVE_DISCLOSURE),
    ("llm08_excessive_agency.yaml", OwaspCategory.LLM08_EXCESSIVE_AGENCY),
)


def _corpus_dir() -> Path:
    """Path to the YAML files. Returns the directory holding this ``__init__``."""
    return Path(__file__).parent


@lru_cache(maxsize=1)
def load_corpus() -> list[AttackPrompt]:
    """Load and validate every YAML file under ``corpus/``."""
    all_prompts: list[AttackPrompt] = []
    base = _corpus_dir()

    for filename, expected_category in _CORPUS_FILES:
        path = base / filename
        if not path.exists():
            raise FileNotFoundError(f"Corpus file missing: {path}")

        with path.open("r", encoding="utf-8") as fh:
            raw_entries = yaml.safe_load(fh) or []

        if not isinstance(raw_entries, list):
            raise ValueError(f"{filename}: top-level must be a YAML list")

        for idx, entry in enumerate(raw_entries):
            try:
                prompt = AttackPrompt.model_validate(entry)
            except Exception as exc:
                raise ValueError(f"{filename} entry {idx} failed validation: {exc}") from exc

            if prompt.category != expected_category:
                raise ValueError(
                    f"{filename} entry {idx} has category {prompt.category}, "
                    f"expected {expected_category}"
                )
            all_prompts.append(prompt)

    return all_prompts


def load_by_category(category: OwaspCategory) -> list[AttackPrompt]:
    """Return only the prompts for one OWASP category."""
    return [p for p in load_corpus() if p.category == category]


def corpus_stats() -> dict[str, int]:
    """Return a count-per-category breakdown — handy for CLI display."""
    stats: dict[str, int] = {}
    for prompt in load_corpus():
        key = prompt.category.value
        stats[key] = stats.get(key, 0) + 1
    stats["total"] = sum(v for k, v in stats.items() if k != "total")
    return stats


__all__ = ["corpus_stats", "load_by_category", "load_corpus"]
