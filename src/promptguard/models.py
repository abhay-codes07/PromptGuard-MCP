"""Pydantic schemas for PromptGuard.

Every data structure that crosses a module boundary is defined here. Tools, the
classifier, the adaptive engine, and the reporting layer all share these types
so that JSON output stays stable across versions.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OwaspCategory(StrEnum):
    """OWASP LLM Top-10 categories testable via prompt-level attacks."""

    LLM01_PROMPT_INJECTION = "LLM01_PROMPT_INJECTION"
    LLM02_INSECURE_OUTPUT = "LLM02_INSECURE_OUTPUT"
    LLM06_SENSITIVE_DISCLOSURE = "LLM06_SENSITIVE_DISCLOSURE"
    LLM08_EXCESSIVE_AGENCY = "LLM08_EXCESSIVE_AGENCY"


class Severity(StrEnum):
    """Severity of a successful attack."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MutationTechnique(StrEnum):
    """Documented jailbreak techniques the adaptive engine can apply.

    Each technique is implemented as a prompt template in ``engine/mutations.py``.
    """

    PAYLOAD_SPLITTING = "payload_splitting"
    ROLEPLAY_FRAMING = "roleplay_framing"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    MULTI_TURN_SETUP = "multi_turn_setup"
    INSTRUCTION_HIERARCHY_ATTACK = "instruction_hierarchy_attack"
    LANGUAGE_SWITCH = "language_switch"


class Verdict(StrEnum):
    """Classifier verdict on whether an attack succeeded."""

    SUCCESS = "success"  # attack worked, defenses bypassed
    BLOCKED = "blocked"  # model refused / defenses held
    ERROR = "error"  # target endpoint failed (timeout, 5xx, etc.)
    UNCERTAIN = "uncertain"  # could not classify confidently


class SignalType(StrEnum):
    """How to interpret ``AttackPrompt.success_signal``."""

    SUBSTRING = "substring"
    REGEX = "regex"
    LLM_JUDGE = "llm_judge"  # delegate to the LLM-judge classifier


# ---------------------------------------------------------------------------
# Core attack model
# ---------------------------------------------------------------------------


class AttackPrompt(BaseModel):
    """A single adversarial prompt from the corpus.

    Loaded from YAML, validated against this schema. Every entry in the corpus
    must conform — see ``corpus/__init__.py`` for the loader.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(..., description="Stable identifier, e.g. 'LLM01-0042'.")
    category: OwaspCategory
    technique: str = Field(
        ..., description="Short slug for the technique (e.g. 'instruction_override')."
    )
    severity: Severity
    prompt: str = Field(..., min_length=1, description="The actual adversarial prompt text.")
    success_signal: str = Field(
        ...,
        description=(
            "What to look for in the model's response to mark this attack as "
            "successful. Substring, regex, or 'llm_judge' depending on type."
        ),
    )
    success_signal_type: SignalType = SignalType.SUBSTRING
    references: list[str] = Field(default_factory=list, description="Source URLs.")
    notes: str | None = None

    @field_validator("id")
    @classmethod
    def _validate_id_format(cls, v: str) -> str:
        """Enforce ``LLM##-####`` shape so IDs sort and group cleanly."""
        if not v or "-" not in v:
            raise ValueError(f"id must be of form 'LLM##-####', got {v!r}")
        return v


# ---------------------------------------------------------------------------
# Adapter / LLM message types
# ---------------------------------------------------------------------------


class Message(BaseModel):
    """A single chat message, used by every adapter."""

    model_config = ConfigDict(frozen=True)
    role: Literal["system", "user", "assistant"]
    content: str


class ChatResponse(BaseModel):
    """Normalised response from any adapter."""

    model_config = ConfigDict(frozen=True)
    content: str
    raw: dict = Field(default_factory=dict, description="Raw provider response for debugging.")
    model: str | None = None
    finish_reason: str | None = None


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------


class ClassificationResult(BaseModel):
    """Output of the classifier for one (attack, response) pair."""

    model_config = ConfigDict(frozen=True)
    verdict: Verdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    reason: str = Field(..., description="Human-readable explanation of the verdict.")
    method: Literal["signal", "llm_judge", "heuristic"] = "signal"


# ---------------------------------------------------------------------------
# Per-attack result inside a redteam run
# ---------------------------------------------------------------------------


class AttackResult(BaseModel):
    """The outcome of running one attack against a target.

    If the adaptive engine kicked in, ``mutations`` will contain the chain of
    mutated attempts and ``final_verdict`` reflects the best outcome reached.
    """

    attack: AttackPrompt
    response_excerpt: str = Field(
        ...,
        description="First ~500 chars of the model's response (truncated for reports).",
    )
    classification: ClassificationResult
    latency_ms: int = Field(..., ge=0)
    mutations: list[MutationAttempt] = Field(default_factory=list)
    final_verdict: Verdict


class MutationAttempt(BaseModel):
    """One adaptive-engine mutation attempt."""

    technique: MutationTechnique
    mutated_prompt: str
    response_excerpt: str
    classification: ClassificationResult
    latency_ms: int = Field(..., ge=0)


# Pydantic forward-reference resolution
AttackResult.model_rebuild()


# ---------------------------------------------------------------------------
# Static-tool outputs (no network calls)
# ---------------------------------------------------------------------------


class CategoryFinding(BaseModel):
    """One per OWASP category in static analysis results."""

    model_config = ConfigDict(frozen=True)
    category: OwaspCategory
    risk_score: int = Field(..., ge=0, le=100)
    matches: list[str] = Field(default_factory=list, description="Evidence strings.")
    suggested_mitigations: list[str] = Field(default_factory=list)


class AuditResult(BaseModel):
    """Output of ``audit_prompt`` — static analysis of a single prompt."""

    role: Literal["system", "user"]
    overall_risk: int = Field(..., ge=0, le=100)
    findings: list[CategoryFinding]
    summary: str


class InjectionResult(BaseModel):
    """Output of ``check_injection`` — pattern match user input vs corpus."""

    matched: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_categories: list[OwaspCategory] = Field(default_factory=list)
    matched_techniques: list[str] = Field(default_factory=list)
    suggested_mitigations: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Final report shape
# ---------------------------------------------------------------------------


class OwaspScores(BaseModel):
    """Aggregate score per OWASP category, 0-100 (higher = more vulnerable)."""

    model_config = ConfigDict(frozen=True)
    LLM01: int = Field(0, ge=0, le=100)
    LLM02: int = Field(0, ge=0, le=100)
    LLM06: int = Field(0, ge=0, le=100)
    LLM08: int = Field(0, ge=0, le=100)


class RedteamSummary(BaseModel):
    """High-level summary of a red-team run."""

    model_config = ConfigDict(frozen=True)
    total_attacks: int
    succeeded: int
    blocked: int
    errors: int
    uncertain: int
    owasp_scores: OwaspScores


class RedteamReport(BaseModel):
    """Top-level report. JSON serialisation of this is the machine-readable
    output; the Markdown renderer consumes the same object."""

    target: str
    model_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    corpus_version: str = "0.1.0"
    mutation_budget: int = 3
    summary: RedteamSummary
    attacks: list[AttackResult]

    def to_dict(self) -> dict:
        """Return a JSON-safe dict. Use ``model_dump(mode='json')`` for full control."""
        return self.model_dump(mode="json")
