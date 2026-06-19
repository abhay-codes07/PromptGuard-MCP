"""PromptGuard — MCP server that red-teams LLM apps against OWASP LLM Top-10.

See README.md for the full pitch and usage. Public API:

>>> from promptguard import models
>>> from promptguard.adapters import AnthropicAdapter, OpenAIAdapter, HTTPAdapter
"""

from promptguard.models import (
    AttackPrompt,
    AttackResult,
    AuditResult,
    CategoryFinding,
    ChatResponse,
    ClassificationResult,
    InjectionResult,
    Message,
    MutationAttempt,
    MutationTechnique,
    OwaspCategory,
    OwaspScores,
    RedteamReport,
    RedteamSummary,
    Severity,
    SignalType,
    Verdict,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "AttackPrompt",
    "AttackResult",
    "AuditResult",
    "CategoryFinding",
    "ChatResponse",
    "ClassificationResult",
    "InjectionResult",
    "Message",
    "MutationAttempt",
    "MutationTechnique",
    "OwaspCategory",
    "OwaspScores",
    "RedteamReport",
    "RedteamSummary",
    "Severity",
    "SignalType",
    "Verdict",
]
