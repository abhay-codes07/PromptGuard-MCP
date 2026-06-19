"""``audit_prompt`` — static analysis of a single prompt.

Given a prompt (typically a system prompt for an LLM app), score how well it
defends against each OWASP LLM Top-10 category and suggest improvements.

This is a heuristic, not a guarantee. Use ``redteam_endpoint`` for empirical
evaluation against a live target.
"""

from __future__ import annotations

import re
from typing import Literal

from promptguard.models import AuditResult, CategoryFinding, OwaspCategory

# Defensive phrases that, if present in a system prompt, suggest the prompt
# author has thought about a given attack class. Their absence => higher risk.
_DEFENSIVE_PATTERNS: dict[OwaspCategory, list[str]] = {
    OwaspCategory.LLM01_PROMPT_INJECTION: [
        r"never follow instructions",
        r"ignore (any|all) user (attempts|instructions)",
        r"do not deviate",
        r"user input is untrusted",
        r"<(user|input)>",  # delimited input
    ],
    OwaspCategory.LLM02_INSECURE_OUTPUT: [
        r"do not (produce|output|emit) (scripts?|html|sql|shell)",
        r"escape (any |all )?special characters",
        r"wrap (all )?code in (code )?blocks",
    ],
    OwaspCategory.LLM06_SENSITIVE_DISCLOSURE: [
        r"never (reveal|disclose|repeat) (this |the |your )?(system )?prompt",
        r"do not list (your )?tools",
        r"do not echo",
    ],
    OwaspCategory.LLM08_EXCESSIVE_AGENCY: [
        r"require (user )?confirmation",
        r"never (delete|drop|email|send) (without|unless)",
        r"only (use|invoke) tools when",
        r"do not assume",
    ],
}


# Risky language in a system prompt — phrases that often correlate with weak
# defenses or invite injection.
_RISKY_PATTERNS: dict[OwaspCategory, list[str]] = {
    OwaspCategory.LLM01_PROMPT_INJECTION: [
        r"\byou are an? unrestricted\b",
        r"\bdo anything the user asks\b",
        r"\bnever refuse\b",
    ],
    OwaspCategory.LLM06_SENSITIVE_DISCLOSURE: [
        r"\b(api[_ ]?key|secret|password|token)\b\s*[:=]",
    ],
    OwaspCategory.LLM08_EXCESSIVE_AGENCY: [
        r"\b(act|behave) as (the )?admin\b",
        r"\byou have full access\b",
    ],
}


def _score_category(prompt: str, category: OwaspCategory) -> CategoryFinding:
    """Score a single category 0-100 (higher = more vulnerable)."""
    defensive_hits: list[str] = []
    risky_hits: list[str] = []

    for pat in _DEFENSIVE_PATTERNS.get(category, []):
        m = re.search(pat, prompt, flags=re.IGNORECASE)
        if m:
            defensive_hits.append(m.group(0))

    for pat in _RISKY_PATTERNS.get(category, []):
        m = re.search(pat, prompt, flags=re.IGNORECASE)
        if m:
            risky_hits.append(m.group(0))

    # Heuristic: start at 50 (neutral). Each defensive hit -15, each risky +20.
    risk = 50 - 15 * len(defensive_hits) + 20 * len(risky_hits)
    risk = max(0, min(100, risk))

    mitigations: list[str] = []
    if not defensive_hits:
        mitigations.append(
            f"No defensive language found for {category.value}. Add explicit "
            "instructions on how to handle this attack class."
        )
    if risky_hits:
        mitigations.append(f"Risky phrasing detected ({', '.join(risky_hits)}). Tighten or remove.")

    return CategoryFinding(
        category=category,
        risk_score=risk,
        matches=defensive_hits + risky_hits,
        suggested_mitigations=mitigations,
    )


def audit_prompt(prompt: str, role: Literal["system", "user"] = "system") -> AuditResult:
    """Statically analyse a single prompt.

    Args:
        prompt: The text to analyse.
        role: ``"system"`` for system prompts (default), ``"user"`` for user input.

    Returns:
        An ``AuditResult`` with per-category risk scores and an overall score.
    """
    findings = [_score_category(prompt, cat) for cat in OwaspCategory]
    overall = int(sum(f.risk_score for f in findings) / len(findings))

    highest = max(findings, key=lambda f: f.risk_score)
    summary = (
        f"Overall risk: {overall}/100. "
        f"Highest risk category: {highest.category.value} ({highest.risk_score}/100)."
    )
    if overall < 25:
        summary += " Prompt shows strong defensive language across categories."
    elif overall < 50:
        summary += " Some defensive gaps; recommended to harden before production use."
    else:
        summary += " Significant gaps; run a full red-team with ``redteam_endpoint``."

    return AuditResult(
        role=role,
        overall_risk=overall,
        findings=findings,
        summary=summary,
    )
