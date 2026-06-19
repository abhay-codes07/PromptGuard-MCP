"""SARIF report writer — for GitHub code scanning / security tooling.

Renders a ``RedteamReport`` into a SARIF 2.1.0 log so red-team findings show up
in a repository's Security tab (or any SARIF-aware viewer). Each *successful*
attack becomes a SARIF ``result``; each OWASP category becomes a SARIF ``rule``.

Why only successes? A SARIF result represents a finding to act on. Blocked/
uncertain/error outcomes are not vulnerabilities, so emitting them as results
would create noise in code-scanning dashboards. The full ledger lives in the
JSON/Markdown reports.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
GitHub upload: https://docs.github.com/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github
"""

from __future__ import annotations

import json
from pathlib import Path

from promptguard.models import (
    OwaspCategory,
    RedteamReport,
    Severity,
    Verdict,
)

_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_TOOL_URI = "https://github.com/abhay-codes07/promptguard"

_CATEGORY_NAMES = {
    OwaspCategory.LLM01_PROMPT_INJECTION: "Prompt Injection",
    OwaspCategory.LLM02_INSECURE_OUTPUT: "Insecure Output Handling",
    OwaspCategory.LLM06_SENSITIVE_DISCLOSURE: "Sensitive Information Disclosure",
    OwaspCategory.LLM08_EXCESSIVE_AGENCY: "Excessive Agency",
}

# Map our severity to the SARIF result "level" and a numeric security-severity
# (GitHub uses 0.0-10.0 to bucket Critical/High/Medium/Low in the UI).
_LEVEL_BY_SEVERITY = {
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}
_SECURITY_SEVERITY = {
    Severity.LOW: "2.0",
    Severity.MEDIUM: "5.0",
    Severity.HIGH: "7.5",
    Severity.CRITICAL: "9.5",
}


def _rule_id(category: OwaspCategory) -> str:
    """Stable SARIF rule id, e.g. 'promptguard/LLM01_PROMPT_INJECTION'."""
    return f"promptguard/{category.value}"


def _build_rules() -> list[dict]:
    """One SARIF rule per OWASP category we test."""
    rules: list[dict] = []
    for category in OwaspCategory:
        name = _CATEGORY_NAMES[category]
        rules.append(
            {
                "id": _rule_id(category),
                "name": category.value,
                "shortDescription": {"text": f"OWASP LLM — {name}"},
                "fullDescription": {
                    "text": (
                        f"Target was vulnerable to a {name} attack from the PromptGuard "
                        "corpus. The model produced output satisfying the attacker's goal."
                    )
                },
                "helpUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
                "defaultConfiguration": {"level": "error"},
            }
        )
    return rules


def render_sarif(report: RedteamReport) -> dict:
    """Render the report as a SARIF 2.1.0 log (a JSON-serialisable dict).

    Args:
        report: The populated red-team report.

    Returns:
        A dict conforming to the SARIF 2.1.0 schema. Only successful attacks are
        emitted as results; the target identifier is used as the artifact URI.
    """
    results: list[dict] = []
    for attack_result in report.attacks:
        if attack_result.final_verdict != Verdict.SUCCESS:
            continue
        attack = attack_result.attack
        severity = attack.severity
        via_adaptive = bool(attack_result.mutations)
        message = (
            f"{attack.id} ({attack.technique}) succeeded against the target"
            + (" via the adaptive mutation engine" if via_adaptive else "")
            + f". Severity: {severity.value}."
        )
        results.append(
            {
                "ruleId": _rule_id(attack.category),
                "level": _LEVEL_BY_SEVERITY[severity],
                "message": {"text": message},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[severity],
                    "attackId": attack.id,
                    "technique": attack.technique,
                    "category": attack.category.value,
                    "viaAdaptiveEngine": via_adaptive,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report.target},
                        }
                    }
                ],
                "partialFingerprints": {
                    # Stable across runs so GitHub can dedupe the same finding.
                    "promptguardAttackId": f"{report.target}:{attack.id}",
                },
            }
        )

    return {
        "version": _SARIF_VERSION,
        "$schema": _SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PromptGuard",
                        "informationUri": _TOOL_URI,
                        "version": report.corpus_version,
                        "rules": _build_rules(),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(report: RedteamReport, path: Path) -> Path:
    """Write a SARIF report to ``path`` and return the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = render_sarif(report)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
