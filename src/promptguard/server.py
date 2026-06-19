"""PromptGuard MCP server.

This is the keystone of "PromptGuard-MCP": it exposes PromptGuard's red-team
tooling over the Model Context Protocol so an agent (Claude Code, Cursor, etc.)
can drive a security audit of an LLM application conversationally.

The server is a thin, declarative shell over the library functions in
``promptguard.tools`` — the model selects tools by their descriptions; there is
no hand-written dispatcher. Every tool returns a JSON-serialisable dict derived
from the same Pydantic schemas the CLI and reporting layers use, so output stays
stable across transports.

Tools exposed:

* ``audit_prompt``     — static, no-network analysis of a single prompt.
* ``check_injection``  — static, no-network pattern match of one user input.
* ``corpus_stats``     — how many adversarial prompts ship, per OWASP category.
* ``list_attacks``     — enumerate corpus entries (optionally filtered).
* ``redteam_endpoint`` — live red-team against an HTTP chat endpoint.

Run it with ``promptguard serve`` (stdio transport — the MCP default for local
servers spawned by a host like Claude Code).
"""

from __future__ import annotations

import logging
import os
from typing import Annotated, Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from promptguard import __version__
from promptguard.corpus import corpus_stats as _corpus_stats
from promptguard.corpus import load_corpus
from promptguard.models import OwaspCategory
from promptguard.tools.audit_prompt import audit_prompt as _audit_prompt
from promptguard.tools.check_injection import check_injection as _check_injection

logger = logging.getLogger(__name__)

# Hard cap so an MCP client can never accidentally launch an unbounded run
# against a third-party endpoint (which would look like an attack to them).
_MAX_ATTACKS_CEILING = 200

mcp = FastMCP(
    "promptguard",
    instructions=(
        "PromptGuard red-teams LLM applications against the OWASP LLM Top-10. "
        "Use audit_prompt / check_injection for fast static checks with no network "
        "calls. Use redteam_endpoint to empirically attack a live HTTP chat endpoint "
        "you are AUTHORISED to test — it sends adversarial prompts and scores the "
        "responses. Always confirm the user owns or is permitted to test a target "
        "before calling redteam_endpoint."
    ),
)


@mcp.tool()
def audit_prompt(
    prompt: Annotated[str, Field(description="The prompt text to analyse.")],
    role: Annotated[
        Literal["system", "user"],
        Field(description="'system' for a system prompt (default), 'user' for user input."),
    ] = "system",
) -> dict[str, Any]:
    """Statically score a single prompt against the OWASP LLM Top-10.

    No network calls. Returns per-category risk scores (0-100, higher = more
    vulnerable), evidence strings, and suggested mitigations. Use this to harden
    a system prompt before deploying — for empirical results against a live
    model, use redteam_endpoint instead.
    """
    return _audit_prompt(prompt, role=role).model_dump(mode="json")


@mcp.tool()
def check_injection(
    user_input: Annotated[str, Field(description="The user-supplied text to scan.")],
    system_prompt: Annotated[
        str | None,
        Field(description="Optional host system prompt for context (reserved)."),
    ] = None,
) -> dict[str, Any]:
    """Fast pattern-match one user input against known prompt-injection shapes.

    No network calls. Returns whether the input matched, a confidence score, the
    matched OWASP categories and technique slugs, evidence, and mitigations.
    This is the cheap pre-flight gate you run on inbound traffic; redteam_endpoint
    is the thorough offline audit.
    """
    return _check_injection(user_input, system_prompt=system_prompt).model_dump(mode="json")


@mcp.tool()
def corpus_stats() -> dict[str, Any]:
    """Return how many adversarial prompts ship in the corpus, per OWASP category.

    Useful to confirm coverage before a run, and as the first link in a
    composable chain (corpus_stats -> list_attacks -> redteam_endpoint).
    """
    stats = _corpus_stats()
    return {"corpus_version": __version__, "counts": stats}


@mcp.tool()
def list_attacks(
    category: Annotated[
        OwaspCategory | None,
        Field(description="Restrict to one OWASP category. Omit for all."),
    ] = None,
    limit: Annotated[
        int,
        Field(description="Max entries to return.", ge=1, le=_MAX_ATTACKS_CEILING),
    ] = 50,
) -> dict[str, Any]:
    """Enumerate corpus attack prompts (metadata only — no prompt bodies).

    Returns id, category, technique, and severity for each entry, optionally
    filtered by category. Pair this with redteam_endpoint's ``categories``
    argument to scope a run. Prompt bodies are withheld to keep the payload small
    and to avoid surfacing raw attack strings unnecessarily.
    """
    corpus = load_corpus()
    if category is not None:
        corpus = [p for p in corpus if p.category == category]
    entries = [
        {
            "id": p.id,
            "category": p.category.value,
            "technique": p.technique,
            "severity": p.severity.value,
        }
        for p in corpus[:limit]
    ]
    return {"total_matching": len(corpus), "returned": len(entries), "attacks": entries}


@mcp.tool()
async def redteam_endpoint(
    url: Annotated[str, Field(description="Target chat endpoint URL (receives a JSON POST).")],
    auth_header: Annotated[
        str | None,
        Field(description="Value for the Authorization header, e.g. 'Bearer sk-...'."),
    ] = None,
    response_path: Annotated[
        str,
        Field(description="Dotted path to the assistant text in the JSON response."),
    ] = "choices.0.message.content",
    max_attacks: Annotated[
        int | None,
        Field(description="Cap the run at N attacks. Omit to run the full corpus."),
    ] = None,
    categories: Annotated[
        list[OwaspCategory] | None,
        Field(description="Restrict to these OWASP categories. Omit for all."),
    ] = None,
    concurrency: Annotated[
        int,
        Field(description="Max concurrent in-flight attacks.", ge=1, le=20),
    ] = 5,
    adaptive: Annotated[
        bool,
        Field(description="Enable the adaptive mutation engine (needs ANTHROPIC_API_KEY)."),
    ] = False,
    mutations: Annotated[
        int,
        Field(description="Max mutation attempts per failed attack when adaptive.", ge=1, le=7),
    ] = 3,
    use_judge: Annotated[
        bool,
        Field(description="Use an LLM-judge for fuzzy attacks (needs ANTHROPIC_API_KEY)."),
    ] = False,
) -> dict[str, Any]:
    """Run a live red-team against an HTTP chat endpoint you are authorised to test.

    Sends adversarial prompts from the corpus to ``url``, classifies each
    response (signal -> LLM-judge -> refusal-heuristic), optionally mutates failed
    attacks with the adaptive engine, and returns a structured RedteamReport with
    per-category OWASP vulnerability scores (0-100). This performs real network
    requests against the target — only call it for endpoints the user owns or is
    explicitly permitted to test.

    The endpoint must accept ``{"messages": [...]}`` JSON and return JSON with the
    assistant text reachable via ``response_path``.
    """
    # Imported lazily so the static tools and `list_attacks` stay import-light.
    from promptguard.adapters.http import HTTPAdapter
    from promptguard.tools.redteam_endpoint import redteam_endpoint as _run

    if max_attacks is not None:
        max_attacks = min(max_attacks, _MAX_ATTACKS_CEILING)

    judge = None
    engine = None
    if use_judge or adaptive:
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ValueError(
                "adaptive/use_judge require ANTHROPIC_API_KEY in the server environment."
            )
        from promptguard.adapters.anthropic import AnthropicAdapter
        from promptguard.engine.adaptive import AdaptiveEngine

        meta = AnthropicAdapter()
        if use_judge:
            judge = meta
        if adaptive:
            engine = AdaptiveEngine(meta, max_mutations=mutations)

    target = HTTPAdapter(url, auth_header=auth_header, response_path=response_path)
    try:
        report = await _run(
            target,
            judge_adapter=judge,
            adaptive_engine=engine,
            max_attacks=max_attacks,
            categories=categories,
            concurrency=concurrency,
            target_label=url,
        )
    finally:
        await target.aclose()

    return report.to_dict()


def run(transport: str = "stdio") -> None:
    """Start the MCP server. Defaults to stdio (local host-spawned server)."""
    logging.basicConfig(
        level=os.environ.get("PROMPTGUARD_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    logger.info("Starting PromptGuard MCP server v%s (transport=%s)", __version__, transport)
    mcp.run(transport=transport)  # type: ignore[arg-type]


if __name__ == "__main__":
    run()
