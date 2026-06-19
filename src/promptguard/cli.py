"""PromptGuard CLI.

Phase-1 commands (working today):
    promptguard version       — print version
    promptguard corpus-stats  — show counts per OWASP category
    promptguard audit-prompt  — static analysis of a single prompt (stdin or file)
    promptguard check-input   — pattern-match a single user input

Live + server commands:
    promptguard audit <url>   — full live red-team against an HTTP endpoint
    promptguard serve         — start the MCP server (stdio transport)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from promptguard import __version__
from promptguard.corpus import corpus_stats
from promptguard.tools.audit_prompt import audit_prompt
from promptguard.tools.check_injection import check_injection

app = typer.Typer(
    name="promptguard",
    help="MCP server that red-teams LLM apps against OWASP LLM Top-10.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()


@app.command()
def version() -> None:
    """Print the PromptGuard version."""
    typer.echo(__version__)


@app.command(name="corpus-stats")
def corpus_stats_command() -> None:
    """Show how many adversarial prompts ship in the corpus, per OWASP category."""
    stats = corpus_stats()
    table = Table(title="PromptGuard corpus", show_header=True, header_style="bold cyan")
    table.add_column("OWASP category")
    table.add_column("Prompts", justify="right")
    for key, count in stats.items():
        if key == "total":
            continue
        table.add_row(key, str(count))
    table.add_section()
    table.add_row("[bold]Total[/bold]", f"[bold]{stats['total']}[/bold]")
    console.print(table)
    console.print(
        "\n[dim]Target for v0.1.0 ship: 50 per category (200 total). "
        "Add entries to corpus/llm*.yaml.[/dim]"
    )


@app.command(name="audit-prompt")
def audit_prompt_command(
    file: Path | None = typer.Argument(
        None, help="Path to a text file containing the prompt. Reads stdin if omitted."
    ),
    role: str = typer.Option("system", "--role", help="system or user"),
    output_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
) -> None:
    """Statically analyse a prompt for OWASP LLM Top-10 weaknesses."""
    if file is not None:
        text = file.read_text(encoding="utf-8")
    elif sys.stdin.isatty():
        typer.echo("Pipe a prompt or pass a file path. See --help.", err=True)
        raise typer.Exit(code=1)
    else:
        text = sys.stdin.read()

    if role not in ("system", "user"):
        typer.echo(f"--role must be 'system' or 'user', got {role!r}", err=True)
        raise typer.Exit(code=1)

    result = audit_prompt(text, role=role)  # type: ignore[arg-type]

    if output_json:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
        return

    table = Table(
        title=f"Prompt audit (role: {role})",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Category")
    table.add_column("Risk", justify="right")
    table.add_column("Evidence")
    table.add_column("Mitigations")
    for f in result.findings:
        risk_str = f"{f.risk_score}/100"
        risk_colour = "red" if f.risk_score >= 60 else "yellow" if f.risk_score >= 35 else "green"
        table.add_row(
            f.category.value,
            f"[{risk_colour}]{risk_str}[/{risk_colour}]",
            "\n".join(f.matches) or "—",
            "\n".join(f.suggested_mitigations) or "—",
        )
    console.print(table)
    console.print(f"\n[bold]{result.summary}[/bold]")


@app.command(name="check-input")
def check_input_command(
    user_input: str = typer.Argument(..., help="The user input to scan."),
    output_json: bool = typer.Option(False, "--json", help="Emit JSON instead of a table."),
) -> None:
    """Pattern-match a user input against the adversarial-prompt corpus."""
    result = check_injection(user_input)

    if output_json:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2))
        return

    if not result.matched:
        console.print("[green]No injection patterns matched.[/green]")
        return

    console.print("[bold red]Possible injection detected[/bold red]")
    console.print(f"  confidence: {result.confidence:.2f}")
    console.print(f"  categories: {', '.join(c.value for c in result.matched_categories)}")
    console.print(f"  techniques: {', '.join(result.matched_techniques)}")
    if result.evidence:
        console.print("  evidence:")
        for e in result.evidence:
            console.print(f"    • {e}")
    if result.suggested_mitigations:
        console.print("  suggested mitigations:")
        for m in result.suggested_mitigations:
            console.print(f"    • {m}")


@app.command()
def audit(
    url: str = typer.Argument(..., help="Target chat endpoint URL (POST JSON)."),
    auth_header: str | None = typer.Option(
        None, "--auth", help="Value for the Authorization header, e.g. 'Bearer sk-...'."
    ),
    response_path: str = typer.Option(
        "choices.0.message.content",
        "--response-path",
        help="Dotted path to extract assistant text from the JSON response.",
    ),
    max_attacks: int | None = typer.Option(
        None, "--max-attacks", help="Cap the run at N attacks (smoke-test mode)."
    ),
    concurrency: int = typer.Option(
        5, "--concurrency", help="Max concurrent in-flight attacks. Lower for rate-limited targets."
    ),
    adaptive: bool = typer.Option(
        False,
        "--adaptive/--no-adaptive",
        help="Enable the adaptive mutation engine. Requires ANTHROPIC_API_KEY for the meta-LLM.",
    ),
    mutations: int = typer.Option(
        3, "--mutations", help="Max mutation attempts per failed attack (when --adaptive)."
    ),
    use_judge: bool = typer.Option(
        False,
        "--judge/--no-judge",
        help="Use a separate LLM to classify fuzzy attacks. Requires ANTHROPIC_API_KEY.",
    ),
    out_dir: Path = typer.Option(
        Path("reports"), "--out", help="Output directory for JSON + Markdown reports."
    ),
) -> None:
    """Run the full red-team against a live HTTP LLM endpoint.

    Sends the corpus of adversarial prompts to the URL, classifies each
    response, and writes JSON + Markdown reports.
    """
    import asyncio

    from promptguard.adapters.http import HTTPAdapter
    from promptguard.engine.adaptive import AdaptiveEngine
    from promptguard.reporting import write_json_report, write_markdown_report
    from promptguard.tools.redteam_endpoint import redteam_endpoint

    async def _run() -> None:
        target = HTTPAdapter(url, auth_header=auth_header, response_path=response_path)
        judge = None
        engine = None
        if use_judge or adaptive:
            from promptguard.adapters.anthropic import AnthropicAdapter

            try:
                meta = AnthropicAdapter()
            except ValueError as exc:
                typer.echo(f"[red]Cannot enable --judge/--adaptive: {exc}[/red]", err=True)
                raise typer.Exit(code=1) from exc
            if use_judge:
                judge = meta
            if adaptive:
                engine = AdaptiveEngine(meta, max_mutations=mutations)

        try:
            with console.status(f"[cyan]Red-teaming {url}…", spinner="dots"):
                report = await redteam_endpoint(
                    target,
                    judge_adapter=judge,
                    adaptive_engine=engine,
                    max_attacks=max_attacks,
                    concurrency=concurrency,
                    target_label=url,
                )
        finally:
            await target.aclose()

        # Write outputs
        json_path = write_json_report(report, out_dir / "report.json")
        md_path = write_markdown_report(report, out_dir / "report.md")

        # Summary
        s = report.summary
        console.print()
        console.print(f"[bold]Red-team complete[/bold] — {s.total_attacks} attacks")
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Category")
        table.add_column("Score", justify="right")
        for cat, score in (
            ("LLM01 Prompt Injection", s.owasp_scores.LLM01),
            ("LLM02 Insecure Output", s.owasp_scores.LLM02),
            ("LLM06 Sensitive Disclosure", s.owasp_scores.LLM06),
            ("LLM08 Excessive Agency", s.owasp_scores.LLM08),
        ):
            colour = "red" if score >= 60 else "yellow" if score >= 30 else "green"
            table.add_row(cat, f"[{colour}]{score}/100[/{colour}]")
        console.print(table)
        console.print(
            f"\n[green]✓[/green] JSON report: {json_path}"
            f"\n[green]✓[/green] Markdown report: {md_path}"
        )

    asyncio.run(_run())


@app.command()
def serve(
    transport: str = typer.Option(
        "stdio",
        "--transport",
        help="MCP transport: 'stdio' (default, for host-spawned servers) or 'sse'.",
    ),
) -> None:
    """Start the PromptGuard MCP server.

    Exposes audit_prompt, check_injection, corpus_stats, list_attacks, and
    redteam_endpoint over the Model Context Protocol. Point an MCP host (Claude
    Code, Cursor, …) at this command — see examples/claude_code_config.json.
    """
    from promptguard.server import run

    run(transport=transport)


if __name__ == "__main__":
    app()
