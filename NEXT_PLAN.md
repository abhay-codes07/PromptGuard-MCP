# PromptGuard — Next Plan (v0.1.0 → v1.0)

> Status at time of writing (2026-06-20): Phases 0–5 complete and the MCP server
> ships (`promptguard serve`, 5 tools). **Workstreams A1, B1, and B2 below are now
> DONE** — the corpus has reached 200 prompts (50/category) with a quality gate,
> the `audit` CLI is CI-native (`--max-score` gate + SARIF output), and a reusable
> GitHub Action ships. 83 tests, ruff-clean. The remaining workstreams are the
> roadmap for what comes next. **They are a plan, not yet applied.**

The goal of this plan is to take PromptGuard from "working alpha that an early
adopter can clone" to "the obvious tool you reach for to red-team an LLM app,
installable in one command and wired into CI." The work is grouped into five
workstreams. Each lists concrete deliverables, the files it touches, and a
done-bar. A recommended sequencing follows at the end.

---

## Workstream A — Ship v0.1.0 (corpus + release)

The single highest-leverage gap. Everything else is more valuable once the tool
is `pip install`-able and the corpus is credible.

**A1. Corpus expansion: 70 → 200 prompts. ✅ DONE (2026-06-20).**
- Reached 50 prompts per OWASP category across the four files in
  `src/promptguard/corpus/` (200 total). New techniques added across all four
  categories (hypothetical framing, many-shot, SSTI/SSRF/CSV/LDAP/NoSQL output
  payloads, RAG-source and memory extraction, payment redirection, supply-chain
  and infrastructure abuse, etc.).
- Added `tests/test_corpus_quality.py`: asserts ≥50 per category, unique ids,
  canonical id format, non-empty concrete signals, `llm_judge` sentinel
  consistency, and unique prompt bodies.
- *Done:* `promptguard corpus-stats` shows 200 total; quality test green.
- *Deferred refinement:* not every entry cites a `references` URL yet (existing
  entries didn't either); a follow-up pass can raise reference coverage.

**A2. PyPI release.**
- Verify the hatchling build (`uv build`), test-install the wheel in a clean venv,
  publish to PyPI as `promptguard` (or a namespaced fallback if taken).
- Add a `release` GitHub Actions workflow triggered on tag `v*` that builds and
  publishes via Trusted Publishing (OIDC, no stored token).
- *Done-bar:* `pip install promptguard` works from a clean environment; README
  install section drops the "not on PyPI yet" caveat.

**A3. Demo asset.**
- Record the asciinema/GIF promised in the roadmap: `serve` → an MCP host calling
  `audit_prompt` then `redteam_endpoint` against a deliberately-weak local echo
  endpoint shipped under `examples/`.
- *Done-bar:* GIF embedded at the top of the README.

---

## Workstream B — Make it CI-native

PromptGuard's pitch is "test before you ship." That only lands if it runs in CI.

**B1. A `promptguard` GitHub Action. ✅ DONE (2026-06-20).**
- Shipped a composite `action.yml` wrapping `promptguard audit <url>` with inputs
  for target, auth (from secrets), formats, concurrency, and the score gate, plus
  SARIF upload and report-artifact steps. Example consumer workflow in
  `examples/github_action_workflow.yml`.
- Added `--max-score <score>` to the `audit` CLI (renamed from the plan's
  `--fail-under` — see DECISIONS): exits code 3 when any OWASP category score
  exceeds the threshold, so a regression fails the build.
- *Done:* CLI gate + Action present; covered by `test_cli.py` gate tests.

**B2. SARIF output. ✅ DONE (2026-06-20).**
- Added `src/promptguard/reporting/sarif_report.py` (SARIF 2.1.0; one rule per
  OWASP category, one result per *successful* attack, severity → code-scanning
  `security-severity`). Wired `--format sarif` into the `audit` command and the
  Action's `upload-sarif` step.
- *Done:* `test_sarif.py` green; Action uploads `report.sarif` to code scanning.

**B3. Regression baselines.**
- `promptguard audit ... --baseline prev.json` diffs the current run against a
  stored report and reports newly-succeeding attacks (regressions) vs newly-
  blocked ones (improvements). New module `src/promptguard/reporting/diff.py`.
- *Done-bar:* diff summary printed and included in JSON/Markdown output.

---

## Workstream C — Deepen the attack engine

Raise the ceiling on what PromptGuard can actually find.

**C1. Multi-turn attack chains.**
- The corpus is single-turn today. Extend `AttackPrompt` with an optional
  `turns: list[str]` and teach `redteam_endpoint` to drive a conversation,
  carrying assistant replies forward. Many real jailbreaks (crescendo,
  many-shot) only work across turns.
- *Done-bar:* ≥10 multi-turn attacks in the corpus; orchestrator handles them;
  schema stays backward-compatible (single `prompt` still valid).

**C2. Expand OWASP coverage.**
- Add prompt-testable categories beyond LLM01/02/06/08 — notably **LLM07
  (insecure plugin/tool design)** and **LLM09 (overreliance / unsafe
  confident-hallucination)**. New enum members, corpus files, and aggregation.
- *Done-bar:* `OwaspScores` covers the new categories; reports render them.

**C3. Smarter adaptive engine.**
- Today the engine applies techniques in a fixed order. Make it *learn within a
  run*: track which techniques bypass this target and try those first on later
  attacks. Add a per-run technique-effectiveness table to the report.
- *Done-bar:* report includes a "most effective techniques against this target"
  section; measurable reduction in mutations-to-success on weak targets.

---

## Workstream D — Broaden reach (adapters + transports)

**D1. More target adapters.**
- Add first-class adapters for Google Gemini, AWS Bedrock, and local Ollama
  alongside the existing Anthropic/OpenAI/HTTP. Each implements `LLMAdapter`; no
  orchestrator changes needed.
- *Done-bar:* `promptguard audit` can target each provider by flag.

**D2. Streaming progress over MCP.**
- `redteam_endpoint` runs the whole corpus before returning. Add incremental
  progress via MCP progress notifications / an SSE transport so a host shows live
  status on long runs. Touches `src/promptguard/server.py`.
- *Done-bar:* an MCP host displays per-attack progress during a run.

**D3. Outbound report sink.**
- Optional webhook / S3 sink for reports so CI runs archive history centrally.
- *Done-bar:* `--sink <url>` posts the JSON report on completion.

---

## Workstream E — Production hardening

**E1. Resilience on the target path.**
- Add retry-with-backoff + per-host rate limiting in `HTTPAdapter` (respect
  `Retry-After`), and a typed error taxonomy distinguishing transport / auth /
  rate-limit / parse failures so reports explain *why* an attack errored.
- *Done-bar:* a rate-limited target degrades gracefully instead of flooding
  `ERROR` verdicts.

**E2. Observability.**
- Structured JSON logging behind `PROMPTGUARD_LOG_LEVEL`, run ids, and optional
  OpenTelemetry spans around each attack and mutation chain.
- *Done-bar:* a single run emits a correlated trace.

**E3. Eval harness.**
- A scored scenario suite (`evals/`) that runs the classifier and adaptive engine
  against fixtures with known-good verdicts, reporting precision/recall of the
  classifier. Guards against corpus or classifier regressions.
- *Done-bar:* `uv run promptguard eval` prints classifier precision/recall; runs
  in CI on a labelled fixture set.

---

## Recommended sequencing

1. ~~**Workstream A1 (corpus to 200)**~~ — ✅ done. (A2 PyPI + A3 demo still open.)
2. ~~**B1 + B2 (CI Action + SARIF)**~~ — ✅ done.
3. **E1 + E3 (resilience + eval harness)** — credibility for real targets. ← next
4. **C1 (multi-turn)** — the biggest single jump in attack power.
5. Remaining items (A2/A3, C2/C3, D*, B3, E2) as pull-driven by user demand.

## Guardrails carried forward

- Corpus stays YAML, schema-enforced; every prompt cites a source.
- Tools remain thin wrappers over the library; CLI and MCP behaviour stay identical.
- `redteam_endpoint` keeps its authorisation framing and live-request caps.
- No new dependency without a one-line rationale in `DECISIONS.md`.
