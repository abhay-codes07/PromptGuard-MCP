# Design decisions

A running log of non-obvious engineering decisions, newest first. One line of
rationale each — enough to defend the choice against a reasonable alternative.

## 2026-06-20 — MCP server uses FastMCP over a hand-rolled protocol loop

`promptguard serve` is built on `mcp.server.fastmcp.FastMCP` (decorator-based
tool registration) rather than the lower-level `mcp.server.Server`. Tools are
declared with typed `Annotated[..., Field(...)]` signatures so the protocol-level
input schema is generated from the function signature — no second source of
truth. **Alternative considered:** the low-level `Server` API with manual
`list_tools`/`call_tool` handlers. Rejected: it would reintroduce exactly the
hand-written dispatcher we want to avoid, and duplicate the schema we already get
for free from the Pydantic-typed tool functions.

## 2026-06-20 — MCP tools are thin wrappers over `promptguard.tools`, returning dicts

Each server tool delegates to the existing library function and returns
`model.model_dump(mode="json")`. The server adds no business logic — it is a
transport. This keeps the CLI and the MCP server behaviourally identical and
means the test suite for the underlying tools already covers the hard parts; the
server tests only need to verify wiring, schema, and the safety cap.

## 2026-06-20 — `redteam_endpoint` carries a hard 200-attack ceiling at the MCP boundary

An MCP host can call tools autonomously. To prevent a model from launching an
unbounded volume of live requests at a third-party endpoint (which reads as an
attack to the target), `max_attacks` is clamped to `_MAX_ATTACKS_CEILING = 200`
inside the server tool, and the tool description explicitly instructs the model
to confirm authorisation before calling. The CLI path keeps no such cap because
it is human-driven.

## 2026-06-20 — `list_attacks` returns metadata only, never prompt bodies

The MCP `list_attacks` tool exposes id/category/technique/severity but withholds
the raw adversarial `prompt` text. Rationale: keep payloads small for context
windows, and avoid surfacing a ready-to-paste attack corpus through a
conversational interface when the metadata is enough to scope a run.
