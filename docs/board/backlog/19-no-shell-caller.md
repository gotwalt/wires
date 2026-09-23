# 19 — CLI efficiency without a shell: `wires` is the agent's only executable

**Lane:** S · **Depends on:** 12 (runs alongside 13–15) · **Files:** `wires/caller/call.rs` (+ a new `wires/caller/shape.rs`), `wires/caller/mcp.rs` (tool descriptions only), `bench/` (new arm), `docs/agent-sandbox.md` (new)

## Why

Card 16 found the CLI advantage comes from **filtering output before it reaches
context** (`gh --json … --jq …`), not from tool schemas. The human's concern
(2026-09-23): that assumes the agent has a general shell with `jq`, pipes, etc.,
and a safety checker can't reason about a general shell. Claude Code refused 15
CLI-arm commands under scoped permissions in card 16; the MCP arm got none refused.

The claim to make true, and measure: **CLI-style efficiency, with a permission
surface as narrow as MCP's.** The agent's sandbox allows exactly one executable,
`wires`. Everything it can do is defined remotely (`host.json`), bound to its IdP
identity, and recorded as a structured `(tool, argv)`.

## Tasks

- [ ] **In-process output shaping in `wires call`** (never a shell, never spawns anything locally): `--jq <filter>` (a pure-Rust jq, e.g. `jaq-core`/`jaq-std`; justify the crate; lockfile via `cargo update --workspace`, never `generate-lockfile`), `--head N` (lines), `--max-bytes N` (char-boundary truncation with a note on stderr). Applied to the remote stdout after it arrives; the exit code passes through unchanged. Exposed as optional fields on `wires mcp`'s tool schema too.
- [ ] Decide and document whether the shaping flags go in the **call record**. They're local, so the host never sees them; recommend a caller-side note only. The host-side `--jq` of tools like `gh` is already in argv and so already logged.
- [ ] **Teach the model without a shell:** `wires tools` output and `wires mcp` tool descriptions say "filter with the tool's own flags (e.g. `gh … --jq`) or `wires call --jq/--head/--max-bytes`; pipes are not available".
- [ ] **`docs/agent-sandbox.md`**: the recommended Claude Code setup in which `wires` is the only thing the agent can run. Check precisely how the installed `claude` matches Bash permission rules for compound commands (`;`, `&&`, `|`, `$(…)`, backticks, newlines) and write down what the rule `Bash(wires call:*)` does and doesn't prevent, with the test commands used as evidence. If a Bash-rule-based setup can't be made airtight, say so and recommend the structural alternatives (a sandbox or container whose PATH holds only `wires`; or `wires mcp` as the permission boundary). No overclaiming.
- [ ] **Benchmark arm 5 (`bench/`):** agent permitted **only** `wires call` (the tightest rule that works, per the doc above); no local `gh`/`jq`/pipes. Host exposes `gh`. Same 5 tasks × n=5 as card 16. Report alongside the four existing arms: median input tokens, cost, turns, accuracy, and the **count of permission refusals**. Budget $15.

## Acceptance

- [ ] Unit + proptest for shaping (jq on arbitrary JSON, head/max-bytes on arbitrary UTF-8 never split a char; invalid jq → clear error, exit 2, remote exit code not masked); e2e through a loopback host.
- [ ] `bench/REPORT.md` updated with arm 5 and an honest paragraph: does efficiency survive a wires-only sandbox?
- [ ] `docs/agent-sandbox.md` with evidence.
- [ ] `bazel test //...`, lint, format check green.

## Notes
