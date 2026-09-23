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

- [x] **In-process output shaping in `wires call`** (never a shell, never spawns anything locally): `--jq <filter>` (a pure-Rust jq, e.g. `jaq-core`/`jaq-std`; justify the crate; lockfile via `cargo update --workspace`, never `generate-lockfile`), `--head N` (lines), `--max-bytes N` (char-boundary truncation with a note on stderr). Applied to the remote stdout after it arrives; the exit code passes through unchanged. Exposed as optional fields on `wires mcp`'s tool schema too.
- [x] Decide and document whether the shaping flags go in the **call record**. They're local, so the host never sees them; recommend a caller-side note only. The host-side `--jq` of tools like `gh` is already in argv and so already logged.
- [x] **Teach the model without a shell:** `wires tools` output and `wires mcp` tool descriptions say "filter with the tool's own flags (e.g. `gh … --jq`) or `wires call --jq/--head/--max-bytes`; pipes are not available".
- [x] **`docs/agent-sandbox.md`**: the recommended Claude Code setup in which `wires` is the only thing the agent can run. Check precisely how the installed `claude` matches Bash permission rules for compound commands (`;`, `&&`, `|`, `$(…)`, backticks, newlines) and write down what the rule `Bash(wires call:*)` does and doesn't prevent, with the test commands used as evidence. If a Bash-rule-based setup can't be made airtight, say so and recommend the structural alternatives (a sandbox or container whose PATH holds only `wires`; or `wires mcp` as the permission boundary). No overclaiming.
- [x] **Benchmark arm 5 (`bench/`):** agent permitted **only** `wires call` (the tightest rule that works, per the doc above); no local `gh`/`jq`/pipes. Host exposes `gh`. Same 5 tasks × n=5 as card 16. Report alongside the four existing arms: median input tokens, cost, turns, accuracy, and the **count of permission refusals**. Budget $15.

## Acceptance

- [x] Unit + proptest for shaping (jq on arbitrary JSON, head/max-bytes on arbitrary UTF-8 never split a char; invalid jq → clear error, exit 2, remote exit code not masked); e2e through a loopback host.
- [x] `bench/REPORT.md` updated with arm 5 and an honest paragraph: does efficiency survive a wires-only sandbox?
- [x] `docs/agent-sandbox.md` with evidence.
- [x] `bazel test //...`, lint, format check green.

## Notes

*2026-09-23, lane S (worker).* Commits: board → shaping (`caller/shape.rs`,
`call.rs`, `mcp.rs`, one line in `tools.rs`) → permission probe → merge of
`aaron/remote-cli` (card 13) + test fix → flags-after-tool → arm 5 → docs.

**Shaping.** `wires call <tool> [--jq F] [--head N] [--max-bytes N] -- args`
(flags may also come before the tool; after the tool's own args begin, or
after `--`, `--jq` belongs to the remote command). Stages run jq → head →
max-bytes. jq output matches `gh --jq`: strings raw, everything else compact
JSON, one per line; it reads every JSON value in stdout. The filter is
compiled before dialing, and a bad one exits 2 with nothing sent. A jq error
on the output exits 2 **only if the remote exited 0**; a non-zero remote code
always wins. Without shaping flags, stdout still streams; with them it is
buffered, and stderr still streams. `wires mcp` takes the same as optional
`jq`/`head`/`max_bytes` fields. A bad filter there is an `isError` tool
result, not a JSON-RPC error, and nothing is dialed. Crate: **jaq**
(`jaq-core` 3.1 / `jaq-std` 3.0 / `jaq-json` 2.0): pure Rust, and jaq-core
forbids `unsafe`. `jaq-std` needs its default features, since `funs()` only
exists with all of them; that brings jiff for dates and regex-bites. The
lockfile went through `cargo update --workspace`, which added 22 crates and
bumped nothing.

**Call record: no change.** The shaping flags aren't part of `Invocation`, so
the host never sees them, and its record is exactly what ran there. A
tool's own `--jq` is argv and is already logged. No caller-side note was
added: nothing on the caller writes to the channel today, and a record the
caller writes about itself would be unverified. Revisit if card 15 gives
callers a channel voice.

**Teaching the model.** `wires tools list` ends with a `# call: …` hint line
(`shape::CALL_HINT`). This is a small edit to `caller/tools.rs` outside the
listed files, and the list test was adjusted. Every `wires mcp` description
ends with `mcp::FILTER_HINT`. The golden MCP tests were updated.

**Permission finding (`docs/agent-sandbox.md`).** Claude Code 2.1.280 splits
compound commands and checks every part. No `;`, `&&`, `||`, `|`, `&`,
newline, `$()`, backtick, `<()`, redirect or env-prefix construct ran
anything that is refused on its own. Substitution and expansion are refused
outright. **Not airtight:** read-only commands (`cat`, `echo`) inside the
working directory are auto-allowed, alone or chained after `wires call`, in
both default and `dontAsk` modes. `< file` and globs feed working-directory
files to the host. `--disallowedTools` can close named commands, but only as
a denylist. The doc recommends `wires mcp` with no Bash tool, or a
wires-only container, over a Bash rule alone. Residual risk: an agent can
pass `wires call`'s own `--tools-file`, `--*-file` and `--relay-url` flags
under any `wires call` rule. That is follow-up work (e.g. an agent mode that
refuses them).

**Arm 5** (`Bash(wires call gh:*)` only, prompt says no shell), n=5:
median input 10,713, Σ $0.39, median 3 turns, 25/25 correct, **0 refusals**.
The same-day control (`wires` + pipe helpers): 10,332 / $0.44 / 3 / 25/25,
with 4 refusals (graphql `{…}`, a `for` loop). Card 16 MCP default:
21,088 / $1.87. The efficiency survives. Most filtering came from gh's own
`--jq` (20 of 39 calls); `wires call --jq` was used in 4 calls.
`bench/wires-up.sh` was fixed for cards 12–13 (`advanced …` plumbing, a
member-only `host.json`). `bench.py` now records `permission_denials` per
run.

**Spend:** arm 5 + control $0.83, smoke $0.10; probes $0.30 committed, plus
~$0.15 of discarded runs. The first probe run put markers outside the cwd
and was confounded by the working-directory guard, so it was re-run inside
the cwd. Total ≈ $1.40.

**Tests:** `wires_test` 345 (312 at card 12 + 23 from this card = 335, then
card 13's tests came in with the merge), `library_test` 254,
`library_doc_test` 45. Lint and `format.check` are green. `shellcheck` isn't
on this worktree's PATH, so `wires-up.sh` wasn't shellchecked.
