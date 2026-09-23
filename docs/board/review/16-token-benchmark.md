# 16 — Benchmark: MCP tool discovery vs a plain CLI

**Lane:** bench · **Depends on:** 01–03 (current binary) · **Files:** new `bench/` directory only (scripts, task list, results); no product code

## Question

The pitch says CLIs are meaningfully more efficient than MCP for agents. The first
measurement (card 08: one tool, one question, n=1) showed −40% input tokens but
only −5% cost. The human expects the gap to be much bigger with a **realistic**
MCP setup, where the tool surface is large and tool discovery costs context.
Settle it with numbers a skeptic on the MCP team would accept.

## Design

- **MCP arm:** GitHub's official MCP server (`ghcr.io/github/github-mcp-server`
  via Docker, stdio), authenticated with `GITHUB_PERSONAL_ACCESS_TOKEN=$(gh auth token)`
  and restricted to **read-only** (`--read-only` / `GITHUB_READ_ONLY=1`, whichever the
  current server supports). Default toolsets, since that's what people actually mount.
- **CLI arm:** the same work through `gh`, exposed by a loopback
  `wires serve --expose 'gh=gh'` and called with `wires call gh -- …` from Claude
  Code's Bash tool. The network hop isn't what's being measured; it's the agent-facing
  surface. A **third arm** runs plain `gh` from Bash with no wires, to show that wires
  adds nothing over a bare CLI.
- **Fairness (this is what makes it credible):**
  - Run the MCP arm twice: once with Claude Code's default tool loading, and once
    with tool search / deferred loading forced on
    (check the current `claude` CLI docs or env for how, e.g. `ENABLE_TOOL_SEARCH`,
    and record the exact setting).
  - Same model, same prompt text apart from the one-line hint of how to reach the
    tool in the CLI arms, same `--allowedTools` scoping, and a fresh session for each run.
  - Record cache writes and reads separately; report total input, cost, turns, wall
    time, and correctness.
- **Tasks (5, read-only, public repos, answers checkable):** for example,
  1. latest release tag of `cli/cli` and its date;
  2. the 3 most recently merged PRs in `modelcontextprotocol/modelcontextprotocol`, with titles;
  3. open issue count with label `bug` in `anthropics/claude-code`;
  4. the files changed in a named commit of a small repo;
  5. a two-step task, e.g. "find the most-commented open issue in X and summarise its last comment".
  Pick tasks where a correct answer can be scored automatically or by a short rubric.
- **n = 5** per task per arm. Headless: `claude -p --output-format json`.
- **Budget:** stop and report if the spend passes $40.

## Deliverables

- `bench/run.sh` (reproducible; reads the token from `gh auth token` at runtime and never writes it to disk or logs), `bench/tasks.md`, `bench/results/<date>.jsonl` (raw per-run usage), `bench/REPORT.md`: a table per arm (median and IQR of input tokens, cost, turns, accuracy), the tool-surface size (number of MCP tools and schema bytes in context), a paragraph of honest interpretation, and the caveats.
- If the result is a small gap, say so plainly. The human wants the truth, not a slogan.

## Acceptance

- [x] All arms × tasks × 5 runs completed (or budget stop documented).
- [x] REPORT.md with the tables, the exact model/CLI versions and settings, and reproduction steps.
- [x] No secrets in the repo (`git grep -i ghp_` / `gho_` is empty).

## Notes

- **Result (n=5, 100 runs, $4.18, all correct):** median total input / Σ cost over 25 runs:
  MCP default (tool search on) 21,088 / $1.87 · MCP tool search off 30,630 / $1.40 ·
  `wires call gh` 10,539 / $0.48 · bare `gh` 6,997 / $0.42. Full tables in `bench/REPORT.md`.
- **The gap comes from response size, not schemas.** Tool search is the default in Claude Code
  2.1.280 (`ENABLE_TOOL_SEARCH` unset resolves to always-on), and it cuts the 26-tool / 68 KB
  surface to ~400 tokens of context. The MCP server returns whole objects (a 48 KB release body,
  52 KB of comments); with `gh --json/--jq` the model gets back ~256 bytes. The pitch line
  "more efficient than MCP tool schemas" should become "the agent filters output before it hits
  context"; the schema-bloat argument doesn't survive tool search. A skeptic will say (rightly)
  that a leaner MCP server would close much of this.
- **Tool search setting:** the card asked for "default vs forced on", but the default already
  *is* on, so the second arm is forced **off** (`ENABLE_TOOL_SEARCH=false`). Values are
  `true`/unset = on, `false` = off, `auto`/`auto:N` = threshold.
- **Pitfall:** `claude -p --tools ""` removes `ToolSearch`, and Claude Code then silently loads
  every MCP schema eagerly. My first smoke run hit this (both MCP arms identical). The bench
  passes `--tools=ToolSearch` / `--tools=Bash,ToolSearch`.
- wires over bare gh: +28 tokens of first-turn context. The median +3.5k input is model behavior
  (re-checking `isLatest`, cross-check calls), not protocol.
- CLI arms had 15 permission refusals (graphql `{…}` quoting, `for` loops) under the prefix
  allowlists, and MCP had 0, so the CLI numbers are slightly pessimistic. The CLI arms weren't
  held to read-only (the gh token can write). The tasks were read-only, and nothing was written.
- Raw stream-json transcripts are **not** committed (they hold whatever the model printed). Only
  the per-run summaries in `bench/results/2026-09-23.jsonl` are. `shellcheck` isn't on this
  worktree's PATH, so the bench scripts aren't shellchecked. There are no Bazel targets in `bench/`.
