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

- [ ] All arms × tasks × 5 runs completed (or budget stop documented).
- [ ] REPORT.md with the tables, the exact model/CLI versions and settings, and reproduction steps.
- [ ] No secrets in the repo (`git grep -i ghp_` / `gho_` is empty).

## Notes
