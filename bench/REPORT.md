# MCP vs CLI: token benchmark (card 16)

*Run 2026-09-23 (UTC): 4 arms × 5 tasks × 5 reps = 100 headless Claude Code
sessions, all 100 scored correct. Total spend $4.18 (smoke tests: about $1.70 more).
Arm 5 (card 19, [below](#arm-5-wires-is-the-only-thing-the-agent-can-run)) added
50 more sessions the same day: $0.83, all correct.*

*Note: the setup has changed since these runs. `bench/wires-up.sh` now
registers `gh` in the admin-signed registry for a role `bench` matched on the
benchmark's IdP identity, and the agent signs in with `wires login`. The
results and the setup table below are from the runs as they were.*

## Headline

The CLI arms used **about half to a third of the input tokens** and cost
**about a quarter as much** as the GitHub MCP server:

| arm | median total input | Σ cost, 25 runs | accuracy |
|---|---|---|---|
| MCP, Claude Code default (tool search on) | 21,088 | $1.87 | 25/25 |
| MCP, tool search forced off | 30,630 | $1.40 | 25/25 |
| `wires call gh` | 10,539 | $0.48 | 25/25 |
| bare `gh` | 6,997 | $0.42 | 25/25 |
| **arm 5**: `wires call gh` only, no shell helpers (card 19) | 10,713 | $0.39 | 25/25 |

**The gap does not come mainly from tool definitions.** Claude Code's default
tool search keeps the 26 GitHub tool schemas out of context: they add ~400
tokens and one extra turn. Most of the gap comes from **response size**. The
MCP server returns whole API objects: a 48 KB release body, or a 52 KB comment
thread. With the CLI, the model picked fields before anything reached context
(`gh release view --json tagName,publishedAt`, `--jq '.files[].filename'`),
and got back 256 bytes. On the task with a small response (t4), cost was
nearly the same ($0.011 MCP vs $0.009 CLI).

## Setup (exact)

| | |
|---|---|
| Claude Code | 2.1.280, `--model opus` → `claude-opus-5-5` (the human's configured default) |
| MCP server | `ghcr.io/github/github-mcp-server` v1.12.2 (commit 85598ba, digest `sha256:508a0857…cac6`), `docker run -i --rm -e GITHUB_PERSONAL_ACCESS_TOKEN … stdio --read-only`, default toolsets (context, copilot, issues, pull_requests, repos, users) |
| gh | 2.101.0 |
| wires | the `wires` binary of the day, a loopback responder serving the local `gh` (card 16's four arms: a `--expose 'gh=gh'` flag; arm 5: a member-only `host.json`); the agent reached it by node id + 127.0.0.1 address (`bench/wires-up.sh`) |
| Session | `claude -p --output-format stream-json --verbose --no-session-persistence --strict-mcp-config --setting-sources project --disable-slash-commands --tools=<arm> --allowedTools=<arm>`, fresh session per run, empty cwd, minimal env (HOME/USER/PATH/…) plus `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1 CLAUDE_CODE_DISABLE_AUTO_MEMORY=1 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` |
| Built-in tools | MCP arms: `--tools=ToolSearch` (+ the MCP server). CLI arms: `--tools=Bash,ToolSearch` |
| Permissions | MCP: `mcp__github`. wires: `Bash(wires call gh:*)`, gh: `Bash(gh:*)`, and both get `Bash(jq/head/tail/grep/wc/sort:*)`. Arm 5 (wires-only): `Bash(wires call gh:*)` and nothing else |
| Tool search | **mcp**: `ENABLE_TOOL_SEARCH` unset. In 2.1.280 an unset value resolves to mode `tst` (tool search always on); this is the default users get. **mcp-eager**: `ENABLE_TOOL_SEARCH=false` → mode `standard` (every schema sent up front). Read from the CLI's mode resolver (`auto`/`auto:N` = threshold mode, `true` = on, `false` = off). The card asked for "default vs forced on". Default already *is* on, so the useful second arm is forced **off** |
| Concurrency | one lane per arm, run in parallel. Each lane runs its 5 tasks in sequence; 5 reps in sequence |

**Pitfall found in the smoke test:** with `--tools ""` (no built-ins), the
`ToolSearch` tool isn't there, and Claude Code **silently falls back to
loading every MCP schema eagerly**. The two MCP arms were then identical
(13.5k first-turn context each). The real run gives both MCP arms
`ToolSearch` explicitly. Anyone reproducing this with `--tools` must do the same.

## Tool surface

- **26 tools, 68,380 bytes** of `tools/list` JSON (`bench/tool-surface.sh`),
  for the default toolsets in read-only mode.
- **In context, first turn** (median over 25 runs, system prompt included):
  bare `gh` 3,256 tokens · `wires` 3,284 · MCP with tool search 3,650 ·
  MCP eager **13,465**. The eager schemas cost ~10.2k tokens. Tool search cuts
  that to ~400, then pays ~1 `ToolSearch` call per run (26 across 25 runs).

## Results

### Per arm (all tasks pooled; median, IQR in parentheses)

| arm | runs | total input tokens | uncached input | cache write | cache read | output | cost (USD) | turns | wall s | accuracy |
|---|---|---|---|---|---|---|---|---|---|---|
| mcp | 25 | 21,088 (16,992–32,459) | 6 | 2,927 (0–11,756) | 14,856 (12,788–19,653) | 709 | 0.0390 (0.0119–0.1111) | 3 (3–4) | 10.6 (8.6–14.1) | 25/25 |
| mcp-eager | 25 | 30,630 (27,664–47,895) | 4 | 1,418 (0–3,690) | 27,660 (26,864–41,095) | 407 | 0.0364 (0.0130–0.0491) | 2 (2–2) | 8.9 (6.9–12.3) | 25/25 |
| wires | 25 | 10,539 (7,309–14,176) | 6 | 731 (223–1,114) | 10,203 (6,574–13,569) | 571 | 0.0189 (0.0092–0.0258) | 3 (2–4) | 10.3 (8.0–12.6) | 25/25 |
| gh | 25 | 6,997 (6,722–11,283) | 4 | 588 (210–993) | 6,718 (6,508–10,114) | 496 | 0.0150 (0.0086–0.0218) | 2 (2–3) | 7.5 (5.7–10.7) | 25/25 |

"Total input" = uncached + cache write + cache read, summed over every turn.

### Sums over the whole run (each arm did the same 25 task-runs)

| arm | Σ total input | Σ cache write | Σ cost (USD) | Σ turns |
|---|---|---|---|---|
| mcp | 612,292 | 183,942 | 1.87 | 86 |
| mcp-eager | 982,951 | 122,143 | 1.40 | 59 |
| wires | 278,499 | 20,550 | 0.48 | 76 |
| gh | 244,282 | 16,906 | 0.42 | 69 |

### Per task (median total input / median cost USD / median turns / accuracy)

| task | mcp | mcp-eager | wires | gh |
|---|---|---|---|---|
| t1-release | 32,459 / 0.012 / 3 / 5/5 | 47,895 / 0.013 / 2 / 5/5 | 10,539 / 0.009 / 3 / 5/5 | 6,650 / 0.007 / 2 / 5/5 |
| t2-merged-prs | 17,631 / 0.058 / 3 / 5/5 | 30,628 / 0.046 / 2 / 5/5 | 11,671 / 0.025 / 3 / 5/5 | 6,971 / 0.015 / 2 / 5/5 |
| t3-bug-count | 25,349 / 0.035 / 4 / 5/5 | 27,335 / 0.017 / 2 / 5/5 | 14,176 / 0.019 / 4 / 5/5 | 14,102 / 0.025 / 4 / 5/5 |
| t4-commit-files | 12,794 / 0.011 / 3 / 5/5 | 27,664 / 0.013 / 2 / 5/5 | 6,790 / 0.009 / 2 / 5/5 | 6,722 / 0.009 / 2 / 5/5 |
| t5-most-commented | 43,800 / 0.215 / 4 / 5/5 | 57,188 / 0.058 / 3 / 5/5 | 14,987 / 0.027 / 4 / 5/5 | 11,079 / 0.021 / 3 / 5/5 |

The median t1 cost is low for every arm because its prefix was cached from
earlier runs. The 21k-token release body is paid for as a cache *write* on
most MCP t1 runs, and that pushes MCP's IQR and Σ cost up.

### Where the bytes come from (tool-result characters, summed over 5 reps)

| task | mcp | mcp-eager | wires | gh |
|---|---|---|---|---|
| t1-release | 240,410 | 240,030 | 1,467 | 709 |
| t2-merged-prs | 38,023 | 32,118 | 11,577 | 1,980 |
| t3-bug-count | 57,584 | 1,761 | 111 | 304 |
| t4-commit-files | 6,985 | 6,645 | 400 | 390 |
| t5-most-commented | 171,672 | 117,480 | 5,323 | 7,591 |

## Interpretation

The CLI advantage is real, and bigger than card 08's n=1 (−40% input, −5%
cost). Against Claude Code's default MCP setup, `wires call gh` used **−50%
input tokens (median) and −74% cost (total)**. Bare `gh` was a little lower
again. But the reason is not the one the pitch gives first. Tool
*definitions* barely matter now: tool search holds a 26-tool, 68 KB server
to ~400 tokens of standing context. Forcing tool search off added ~10k
tokens per turn, but because that prefix caches well it actually cost
*less* than tool search (Σ $1.40 vs $1.87). What matters is **output
shaping**. `gh` lets the model ask for exactly the fields it needs
(`--json`, `--jq`), a vocabulary it already knows. The GitHub MCP server
returns full API objects that land in context and get cache-written at the
full input price. A skeptic on the MCP team would answer, correctly, that
this is a property of *this server's* responses, not of MCP. A server with
field selection or leaner defaults would close much of the gap. The claim
that survives is: "CLIs let the agent filter output before it hits context,
using flags it already knows; typical MCP servers return whole objects."
"MCP tool schemas bloat context" does not survive, now that tool search is
the default. **wires adds nothing material over a bare CLI**: +28 tokens of
first-turn context. Its median gap over `gh` (+3.5k input, +$0.004) comes
from the model's own choices: it re-checked `isLatest`/`isPrerelease` on t1
in 4 of 5 runs and made extra cross-check calls. The protocol doesn't
explain it.

## Arm 5: `wires` is the only thing the agent can run

*Card 19, run 2026-09-23 (UTC), right after card 13 merged. Results:
`bench/results/2026-09-23-arm5.jsonl`.*

Card 16's CLI arms let the agent pipe into `jq`/`head`/`grep`. A skeptic
would say the efficiency came from a general shell, and a general shell is
exactly what a safety reviewer can't reason about. Arm 5 takes that away.
`--allowedTools=Bash(wires call gh:*)` is the only rule: no pipe helpers.
The prompt says there is no shell. It says to filter with gh's own flags or
with `wires call gh --jq/--head/--max-bytes -- …`, which shape the remote
stdout inside `wires` without spawning anything. The same run repeated the
card-16 `wires` arm (with pipe helpers) as a same-day control. The binary and
the host config (`host.json`, card 13) changed between the two runs.

| arm | median total input | Σ cost, 25 runs | median turns | accuracy | permission refusals |
|---|---|---|---|---|---|
| MCP, default (card 16) | 21,088 | $1.87 | 3 | 25/25 | 0 |
| MCP, tool search off (card 16) | 30,630 | $1.40 | 2 | 25/25 | 0 |
| `wires call gh` + pipe helpers (card 16) | 10,539 | $0.48 | 3 | 25/25 | 7 |
| bare `gh` + pipe helpers (card 16) | 6,997 | $0.42 | 2 | 25/25 | 8 |
| `wires call gh` + pipe helpers (same-day control) | 10,332 | $0.44 | 3 | 25/25 | 4 |
| **arm 5: `wires call gh` only** | **10,713** | **$0.39** | **3** | **25/25** | **0** |

Card 16's refusal counts come from its notes (15 total, split 8 gh / 7 wires).
Its result rows predate the per-run `permission_denials` field that
`bench.py` now records.

| task (median input / median cost) | wires control | arm 5 |
|---|---|---|
| t1-release | 6,693 / $0.007 | 10,917 / $0.012 |
| t2-merged-prs | 13,204 / $0.022 | 7,327 / $0.017 |
| t3-bug-count | 10,332 / $0.018 | 6,981 / $0.009 |
| t4-commit-files | 6,790 / $0.008 | 7,042 / $0.009 |
| t5-most-commented | 11,173 / $0.029 | 11,305 / $0.021 |

Tool-result characters over 5 reps were 21,821 for the control and 9,785 for
arm 5. Arm 5 made 39 calls against the control's 46.

**Does the efficiency survive a wires-only sandbox? Yes, at n = 5.** Arm 5
matched the same-day control on median input (+4%, inside the IQR) and came
in lower on total cost (−11%) and turns (64 vs 71). It kept its ~2× input and
~4.8× cost advantage over the default MCP arm, with **zero** permission
refusals against the control's 4. The refusals the pipe helpers invited were
the `gh api graphql -f query='{…}'` cross-checks and a `for` loop. They
stopped happening: once the prompt says "no shell", the model doesn't reach
for shell idioms. Most filtering came from **gh's own flags**: 20 of 39 calls
used `gh … --jq`, and 4 used `wires call --jq` (t4, t5). So the claim that
survives is about the CLI's vocabulary, not about wires' flags. The in-process
`--jq` is a fallback for tools that have no filter of their own.

Three honest limits:
- **t1 cost more under arm 5** (10.9k vs 6.7k median input). The model asked
  for extra fields (`isLatest`, `isPrerelease`, `isDraft`) and re-checked. The
  control happened not to. This is model behavior, not a sandbox cost.
- **The sandbox isn't as tight as its name.** `Bash(wires call gh:*)` does stop
  every chained or substituted command the probe tried. But Claude Code still
  auto-allows read-only commands like `cat` inside the working directory
  (see `docs/agent-sandbox.md`). The benchmark ran in an empty directory, and
  the model never tried one. An airtight setup is structural: `wires mcp`
  with no Bash tool, or a container that holds only `wires`.
- **Same caveats as above:** one model, one tool, n = 5, stripped-down
  sessions, warm caches. The two same-day arms ran side by side and share a
  cache prefix.

## Caveats

- **Stripped-down sessions.** Each arm had only its own tools, and no CLAUDE.md,
  skills or memory. A real Claude Code session starts at ~20k+ tokens of
  context, so the *percentages* above overstate what a user would see. The
  *absolute* per-task deltas carry over.
- **One model** (Opus 5.5), **one MCP server** (GitHub's, whose release and
  issue payloads are unusually verbose), **default toolsets** only.
  `--toolsets=all` would widen the eager gap and barely move tool search.
- **n = 5** per cell. Every arm scored 25/25, so these tasks don't separate
  the arms on accuracy, only on cost.
- **The CLI arms were not held to read-only.** The `gh` token can write; the
  MCP server ran with `--read-only`. All tasks were read-only, and no writes
  happened.
- **The permission scoping hurt the CLI arms slightly.** Claude Code refused 15
  CLI commands (8 gh, 7 wires; mostly `gh api graphql -f query='{…}'`
  cross-checks on t3, plus a `for` loop and a `python3` pipe) under the
  prefix allowlist, and each refusal cost a turn. MCP had 0. The CLI
  numbers are therefore slightly pessimistic.
- **Costs depend on cache state.** The lanes ran in parallel and the 5-minute
  cache stayed warm across runs. `gh` and `wires` share a system/tool prefix,
  so they can read each other's cache. Token counts don't depend on caching;
  dollar figures do.
- Ground truth for volatile tasks (t2, t3) is a snapshot at the start and end
  of each rep. t3 allows ±max(3, 1%).

## Reproduce

```bash
cargo build --release -p wires                # run.sh also does this
./bench/tool-surface.sh                       # 26 tools, bytes per tool
./bench/run.sh --reps 1                       # smoke: 1 run per arm per task (~$1.50)
./bench/run.sh --reps 5                       # full; appends to bench/results/<utc-date>.jsonl
python3 bench/report.py bench/results/<utc-date>.jsonl
# arm 5 (card 19) and its same-day control, into their own file (~$0.85):
BENCH_OUT=bench/results/<utc-date>-arm5.jsonl ./bench/run.sh --reps 5 --arms wires-only,wires
python3 bench/report.py bench/results/<utc-date>-arm5.jsonl
python3 bench/permission-probe.py --out /tmp/probe.jsonl   # docs/agent-sandbox.md evidence (~$0.20)
```

Needs `claude` logged in, `gh` logged in, docker, and python3. The token is
read at runtime with `gh auth token`, passed to the container through the
environment, and never written anywhere. Raw transcripts go to a temp dir
outside the repo (`BENCH_RAW` overrides). wires state lives in
`/tmp/wb16`, which stays short because of macOS's 104-byte socket-path limit
(`BENCH_WIRES_DIR` overrides).
