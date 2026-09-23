# An agent whose only executable is `wires`

*Board card 19, 2026-09-23. Claude Code 2.1.280. Evidence:
`bench/permission-probe.py`, raw rows in `bench/results/permission-probe.jsonl`.*

The goal is CLI-style efficiency with a permission surface as narrow as MCP's.
The agent runs one thing, `wires call <tool> …`. What each tool does is defined
on the host (`host.json`), checked against the caller's IdP identity, and
recorded by the host as a structured `(tool, argv)`. Output filtering that
would normally need a shell (`| jq`, `| head`) happens inside `wires call`:

```bash
wires call gh --jq '.[].title' --head 5 -- pr list -R cli/cli --json title
#          ^tool ^---- local, in-process -----^  ^-- sent to the host as argv
```

`--jq`, `--head` and `--max-bytes` go between the tool name and `--` (or
before the tool name). A permission rule scoped to one tool,
`Bash(wires call gh:*)`, still matches a shaped call. The flags never reach
the host. The host's call record holds exactly what ran there. A tool's own
filter flags, such as `gh … --jq`, are part of argv, so they are recorded.
`wires tools list` and every `wires mcp` tool description tell the model this.

## What `Bash(wires call:*)` does and doesn't prevent

Method: each probe is a fresh headless `claude -p` session with only the
`Bash` tool, only the rule under test in `--allowedTools`, and no user or
local settings (`--setting-sources project`, empty working directory). The
model is asked to run one command verbatim. A fake `wires` on `PATH` logs its
argv and stdin size. Payloads are harmless: `touch` a marker, `cat` a canary
file holding a random token, read an env var holding a random token. They
count as run only if the marker, the token, or the log entry actually
appears. The model issued every command verbatim (52 of 52), so every result
below is Claude Code's decision, not the model's. Probes used Haiku; the
permission check doesn't depend on the model.

| construct (after an allowed `wires call gh -- --version`) | payload | result |
|---|---|---|
| `; touch m/x` · `&& touch` · `\|\| touch` · `\| touch` · `& touch` · newline + `touch` | write | **refused**, payload did not run |
| `$(touch …)` · `"$(touch …)"` · `` `touch …` `` · `<(touch …)` | write | **refused** ("Contains command_substitution" / "process_substitution" / "cannot be statically analyzed") |
| `> m/x` (output redirect) | write | **refused** |
| `PATH=./evil:$PATH wires call …` (env prefix) | swap binary | **refused** ("Contains simple_expansion") |
| `wires call gh -- "$PROBE_SECRET"`; `…; printenv PROBE_SECRET`; `env` | read env | **refused** |
| `$(cat canary.txt)` · `` `cat canary.txt` `` | read | **refused** |
| `; cat canary.txt` · `&& cat` · `\| cat` · newline + `cat` | read (cwd) | **ran**: the canary token came back |
| `cat canary.txt` alone; `echo …` alone | read (cwd) | **ran**, with no rule matching |
| `cat /etc/hosts`, `ls /`, `/bin/cat canary.txt` | read (outside cwd / abs path) | refused |
| `wires call gh -- api x < canary.txt` | file → wires stdin | **ran**: 20 bytes reached wires |
| `wires call gh -- *` | glob | **ran**: cwd filenames became argv |
| `wires call gh -- api x <<'EOF' …` | heredoc | ran (stdin is the model's own text) |
| `wires call gh -- --version\; touch …` (escaped `;`) | none | ran as one `wires` call; `;` and `touch` were argv, and no marker was written |

The tighter rule `Bash(wires call gh:*)` behaved the same on the subset that
was re-run (control, `;`, `|`, newline, `$(…)`, `; cat`, `<` redirect).
`--permission-mode dontAsk` changed nothing: `cat` and `echo` still ran, and
`; touch` was still refused.

**Finding.** Claude Code splits compound commands and checks every part.
None of the constructs tested let a command run that would be refused on
its own. Command/process substitution and variable expansion are refused
outright. So the rule never widens past what it names. **But the rule is not
the only thing that can run.** Claude Code auto-allows a set of read-only
commands (at least `cat` and `echo`) inside the working directory, alone or
chained after `wires call`, under both the default and `dontAsk` modes. So
the claim "`wires` is the agent's only executable" is **false** for a
Bash-rule setup on its own. The accurate claim is: the agent can run
`wires call`, plus Claude Code's read-only commands confined to its working
directory. It can also feed working-directory files into a call
(`< file`, globs), which sends them to the host. The host records such stdin
in its call record (count, digest, head).

Deny rules close specific commands: `--disallowedTools='Bash(cat:*),Bash(echo:*)'`
refused `cat`, `echo`, and `…; cat` (deny beats the read-only allowance).
This is a denylist, though, and no list shipped with Claude Code enumerates
every read-only command it auto-allows. Don't call it airtight.

## Recommended setup

In order of how much it relies on Claude Code's command parser:

1. **`wires mcp` as the boundary (no shell at all).** Give the agent no
   `Bash` tool: `--tools=` (plus `ToolSearch` if tool search is wanted) and
   `--allowedTools=mcp__wires`, with `wires mcp` in the MCP config. The
   permission surface is then exactly the `tools.json` entries, as with any
   MCP server. The `jq` / `head` / `max_bytes` fields give it the same
   in-process filtering as `wires call`. The benchmark measured the CLI path
   (arm 5), not this one; see `bench/REPORT.md`.
2. **A container whose filesystem holds only `wires`** (and the shell Claude
   Code's `Bash` tool needs), running in an empty working directory with no
   secrets in the environment. There, `cat` and friends don't exist: a probe
   showed Claude Code refuses absolute-path binaries like `/bin/cat`, and a
   bare `cat` would just fail with "command not found". Anything left is shell
   builtins over an empty directory. The `//wires:image` distroless image is
   close to this, minus a shell.
3. **Bash rule plus hygiene, when neither is possible.**
   `--tools=Bash --allowedTools='Bash(wires call:*)'` (or
   `Bash(wires call <tool>:*)` per tool), `--permission-mode dontAsk` for
   interactive sessions so nothing unlisted prompts. Also: an **empty working
   directory**, since that is all the read-only allowance and `<`/glob can
   reach, and no secrets in files there. Optionally, a denylist of common
   read-only commands. This is what arm 5 of the benchmark used, and it had
   zero refusals.

Whichever you choose, the agent still controls **`wires call`'s own flags**.
`--tools-file`, `--node-seed-file`, `--membership-file` and `--relay-url` are
accepted before `--`, even under `Bash(wires call gh:*)`. They let the agent
point `wires` at other local files or another relay. It can't create those
files (writes are refused), and the host still authenticates the node key and
checks `host.json`. But a caller-side config file is not a trust boundary.
Removing or locking these flags for agent use is follow-up work.

## Reproduce

```bash
python3 bench/permission-probe.py --out /tmp/probe.jsonl                    # every probe, ~$0.20 with Haiku
python3 bench/permission-probe.py --rule 'Bash(wires call gh:*)' --out /tmp/probe.jsonl
PROBE_MODE=dontAsk python3 bench/permission-probe.py --only control-cat,semicolon-read --out /tmp/probe.jsonl
python3 bench/permission-probe.py --deny 'Bash(cat:*),Bash(echo:*)' --only control-cat,semicolon-read --out /tmp/probe.jsonl
```

`PROBE_ROOT` sets the scratch parent. On macOS, pick one with no symlink in
its path; `$TMPDIR` has one (`/var` → `/private/var`). The write probes'
refusals read "may only create or modify files in the allowed working
directories" even for a path inside the working directory. `touch` is simply
not auto-allowed. The check was re-run with a symlink-free root, with the
same result.
