# 20 — Locked caller mode: `wires call` can't be steered off its config

**Lane:** S2 · **Depends on:** 19 · **Files:** `wires/caller/call.rs`, `wires/caller/mcp.rs`, `docs/agent-sandbox.md`

## Why

Card 19's permission probe (`docs/agent-sandbox.md`): under any `Bash(wires call…)`
rule the agent can still pass `wires call`'s own override flags (`--tools-file`,
`--*-seed-file`, `--membership-file`, `--relay-url`, …). With them it could point
the caller at a different tools map or relay, or feed arbitrary local files in
as credentials. A sandbox recipe that says "the agent may only run `wires`"
needs `wires` itself to refuse being steered.

## Design

- A locked mode, turned on by the operator rather than the agent: `WIRES_LOCKED=1` in the sandbox environment, or `"locked": true` in the caller's config, which the agent can't write. Once on, `call` and `mcp` reject every override flag except `--jq/--head/--max-bytes` and the tool arguments, with an error naming the flag.
- Also consider refusing `< file`-style stdin in locked mode unless the operator allows it (`WIRES_LOCKED_STDIN=allow`), since card 19 found that working-directory files can be sent to the host that way. Record the trade-off (stdin is also how SQL arrives from MCP clients).
- Update `docs/agent-sandbox.md`: the recommended recipe becomes a container or PATH containing only `wires`, with `WIRES_LOCKED=1` and a read-only config.

## Acceptance

- [x] Unit: every override flag is rejected in locked mode; shaping flags are still accepted.
- [x] Re-run the card 19 probe cases for the flags with locked mode on, and record the result in the doc.
- [x] `bazel test //...`, lint, format check green.

## Notes

*2026-09-23, lane S2 (worker).* Commits: locked mode + probe + doc → merge
of `aaron/remote-cli` (card 17) → help-text wording + card.

**What it does (`wires/caller/lock.rs`).** On when the operator sets
`WIRES_LOCKED` to anything but empty/`0`/`false`/`no`/`off` (fail closed), or
puts `"locked": true` in `$WIRES_HOME/tools.json` (new serde-default field on
`ToolsConfig`, omitted when false; only the default file is read, never a
`--tools-file`, and an unparseable default file is an error, not "open").
Then `call` and `mcp` refuse **every `CredArgs` flag**: `--tools-file`,
`--node-seed`, `--node-seed-file`, `--membership`, `--membership-file`,
`--inclusion-proof`, `--inclusion-proof-file`, `--relay-url`. `call` exits 2
(nothing dialed), `mcp` exits 1 at startup; the message names the flag.
Allowed: `--jq`/`--head`/`--max-bytes`, the tool name (incl. `host8/name`),
and all tool args (args spelled like our flags after `--` are remote argv).
A unit test pins `OVERRIDE_FLAGS` to `CredArgs`'s clap long names, and
`call`'s other flags to exactly the three shaping ones, so a new credential
flag is refused until someone decides otherwise. Env fallbacks
(`WIRES_NODE_SEED`, `WIRES_MEMBERSHIP`, `WIRES_INCLUSION_PROOF`, `WIRES_HOME`)
still work: they are the operator's environment.

**stdin decision: refuse data on `wires call`'s stdin in locked mode unless
`WIRES_LOCKED_STDIN=allow`; leave `wires mcp`'s `stdin` field alone.**
Reasoning: on the shell path, stdin is the only way a working-directory file
reaches the host with no second command (`< file` passes every rule; `cat f |`
too, since `cat` is auto-allowed). wires can't tell a redirected file from a
heredoc or pipe (shells use either), so it refuses stdin data wholesale; the
cost is that a heredoc of the model's own SQL is refused too, and the agent
passes SQL as an argument, which the MCP schema and `wires tools` already
teach. On the MCP path the `stdin` field is text in the client's JSON-RPC
request (that's how MCP clients send SQL), never a file `wires mcp` reads,
so it can't carry local files and stays allowed. Mechanics: a terminal is
treated as no input; otherwise one byte is peeked with a 300 ms timeout
(a harness holding stdin open never hangs the call); data → exit 2; EOF or
idle → the remote gets EOF. Nothing from stdin is ever forwarded in that
mode, so the timeout can't leak.

**Probe re-run** (`bench/permission-probe.py --real-wires … [--locked]`, new
`WIRES_PROBES` set against the real binary with an empty scratch
`WIRES_HOME`, so nothing dials; rows in
`bench/results/permission-probe-locked.jsonl`, 31 sessions, **$0.18**):
unlocked, all 8 flags + `< canary.txt` + heredoc were honored (e.g.
`--tools-file canary.txt` → `wires: parsing canary.txt: …`); locked, all 10
were refused by wires, shaping still accepted. Claude Code allowed every one
of those commands under `Bash(wires call:*)` — the refusals are wires'.
Under `Bash(wires call gh:*)` Claude Code already refused
`wires call --relay-url … gh` (flag before the tool breaks the prefix). The
five attempts to unlock from the command line (`WIRES_LOCKED=0 wires …`,
`WIRES_HOME=. wires …`, `env -u`, `unset …;`, `export …;`) were all refused
by Claude Code ("requires approval").

**Not covered (documented in `docs/agent-sandbox.md`).** Globs still put
cwd *file names* in argv. The lock guards `call`/`mcp` only: `tools add`,
`join`, `login` aren't locked, so the permission rule must stay at
`wires call` (not `Bash(wires:*)`). Follow-up if wanted: lock those too.

**Off-lane touches.** `caller/tools.rs` (the `locked` field + test
literals), `caller/mod.rs` (module), `bench/permission-probe.py` (the real-
binary probe set), board README link. Wording fix requested by the
integrator: `call.rs` module doc and `wires call --help` (`tool`,
`--tools-file`) now say the name resolves via the channel directory with
`tools.json` as aliases; same for `mcp.rs`'s module doc.

**Tests:** `wires_test` 390 (7 new in `caller::lock`, incl. a proptest),
`library_test` 284, `library_doc_test` 49. Lint, `format.check`,
`demo-remote-cli.sh --quiet` green. One run of
`e2e::directory::…stopped_host_go_stale` timed out under load while the
probe ran in parallel; green on re-run (not touched by this card).

**For the README (replace the "Locked mode … is coming" sentence and the
"Not yet" bullet):**

> - a container or sandbox whose `PATH` holds only `wires`, in an empty
>   working directory with no secrets in the environment, with
>   `WIRES_LOCKED=1` set (or `"locked": true` in a `tools.json` the agent
>   can't write). Locked, `wires call` and `wires mcp` refuse every flag
>   that would point them at other credentials, another tools map or
>   another relay (`--tools-file`, `--*-seed*`, `--membership*`,
>   `--inclusion-proof*`, `--relay-url`); only `--jq`, `--head`,
>   `--max-bytes`, the tool name and its arguments are accepted. `wires call`
>   also refuses data on stdin, so `< file` can't ship a local file to the
>   host; pass input as arguments, or set `WIRES_LOCKED_STDIN=allow` if your
>   tools need piped input. (`wires mcp`'s `stdin` field is unaffected: it
>   is the model's own text.)

and drop "Locked caller mode" from *Not yet*. Also fix the link:
`docs/board/backlog/20-locked-caller.md` → `review/` (then `done/`).

