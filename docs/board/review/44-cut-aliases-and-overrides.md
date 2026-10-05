# 44 — Cut `tools.json` aliases and the caller's credential-override flags

**Depends on:** [41](../done/41-idp-membership.md) · **Status:** review (worker, 2026-10-05) · **Files:** `wires/caller/{tools,call,mcp,lock,inbox}.rs`, `wires/gateway/`, `wires/lib.rs`, `wires/help.rs`, `wires/snapshots/`, `docs/agent-sandbox.md`, `bench/permission-probe.py`

## Why

`wires tools` and `tools.json` pin a name to one host by node id, address
and relay: the model from before services had names (card 27). The command
is hidden, but its type (`RemoteTool`, `ToolTarget`) is still how `call`,
`mcp` and the gateway represent a service, and an alias must already be a
service in the caller's view that lists that host, so all it adds is "force
this host".

`call`, `mcp` and `inbox` also take `--node-seed[-file]`, `--relay-url` and
`--tools-file` (15 flag instances; `--membership[-file]` goes with card 41).
No script or demo uses them. Locked mode (`caller/lock.rs`, 465 lines)
exists largely to refuse them.

## Proposal

- Delete `wires tools`, `tools.json`, `--tools-file` and the alias dial path;
  name the remaining type for what it is.
- Delete the credential-override flags on the caller's commands;
  `WIRES_HOME` is the one way to point `wires` at a keystore. Keep
  `--node-seed-file` on `serve` and the gateway, where containers mount a
  key.
- Locked mode shrinks to the stdin rule.
- If `--policy-ttl` becomes a policy setting, `--help-all` and its snapshots
  can go too.

About 1.5–2k lines. **Open:** whether anyone relies on `--relay-url` per
command for a self-hosted relay ([deployment.md](../../deployment.md)); it
may belong in the keystore or the network string instead.

## Since this was drafted (cards 41, 43 and 47)

- `--membership[-file]` and `WIRES_MEMBERSHIP` went with badges; locked mode now refuses four
  flags and stdin.
- `tools.json` is written 0600 like every keystore file (it was created at the umask, which let a
  group member switch off `"locked"`).
- `wires mcp` warns `shadowed by the service of that name in your view` when an alias loses to a
  service.
- The `RemoteTool` / `ToolTarget` / `remote_tool` rename was left for this card.
- `docs/agent-sandbox.md` still tabulates an old permission probe, minus the removed rows; redo or
  drop the table when the flags go.

## Notes

**Worker, 2026-10-05 (branch `worker/44-cut-aliases`).** Done as proposed: −1,816 / +383 lines (before these notes)
overall (Rust: −1,555 / +301), `caller/tools.rs` and the four `tools*` snapshots deleted.

What changed:

- **protocol.md first**: the §5 alias paragraph and the §8 `tools.json` row are gone; §5's exit 2
  says "locked mode refuses its stdin"; §7 (embedded host) no longer mentions `$WIRES_NODE_SEED`;
  §8's closing paragraph now says `$WIRES_HOME` is the one way to point `wires` at another
  keystore, the caller's commands take no key/relay/config flag, `serve` alone takes its key ahead
  of the keystore (`--node-seed-file`, `--node-seed`), `serve`/`directory serve`/`gateway` take
  `--relay-url`, and locked mode refuses only a `wires call` stdin that holds data.
- **Aliases**: `wires tools`, `tools.json`, `ToolsConfig`, `--tools-file`, the alias dial path
  (`Dial`, `dial`, `check_alias`, `lookup`, `Route`) are deleted. `RemoteTool`/`ToolTarget`/
  `remote_tool` are gone rather than renamed: what is left is **`caller::mcp::ViewService`**
  (`name`, `description`: a service in the caller's view, as an MCP tool offers it), built by
  **`services_in(&View)`** (was `with_services(ToolsConfig, &View)`); `McpServer::set_tools` →
  `set_services`. The host is not part of the type any more: it is picked at call time
  (`pick::candidates`), so the `Caller` trait now takes `service: &ServiceName` instead of a tool.
  The MCP server's "aliases first, then services; past the threshold aliases + search" listing
  collapses to "services; past the threshold search + call".
- **Credential overrides**: `CredArgs` (`--node-seed`, `--node-seed-file`, `--relay-url`) is
  deleted from `call`, `mcp` and `inbox`, and **`login`'s `--node-seed[-file]` too** (a caller
  command; the token it stores in the keystore must be bound to the keystore's key, so an
  override there could only produce a token `call` can't use). `Credentials::resolve()` reads the
  keystore's key (`node_identity_in`); `Credentials::through_relay(url)` is the gateway's way in.
  `mcp`'s args struct is empty; `wires mcp`, `call` and `inbox` no longer show `--help-all`.
- **`$WIRES_NODE_SEED` is gone everywhere**, not only on the caller's commands. Kept, it would
  have been the one override left on `call`, and locked mode would have had to keep refusing it;
  it also leaked into every command through `node_identity_in` (services, join, directory serve,
  policy fetch, remove). `serve` keeps `--node-seed-file` (containers mount a key) and the inline
  `--node-seed` (out of this card's scope; deployment.md already advises against it). The gateway
  had no seed flag of its own (it used `$WIRES_NODE_SEED` or the keystore; `deploy/gateway` mounts
  `/data` as `WIRES_HOME`), so it now uses its keystore; adding `--node-seed-file` to it was not
  needed for the Compose deployment.
- **Locked mode** (`caller/lock.rs`, 459 → 143 lines) is the stdin rule and nothing else:
  `lock::detect()` (`WIRES_LOCKED`, fail closed), `check_process_stdin`, `StdinRefused`,
  `EXIT_LOCKED`. Gone: `Lock`, `StdinPolicy`, `Refused::{Flag, Env}`, `OVERRIDE_FLAGS`,
  `OVERRIDE_ENV`, `"locked"` in `tools.json`, and **`WIRES_LOCKED_STDIN=allow`** (with nothing
  else to lock, `WIRES_LOCKED=1` + `allow` meant "not locked"; an operator who wants piped input
  leaves the lock off). `wires mcp` and `wires inbox` no longer consult the lock (nothing to
  refuse). No survivors to justify.
- Also gone with them: `shape::CALL_HINT` (only `wires tools list` printed it), the inbox
  `Fetcher.relay` field, the `errors.txt` lines for the flag/env refusals, and bench/help/eval.py's
  "not allowed in locked mode" guess marker. The env-scrub tests that used `WIRES_NODE_SEED` as a
  sample host variable now use `WIRES_LOCKED`.
- **`docs/agent-sandbox.md` and `bench/permission-probe.py`** (in this card's files): redone, not
  dropped. The locked-mode section describes the stdin-only lock; the probe table keeps only the
  rows that still apply (shaping, `<` redirect, heredoc, the five unlock attempts), says the unlock
  rows were measured with a `--tools-file` payload (Claude Code refused them on the environment
  change, before `wires` ran), and that the probe script now uses `< canary.txt` as the payload and
  has not been re-run (it needs a live `claude`, ~$0.20). The raw `bench/results/*.jsonl` rows are
  historical and untouched.

**Decision — `--relay-url` for a self-hosted relay.** Dropped from the caller's commands, kept on
`serve`, `directory serve` and `gateway`. No script, demo, test or deploy file passed it to a
caller; deployment.md was the only place that told callers to. Where n0's discovery is reachable,
a caller still reaches a host on a self-hosted relay: the host publishes its home relay with its
address, and iroh dials whatever relay the address names. What breaks is the fully air-gapped case
(no n0 DNS) with callers behind NAT, who now have no way to name the relay. The right home for it
is **the network string**: one relay per network ("keep it one logical endpoint" is already
deployment.md's rule), set by the admin, stored in `network.json` by `join`/`login`, used by every
bind. That is a §2 format change plus `bind_with` reading it, so it is a card of its own, not
built here. (A keystore file would also work but makes every node configure it by hand.)

**`--policy-ttl` → policy setting**: does not fall out of this card. It is on `init` and every
policy edit; moving it into `policy settings` is a §3 change in the admin lane. Even then
`--help-all` stays: `serve`, `directory serve`, `gateway`, `login` (`--issuer`, `--client-id`,
`--client-secret`) and the admin edits still hide flags.

**Statements now false in narrative docs (for the sweep):**

- `docs/usage.md:402` — the embedded host "reads neither `$WIRES_HOME` nor `$WIRES_NODE_SEED`"
  (the variable no longer exists).
- `docs/usage.md:553–569` — `wires call`'s override flags (`--tools-file`, `--node-seed[-file]`,
  `--relay-url`), `"locked": true` in `tools.json`, locked mode refusing those flags and
  `WIRES_NODE_SEED`, and `WIRES_LOCKED_STDIN=allow`.
- `docs/usage.md:706–707` — `--help-all` lists "the credential overrides (`--node-seed[-file]`,
  `--tools-file`, …)": only `serve` has seed flags now; `call`/`mcp`/`inbox` have no `--help-all`.
- `docs/usage.md:731` — `wires call`'s row: "or a `tools.json` alias, which a service in your view
  of the same name beats", and "a flag locked mode refuses" (now: stdin in locked mode).
- `docs/usage.md:735` — the whole `wires tools add|list|rm` row.
- `docs/usage.md:775–776` and `docs/deployment.md:128–129` — "Secrets resolve flag → environment
  variable → `--…-file` → keystore": no environment variable carries the node key any more
  (`$WIRES_OIDC_*` still override login settings).
- `docs/usage.md:798–800` — "pass `--relay-url <its url>`" reads as every command; callers no
  longer take it.
- `docs/deployment.md:214–218` — "pass `--relay-url` to `serve`, `directory serve`, `call`, `mcp`,
  `gateway` and `inbox`": now only `serve`, `directory serve` and `gateway` (and see the relay
  decision above for the air-gapped gap).
- `docs/demo.md:131` — "only `wires` with `WIRES_LOCKED=1`": still true, but locked mode now only
  refuses stdin data; worth a word if the demo narrates what it locks.
- `CLAUDE.md:175` (Architecture, `caller/`) — "locked mode (`WIRES_LOCKED`) and `tools.json`
  aliases": the aliases are gone; locked mode is the stdin rule.
- `docs/board/README.md:85` links this card under `backlog/` (the integrator's file).

Outside my lane, touched minimally: `wires/admin/keystore.rs` (`$WIRES_NODE_SEED` out of
`node_identity`/`node_identity_in`), `wires/caller/login.rs` (seed flags), `wires/host/serve.rs`
and `wires/host/embed.rs` (doc comments), `wires/e2e/{gateway,views,service_child}.rs` and
`wires/host/transport.rs` (tests), `bench/help/eval.py` (the guess marker). For card 46: in
`call.rs` I kept `relay_override`, `call_entry` and the `hints.targets(...)` line untouched; the
merge-relevant changes are the `Caller` trait signature (`&ServiceName`), `Credentials::resolve()`
taking no args, and `call_cmd` losing its alias route. `pick.rs` is untouched.

Checks: `cargo test --workspace` green (one run hit `host::push::tests::a_banned_persons_fetch_
drops_the_queue` asserting exactly one "push denied" log line; it passed alone 5/5 and on the full
re-run — a log-capture flake under parallel load, in a file this card doesn't touch); clippy
`-D warnings` and `cargo fmt --check` clean; no shell script touched (shellcheck n/a);
`.scripts/demo-remote-cli.sh --quiet` and `.scripts/demo-push.sh --quiet` green.
