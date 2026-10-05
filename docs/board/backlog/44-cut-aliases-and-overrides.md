# 44 — Cut `tools.json` aliases and the caller's credential-override flags

**Depends on:** [41](41-idp-membership.md) · **Status:** backlog, not scheduled (drafted from the 2026-10-04 review; the human hasn't decided) · **Files:** `wires/caller/{tools,call,mcp,lock,inbox}.rs`, `wires/gateway/`, `wires/lib.rs`, `wires/help.rs`, `wires/snapshots/`, `docs/agent-sandbox.md`, `bench/permission-probe.py`

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

## Notes
