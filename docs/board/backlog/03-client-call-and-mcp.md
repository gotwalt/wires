# 03 — `wires call` and `wires mcp`

**Lane:** C · **Depends on:** 00 (and 01's `call_on` for the live e2e) · **Files:** `wires/tools.rs`, new `wires/call.rs`, new `wires/mcp.rs`, `wires/main.rs` (new subcommands only)

## Goal

Two front doors to the same remote CLIs, both driven by `$WIRES_HOME/tools.json`:

- **`wires call <tool> [-- args…]`** — the CLI-native path. An agent runs it from
  its shell like any other command: stdin/stdout/stderr pass through, the remote
  exit code becomes ours, refusal exits `77` with the reason on stderr. This is
  the path the pitch says is cheaper than MCP.
- **`wires mcp`** — a stdio MCP server exposing each `tools.json` entry as an MCP
  tool, for workflows that only speak MCP (Claude Desktop, IDEs). The old
  `wires-mcp` gateway (`archive/poc-2026-05:crates/wires-mcp`) reduced to its
  essence: no HTTP, no OAuth, no JWTs — identity is this node's key.

## Design

- **`ToolsConfig::load`** (stub in card 00): missing file = empty; duplicate names = error.
  Add `wires tools add <name> (--ticket T | --node HEX [--relay-url U]) --description D [--remote-tool N]`,
  `wires tools list`, `wires tools rm <name>`.
- **Ticket targets** reuse `connect`'s ticket handling (grant, preflight checks);
  **node targets** are inclusion-only sessions (`ticketless = true`). The remote tool
  name is `remote_tool.unwrap_or(name)`; for ticket targets whose scope is
  `tool:<x>`, default `remote_tool` to `x`.
- Put the dialing behind a small trait (`trait Caller { async fn call(&self, &RemoteTool, Argv, Vec<u8> /*stdin*/) -> Result<CallOutcome> }`,
  `CallOutcome { exit, stdout, stderr }` or `Denied(reason)`) so `mcp.rs` is unit-tested
  against a fake while lane A finishes `call_on`.
- **MCP server:** newline-delimited JSON-RPC 2.0 on stdio; **stdout is protocol-only**
  (logs → stderr). Implement `initialize`, `notifications/initialized`, `tools/list`,
  `tools/call`, `ping`. Support both the classic handshake (`2025-06-18`) and the
  stateless 2026-07-28 form (per-request `_meta` key
  `io.modelcontextprotocol/protocolVersion`) — `.scripts/fake-mcp-server.py` and the
  README "MCP over wires" section show what was verified. `tools/list` ordering is
  deterministic (config order).
  - Tool input schema: `{ "args": {"type":"array","items":{"type":"string"}}, "stdin": {"type":"string"} }`, both optional.
  - Result: one text content block: stdout (cap 64 KiB, with a truncation note), then
    `stderr:` block if non-empty, then `exit: N`. `isError: true` when exit ≠ 0 or denied
    (denied text starts with `denied by responder:`).
  - Description = `tools.json` description + ` (runs remotely via wires; every call is logged to the <audit_topic> channel)` when `audit_topic` is set.
- **Stretch (only if time):** a `recent_calls` MCP tool reading the local tail's store.

## Acceptance

- [ ] Unit: `ToolsConfig` load/validate/round-trip; MCP golden transcripts against a fake
      `Caller` (initialize → list → call ok → call nonzero exit → call denied → unknown tool).
- [ ] Proptest: arbitrary `args` arrays survive MCP → `Argv` → fake caller unchanged.
- [ ] e2e once card 01 is merged: `wires mcp` subprocess, driven over pipes, calls a
      loopback `serve --expose` responder and returns the remote output.
- [ ] Manual: a headless `claude -p` session with `wires mcp` in `--mcp-config` lists and
      calls the tool (record the command used in Notes).
- [ ] `bazel test //...`, `aspect lint //...`, format check green.

## Notes
