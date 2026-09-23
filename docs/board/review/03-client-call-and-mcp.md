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

- [x] Unit: `ToolsConfig` load/validate/round-trip; MCP golden transcripts against a fake
      `Caller` (initialize → list → call ok → call nonzero exit → call denied → unknown tool).
- [x] Proptest: arbitrary `args` arrays survive MCP → `Argv` → fake caller unchanged.
- [ ] e2e once card 01 (**blocked on card 01 merge** — integrator to run) is merged: `wires mcp` subprocess, driven over pipes, calls a
      loopback `serve --expose` responder and returns the remote output.
- [ ] Manual (**needs the live path; not run**): a headless `claude -p` session with `wires mcp` in `--mcp-config` lists and
      calls the tool (record the command used in Notes).
- [x] `bazel test //...`, `aspect lint //...`, format check green. (`aspect` isn't on this worktree's PATH; ran the same aspects via `bazel build --config=lint //wires/...` — clippy clean for call/mcp/tools, the only diagnostics are the pre-existing lane A/B dead-code ones in `transport.rs`.)

## Notes

- **tools.rs was missing from 2f57378** (case-insensitive FS); I restored it with my implementation and resolved the add/add with 47454ea in favor of mine.
- **`ToolTarget::Node` gained `addrs: Vec<SocketAddr>`** (serde default, omitted when empty; `tools add --node … --addr A`). Without it a node target could only be found through n0 discovery, so a loopback e2e couldn't use `--node`. Old files still parse.
- **Remote tool name** is worked out at dial time (`Dial::resolve`), not stored at `add`: explicit `remote_tool` → `tool:<x>` ticket scope → local name. Hand-edited files get the same default.
- **`Caller`** returns `impl Future + Send` (not `async fn` in the trait, which would trip the `async_fn_in_trait` lint). `Err` means a local/transport failure; a refusal is `Ok(CallOutcome::Denied)`. `WiresCaller` binds a fresh endpoint for each call, then `transport::call_on` buffers stdout/stderr into `Vec`s and a `Denied` error becomes a `Denied` outcome.
- **`wires call`** streams real stdio through the same `call::dial` (it doesn't use the buffered `Caller`) and reuses `main.rs`'s `preflight` and `exit_with`, so a refusal exits 77. `wires call` and `wires mcp` take the same credential flags as `connect`, plus `--tools-file` and a `--relay-url` override. The clap Args live in each module, so `main.rs` only gained enum variants and dispatch.
- **MCP details**: `initialize` agrees to 2026-07-28, 2025-11-25, 2025-06-18, 2025-03-26 or 2024-11-05 and offers 2026-07-28 for anything else. It does not require `initialize` (stateless). When the request's `_meta` version or the agreed version is ≥ 2026-07-28, results carry `resultType: "complete"` and `_meta` {protocolVersion, serverInfo}. Older revisions get plain results. An unknown tool or bad arguments returns JSON-RPC -32602 and never reaches the caller. A transport failure returns `isError: true` with text `wires: call failed: …`. Stdout and stderr are each capped at 64 KiB on a char boundary, with a `[wires: stdout truncated to N of M bytes]` note. The input schema sets `additionalProperties: false`.
- **Requests are handled one at a time.** A long call blocks later requests, including `ping`, until it returns. That's fine for Claude Code. Make it concurrent if a client times out pings.
- **For the integrator's live e2e**: `wires tools add t --node <responder> --addr 127.0.0.1:<port> --description …` (or `--ticket`), then pipe `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"args":["x"]}}}` into `WIRES_HOME=… wires mcp`. Manual check: `claude -p --mcp-config '{"mcpServers":{"wires":{"command":"/abs/path/wires","args":["mcp"]}}}' "list your tools, then call t"`.
- Stretch `recent_calls` not done.

