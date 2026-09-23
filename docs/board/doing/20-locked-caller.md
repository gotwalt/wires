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

- [ ] Unit: every override flag is rejected in locked mode; shaping flags are still accepted.
- [ ] Re-run the card 19 probe cases for the flags with locked mode on, and record the result in the doc.
- [ ] `bazel test //...`, lint, format check green.

## Notes
