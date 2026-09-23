# 01 — `serve --expose`: many CLIs, per-call arguments

**Lane:** A · **Depends on:** 00 · **Files:** `wires/transport.rs` (serve_session, authorize, `call_on`, `dial_session`), `wires/main.rs` (serve/connect args only), `.scripts/serve-rg.sh` if touched

## Goal

One responder fronts several allowlisted CLIs. The caller picks one by name and
passes arguments per call. Today `serve` wraps exactly one fixed command and
stdin is the only input — useless for `psql -c "…"`-shaped tools.

## Design

- **CLI:** `wires serve --expose 'db_query=sqlite3 -safe -readonly /data/orders.db' --expose 'rg=rg --no-config' …`.
  The command after `=` is split on ASCII whitespace (no quoting, no shell). Also
  accept `--expose-file tools.json` (`{"db_query": ["sqlite3", "-safe", …]}`) for argv
  that needs spaces. Populates `ServeConfig.tools`. `--expose` and the trailing
  `-- <command>` are mutually exclusive.
- **Session (multi-tool mode):** after reading `Handshake`, read the next frame
  (same `HANDSHAKE_TIMEOUT`). It must be `Frame::Invoke`; otherwise `Denied("invoke required")`.
  Unknown tool → `Denied("unknown tool: <name>")`. Single-command mode receiving
  `Invoke` → `Denied("this responder runs a single command; drop --tool")`.
- **Exec:** `tools[name] ++ invocation.argv`, via `Command::new(argv[0]).args(..)`. Never a shell.
  Add `WIRES_TOOL=<name>` to the injected env alongside `WIRES_CALLER_NODE` etc.
- **Authorization per tool:** a grant's scope must be `tool:<name>` for the invoked
  tool, or `tool:*` for all tools on this responder. `--allow-any-member` still
  admits any member to any exposed tool. Inclusion-only (no grant) otherwise
  follows the existing `authorize` rules. Keep `check_accept` untouched; do the
  scope match in `authorize`.
- **Dial side:** implement `call_on` (stub from card 00): write `Handshake`, then
  `Invoke`, then proceed exactly as `dial_session`. Refactor `dial_session` to take
  `Option<Invocation>` rather than duplicating it. `wires connect --tool NAME -- args…`
  uses it (so the path is exercisable before lane C lands).
- **Audit hooks:** leave a clearly marked spot (a `// audit:` comment is enough) at
  (a) every `Denied` after the caller is known, (b) after authorization before spawn,
  (c) after child exit — lane B fills them. Compute and keep in scope what B will
  need: tool name, argv, roster version, spawn `Instant`, stdout/stderr byte counts,
  and a running `blake3::Hasher` over stdout (add `@crates//:blake3` to `//wires` deps).

## Acceptance

- [x] Unit tests (duplex pipes, no iroh): invoke → correct argv exec'd; args with spaces,
      quotes, `;`, `$(…)` arrive literally (use `printf '%s\n'` as the tool); missing /
      unknown / unexpected Invoke each deny with the reason above; scope `tool:a` can't
      call `b`; `tool:*` can.
- [x] Proptest: any valid `Argv` round-trips to the child's argv byte-for-byte.
- [x] Loopback e2e (`wires/e2e.rs` style): `serve --expose` + `connect --tool` over a real endpoint.
- [x] Existing single-command tests and `.scripts/demo-mcp.sh` still green.
- [x] `bazel test //...`, `aspect lint //...`, format check green.

## Notes

- sqlite3's CLI has dot-commands (`.shell`, `.system`) — the `-safe` flag (3.37+)
  disables them. The demo's `db_query` must use it; say so in `--help` text for `--expose`.
  (Done: the `--expose` help text says so.)
- **Scope in multi-tool mode.** `ServeConfig.scope` is not compared when `tools` is
  non-empty: `Some(_)` means "a grant is required", `None` means any member
  (`--allow-any-member`). `serve --expose` sets it to `transport::TOOL_SCOPE_ANY`
  (`"tool:*"`). An accepted grant must be scoped `tool_scope(tool)` (`tool:<name>`)
  or `tool:*`. `--scope` conflicts with `--expose`/`--expose-file`, and so does the
  trailing `-- <command>`. `check_accept` is unchanged.
- **Check order.** Handshake, then Invoke (missing, wrong frame, malformed or
  timeout all give `invoke required`), then the credential sources, then `authorize`
  (membership and per-tool scope), then the unknown-tool check. Only an authorized
  caller learns whether a tool exists. A revoked caller naming a bogus tool is told
  it's revoked (tested).
- **An Invoke sent to a single-command responder is caught on the stdin stream.**
  The ack has already gone out and the child has already been spawned, because an
  interactive child can't wait for a first frame. The stdin task signals, holds
  the child's stdin open so it can't exit on EOF and race the refusal, and the
  session kills the child and sends `Denied(DENY_SINGLE_COMMAND)`. The caller was
  already authorized for that command. Side effects: output the child writes
  before the kill can reach the caller. The audit log gets `Finished(exit -1)`
  for the `Started`, then a `Denied`.
- **Audit (merged with lane B).** `CallAudit::start` records the invoked tool and
  the caller's `Argv`, not the fixed argv. Single-command mode keeps `stdio_tool()`
  plus the command args. Every `denied(..)` after the Invoke passes `Some(tool)`.
  B's taps own byte counting and hashing, so I dropped my own pump hasher when
  merging, and no `blake3` code remains in `//wires`. The `@crates//:blake3` dep I
  added is still there; the integrator can drop it if nothing uses it.
- **Dial side.** `dial_session(.., invocation: Option<Invocation>, verify_target, ..)`.
  `connect_on` and `call_on` both call the private `dial_on`. `call_on` keeps the
  stub's signature exactly. `wires connect --tool NAME -- args…` binds and calls
  `call_on`. Trailing args without `--tool` are a clap error.
- `transport::exposed_tools(specs, file)` parses `--expose` and `--expose-file`. It
  lives in transport.rs so main.rs diffs stay small. Within the JSON file,
  duplicate keys are last-wins (serde). Duplicates across sources are an error.
- `WIRES_TOOL=<name>` is injected (and scrubbed from the inherited env) alongside
  `WIRES_CALLER_NODE`.
- Also committed a rustfmt-only fix to the `cli_admin` match arm, which the base
  left unformatted and which failed `format.check`. The merge later replaced it
  with lane C's arm.
- **Live e2e (cards 01+03), real binary over loopback and n0:** `serve --expose
  'shout=tr a-z A-Z' --expose 'lines=printf %s\n'`, with a `tool:lines` ticket.
  `connect --tool lines -- 'a b' '$(id)' 'x;y'` printed them literally, exit 0.
  `--tool shout` got `denied … does not cover tool shout`, exit 77.
  `wires tools add lines --ticket …` then `wires call lines -- one 'two three'` gave
  exit 0. `wires mcp` `tools/call` returned `"via\nmcp\nexit: 0"`, `isError: false`.
  `.scripts/demo-mcp.sh --quiet` passed.
- `aspect lint //...` isn't on the worktree PATH. I ran the main checkout's
  bazel_env `aspect` binary: exit 0. Its only remaining warning is the
  pre-existing dead `HeadSource::None`.
