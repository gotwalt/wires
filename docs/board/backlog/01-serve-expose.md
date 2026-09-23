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

- [ ] Unit tests (duplex pipes, no iroh): invoke → correct argv exec'd; args with spaces,
      quotes, `;`, `$(…)` arrive literally (use `printf '%s\n'` as the tool); missing /
      unknown / unexpected Invoke each deny with the reason above; scope `tool:a` can't
      call `b`; `tool:*` can.
- [ ] Proptest: any valid `Argv` round-trips to the child's argv byte-for-byte.
- [ ] Loopback e2e (`wires/e2e.rs` style): `serve --expose` + `connect --tool` over a real endpoint.
- [ ] Existing single-command tests and `.scripts/demo-mcp.sh` still green.
- [ ] `bazel test //...`, `aspect lint //...`, format check green.

## Notes

- sqlite3's CLI has dot-commands (`.shell`, `.system`) — the `-safe` flag (3.37+)
  disables them. The demo's `db_query` must use it; say so in `--help` text for `--expose`.
