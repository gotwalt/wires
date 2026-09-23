# 00 — Shared types

**Lane:** 0 · **Depends on:** — · **Owner:** integrator

## What landed

- `library/invoke.rs` — `ToolName` (validated `[a-z][a-z0-9_-]{0,63}`), `Argv` (≤256 args, ≤64 KiB, no NUL), `Invocation { tool, argv }`.
- `library/session.rs` — `Frame::Invoke(Invocation)`, tag `7`. Dialer sends it immediately after `Handshake` without waiting for the ack; multi-tool responder reads both, then acks or denies.
- `library/audit.rs` — `CallId`, `OutputDigest` (BLAKE3 of stdout), `AuditRecord::{Started, Finished, Denied}`.
- `library/idp.rs` — `IdToken`, `OidcNonce::for_node` (**stub**, lane F), `Principal`, `IdentityClaim { node, id_token }`.
- `library/record.rs` — `ChannelRecord::{Audit, Identity}`; one-line JSON `{"wires":"record/v1","record":{…}}`; `parse` returns `None` for plain chat text.
- `wires/transport.rs` — `ServeConfig.tools: BTreeMap<ToolName, Vec<String>>` (empty = single-command mode), `ServeConfig.audit: Option<AuditSink>`; `AuditSink` (non-blocking mpsc); `call_on(…, invocation, …)` (**stub**, lane A).
- `wires/tools.rs` — `ToolsConfig`/`RemoteTool`/`ToolTarget` for `$WIRES_HOME/tools.json`; `load` (**stub**, lane C).

## Notes

- Invoke is a separate frame rather than a `Handshake` field so the single-command path and its ~15 test fixtures are untouched.
- Records are plain topic messages: they inherit envelope signing, encryption, and per-publisher hash chains, so they carry no signature of their own.
- Expect dead-code warnings until lanes A/B/C wire these up.
