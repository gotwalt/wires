# 02 — `serve --audit-topic`: every call on the channel

**Lane:** B · **Depends on:** 00 · **Files:** new `wires/audit.rs`, new `wires/render.rs`, `wires/topics.rs` (router extension only), `wires/transport.rs` (emission calls only), `wires/main.rs` (serve + tail args/output)

## Goal

The responder publishes a signed record of every call — started, finished,
denied — to an E2EE topic. Any member running `wires tail <topic>` anywhere
sees them live, rendered for humans. This is the observability leg of the pitch.

## Design

- **One endpoint, one allocator.** A responder with `--audit-topic ops` stands up
  the `TopicNode` for `ops` itself and registers the session ALPN
  (`transport::ALPN`) on the **same** iroh `Router`, instead of binding its own
  endpoint. Add the smallest extension to `TopicNode` that allows this (e.g. a
  constructor that accepts extra `(alpn, handler)` pairs). One node identity must
  never run two endpoints (see `ipc.rs` docs), and the process that owns the
  topic's redb store is the single sequence allocator — so audit records are
  sealed/appended/broadcast by the same loop that `wires tail` uses for
  `PublishRequest`s. Reuse that path; don't write a second allocator.
- **Prereqs fail closed at startup:** `--audit-topic` requires that the responder
  holds an inclusion proof, roster head, and fabric key (it's a member of the
  channel). Missing → refuse to start with a message naming the `wires import` flag.
- **Emission:** create `AuditSink::channel`, put the sink in `ServeConfig.audit`,
  drain the receiver into `ChannelRecord::Audit(..).to_text()` → publish. Fill the
  three `// audit:` hooks lane A leaves in `serve_session` (if A hasn't merged yet,
  add minimal hooks in the current single-command path using `tool = "stdio"` and
  the command's argv — the integrator reconciles). `Denied` records carry the same
  reason string the caller got. Runtime publish failures are logged, never fail a call.
- **Rendering (`wires/render.rs`):** `wires tail` checks `ChannelRecord::parse` on
  every message. Plain text renders as today. Records render as one line each:
  - `▶ 3fa2 alice@corp (a1b2…) db_query "select count(*) from orders"`
  - `■ 3fa2 exit 0 · 41 ms · 3.1 KiB out · blake3 9c1e…`
  - `✗ a1b2… db_query denied: membership rejected: revoked`
  - `🪪 a1b2… claims identity (unverified)` — lane F replaces "unverified" with the
    verified principal via a function in `render.rs` it will own after you.
  Caller shown as principal email when a `principal` is present, else short node id.
  `--json` emits the parsed record object instead of the text.
- Document the observer setup in the card Notes: observer = any roster member with
  the fabric key; it holds no grant for the tool and no credential of the caller.

## Acceptance

- [ ] Unit: sink → publish loop turns each `AuditRecord` into exactly one message; render
      golden tests for all record kinds and for plain text.
- [ ] e2e (loopback, `wires/e2e.rs`): node R serves `cat` with `--audit-topic ops`; node O
      tails `ops`; node C calls → O observes `Started` (caller == C's id) then `Finished`
      (exit 0, byte count, digest == blake3 of output). C revoked via roster head → O
      observes `Denied` with the revocation reason.
- [ ] Responder refuses to start without fabric key/proof when `--audit-topic` is set.
- [ ] `bazel test //...`, `aspect lint //...`, format check green.

## Notes
