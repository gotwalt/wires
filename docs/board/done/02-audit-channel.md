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

- [x] Unit: sink → publish loop turns each `AuditRecord` into exactly one message; render
      golden tests for all record kinds and for plain text.
- [x] e2e (loopback, `wires/e2e.rs`): node R serves `cat` with `--audit-topic ops`; node O
      tails `ops`; node C calls → O observes `Started` (caller == C's id) then `Finished`
      (exit 0, byte count, digest == blake3 of output). C revoked via roster head → O
      observes `Denied` with the revocation reason.
- [x] Responder refuses to start without fabric key/proof when `--audit-topic` is set.
- [x] `bazel test //...`, `aspect lint //...`, format check green.

## Notes

**Observer setup.** An observer is any roster member holding the current fabric
key: `wires import --membership … --inclusion-proof-file <id>.proof
--roster-head … --fabric-key-file <id>.key`, then `wires tail ops --peer <ticket>`
(the responder prints its topic ticket on stderr at startup: `share to bootstrap:
…`). It holds no grant for any exposed tool and no credential of the caller; it
needs nothing from either end of the call. After a `roster commit` it must
re-import the new key to keep reading (records are sealed under the latest key).

**Responder setup.** `wires serve --trust-root <root> … --audit-topic ops
[--audit-peer <ticket>…] -- <cmd>`. The responder must itself be a provisioned
channel member; otherwise it refuses to start with the same `wires import …`
remedy `wires tail` gives. `--trust-root` must equal the membership's fabric.

**Decisions.**
- *One endpoint:* `TopicNodeConfig.protocols: Vec<(&'static [u8], Box<dyn
  DynProtocolHandler>)>` (a config field rather than a new constructor — smallest
  diff; colliding ALPNs refused). `transport::SessionProtocol(Arc<ServeConfig>)`
  is the router handler; `handle_connection` was split so `serve_connection(conn)`
  is shared by both paths.
- *One allocator:* `audit::forward` turns each record into one `ipc::PublishRequest`
  on the **same** mpsc the control socket feeds; `run_tail` gained one param
  (`hosted: Option<audit::Hosted>`), otherwise its loop is untouched. Records are
  sealed by `publish_from_tail` like any `wires publish`.
- *Emission in `serve_session`* (search `// audit:`): `crate::audit::denied(…)`
  before each of the 4 `deny(…)` calls (bad first frame, closed before handshake,
  credential sources unusable, `authorize` failure); `CallAudit::start` right after
  the child spawns (tool `"stdio"`, argv = `config.command[1..]`); stdout/stderr
  wrapped in `audit::tap_stdout/tap_stderr`; `audit.finish(code)` after the exit
  code is known. Lane A: move `start` to after the Invoke is resolved (pass the
  real `ToolName` + caller argv) and pass `Some(tool)` to `denied` once named.
- *Denied* records use `tool: None` in single-command mode (the caller named
  nothing). Reason is cut by `truncate_reason`, byte-identical to the frame.
- *Digest:* added `library::OutputHasher` (streaming BLAKE3 + count) to
  `library/audit.rs` instead of adding a `blake3` dep (and lockfile churn) to
  `//wires`.
- *Rendering:* record lines keep the chat prefix `HH:MM:SS <sender8>` (sender =
  the responder that wrote it), then the card's formats. `--json` emits
  `{ts,sender,seq,record}` (no `text`) for records. Every wire string is escaped
  (no forged lines / terminal escapes). `render::identity_line(&IdentityClaim)
  -> String` is the single function lane F replaces.
- *Serve prints the channel:* `serve --audit-topic` runs the tail loop with
  backfill 0, so its stdout shows the channel live (its own records included).

**Off-lane touches.** `library/audit.rs` + `lib.rs` (OutputHasher export);
`wires/main.rs` rustfmt fix of lane D's `cli_admin` arm (format check was red
after merging `aaron/remote-cli`).

**Lint.** `aspect lint //...` (via `bazel_env`'s `aspect`; not on PATH) reports
only the pre-existing dead-code warnings for lane A/C stubs (`tools.rs`,
`ServeConfig.tools`, `call_on`, `HeadSource::None`).
