# 33 — Wires-native services: the host runtime as a library

**Lane:** N · **Depends on:** 28 · **Status:** Phases 0 and 1 done; Phase 2 next (2026-09-23)
· **Files:** `library/membership/identity.rs` (key hygiene), `wires/admin/keystore.rs`
(seed read/write only), `wires/host/transport.rs` (the bridge), `wires/host/service.rs`
(new), `wires/host/serve.rs`, protocol.md §9; Phase 1: `wires/lib.rs` (was
`main.rs`), `wires/main.rs`, `wires/host/{native,embed,gate,config_v2}.rs`,
`wires/examples/kv.rs`, `wires/e2e/native.rs`, protocol.md §5, CLAUDE.md

## Why (the human, 2026-09-23)

"I'd like to be able to build wires-native services — instead of merely
wrapping a CLI, imagine building the wires serve library directly into an app
that runs as a daemon. The future I eventually want is that, but with bindings
for typescript and python and other languages so that anybody can make a
service for wires in whatever language they want. I think first step is a
rust proof of concept, then we extract it to a generated library."

A native service is useful where a wrapped CLI isn't: a warm process that
keeps state across calls (connection pools, caches, loaded models), no
fork/exec per call, the verified caller given as a type rather than
`WIRES_*` variables, and pushing to the caller as a method call.

## Decisions

- **The wire stays CLI-shaped.** A native service is invoked with `Invoke {
  tool, argv }` and speaks stdin/stdout/stderr/exit, like a CLI. `wires
  call`, `wires mcp`, the gateway and `wires watch` don't change and can't
  tell the two apart. A typed RPC mode is out of scope until someone needs one.
- **The runtime decides and records; the app only handles the call.** A
  handler runs only after the gate admits the call and its `Started` is
  fsynced, the same as a child process today. It never sees a refused call
  and can't skip the log. The bridge wraps its stdio in the same audit taps,
  so its records match a CLI service's.
- **The node key is in the app's memory (accepted by the human, 2026-09-23).**
  A native service isn't a child of the host: it *is* the host, the
  operator's own code, trusted as much as `wires serve`. Card 28's rule (a
  service child gets none of the host's keystore) and card 32's sandbox
  apply to CLI services only. In place of process isolation, the key is kept
  out of reach of safe code: "use obvious rust memory safety features to
  ensure that it can't leak" (protocol.md §9). That doesn't protect against
  `unsafe` code or a foreign-language runtime in the same process.

## Phases

**Key hygiene (done: `95f9091`).** `NodeIdentity`: no `Clone`, `Debug` or
`Serialize` (compile-fail doctests); `expose_seed()` / `expose_seed_hex()`
return `Zeroizing`; `duplicate()` is the explicit second owner; the keystore
reads and writes seeds through scrubbed buffers.

**Phase 0: make the spawn step swappable (refactor only).** The bridge takes a
`Running` (stdin, stdout, stderr, and a `Process` to wait on or kill) instead
of a `Command`. Spawning a CLI child becomes one way to produce a `Running`.
The audit taps, the "stop feeding stdin once it exits" rule and the kill on
disconnect stay in the bridge, so every kind of service gets them.
- [x] `cargo test --workspace` green with no test changed except bridge
      unit tests; `make lint`, `cargo fmt --check` green.
- [x] A bridge unit test driving a non-child `Running` (in-memory stdio)
      through a session: frames, exit code, taps.

**Phase 1: Rust proof of concept.** A `[lib]` target on `wires` exposing
`Host::builder(home).trust_issuer(..).host_json(..).service(name, impl Service).build()?.serve()`
(or `.serve_until(shutdown)`). `Service::call(&self, Call, CallIo) -> impl
Future<Output = i32>`. `Call` carries the verified caller node, `Principal`,
role, state version, service, args and call id. `CallIo` is boxed
`AsyncRead`/`AsyncWrite` over `tokio::io::duplex` pipes. If the caller
disconnects, the handler's task is aborted; if the handler panics, the call
exits -1 and still gets a `Finished` record. Native and `Command` services
can mix in one host. The same preflight applies: the signed state must
assign every registered service to this node. The embedding API takes a
keystore path, never a seed string.
- [x] Example: `examples/kv.rs`, a key-value daemon keyed by the verified
      principal (state kept across calls, typed identity).
- [x] `Call::push_to_caller`: the per-call push capability as a method
      (`HostBuilder::push_allow` or `host.json` `push`); e2e
      `a_native_service_pushes_to_its_caller`.
- [x] e2e (`wires/e2e/native.rs`, hermetic loopback, the example's own `Kv`):
      called through the dial `wires call` uses; a refused caller never
      reaches the handler; the host's signed log holds `Started` / `Finished`
      / `Denied` with principal, role, argv and stdin digest and head; an
      unassigned native service refuses to start.

**Phase 2: move it into its own crate, then generate bindings.** Split the
host runtime into a third crate (`service/`, package `wires-service`) once
Phase 1's API settles; `wires serve` becomes a thin user of it. The
language-facing surface is a callback interface made of chunks
(`read_stdin() -> Option<Bytes>`, `write_stdout(Bytes)`, `write_stderr(Bytes)`,
return the exit code), since generated bindings can't cross generics or
`AsyncRead`. Python via UniFFI (already used for the iOS companion; also
gives Swift/Kotlin); TypeScript via napi-rs unless a UniFFI Node backend
proves good enough when evaluated.

## Notes

- 2026-09-23: in-process stdin already streams without a size limit
  (64 KiB frames, backpressure); the 4 KiB is only `stdin_head` in the
  record. Nothing to change for native services.
- 2026-09-23, Phase 0: `wires/host/service.rs` holds `Running` (boxed
  stdin/stdout/stderr) and the dyn-compatible `Process` trait (`wait` returns a
  boxed future; `kill`). `bridge_child` is now `bridge(send, recv, Running, …)`;
  spawn failures (`finish(-1)`, "spawning {program}") moved to the caller in
  `serve_session_permitted`. The in-process `TaskProcess` (a `JoinHandle`;
  `kill` aborts it; an aborted or panicked task exits -1) lives in the
  transport tests for now; Phase 1 promotes it. Tests:
  `an_in_process_service_is_bridged_and_recorded_like_a_child` (frames, exit,
  stdout/stderr/stdin taps) and
  `an_in_process_service_is_stopped_when_the_dialer_vanishes`.
- 2026-09-23, Phase 1: `wires` is now a library plus a one-line `main.rs`
  (`wires::run`). The old `main.rs` became `lib.rs` unchanged apart from
  `fn main` → `pub fn run` and the re-exports, so every `crate::` path still
  works. `extern crate self as wires` lets `examples/kv.rs` (written against
  the public API) be included in the e2e tests as is. `serve_cmd` is now a
  thin `Serving` + `serve_until(serving, shutdown)`, which the embedded `Host`
  shares, so both start, log and serve the same way; `Binding::Endpoint` is
  the hermetic-test seam. `host.json` loaded by an embedding app may list no
  services (`load_embedded` / `validate_fields`). Dropped from the plan: the
  cancellation token (aborting the task is enough; clean up in `Drop`).
  Not tested separately: `wires mcp` and the gateway reach a native service
  through the same dial (`call_service_on`) the tests use; the tests read the
  host's signed log file directly, not through the `wires watch` stream.
- Known limit: `transport::bind_with_alpn` still reads the local hints file
  from `$WIRES_HOME`, not from an embedded host's keystore (protocol.md §5).
- 2026-09-23, push: the transport mints a native call's capability exactly as
  for a child (same `Capabilities` registry, bound to the call id, dropped
  after the bridge to start the grace period). The handler gets a
  `CallerPush` (registry + token + the push service's sender, never printed)
  instead of `WIRES_PUSH_TOKEN`; `push_to_caller` runs the child socket's
  check, then sends the same `PushCommand`. `serve_until` now makes the push
  queue before the host is shared (`ServicesHost::push_commands`).
