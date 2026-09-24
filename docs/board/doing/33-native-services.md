# 33 — Wires-native services: the host runtime as a library

**Lane:** N · **Depends on:** 28 · **Status:** Phase 0 done; Phase 1 next (2026-09-23)
· **Files:** `library/membership/identity.rs` (key hygiene), `wires/admin/keystore.rs`
(seed read/write only), `wires/host/transport.rs` (the bridge), `wires/host/service.rs`
(new), `wires/host/serve.rs`, protocol.md §9; Phase 1 adds a `[lib]` target to
`wires/` and an example

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

**Key hygiene (done: `db925a7`).** `NodeIdentity`: no `Clone`, `Debug` or
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
`Host::builder().home(..).identity(..).service(name, impl Service).build()?.serve()`.
`Service::call(&self, Call, CallIo) -> i32`. `Call` carries the verified
caller node, `Principal`, role, state version and `Argv`, plus
`push_to_caller` (the per-call capability as a method) and a cancellation
token. `CallIo` is a `tokio::io::duplex` pair per stream. If the caller
disconnects, the handler's task is aborted; if the handler panics, the call
exits -1 and still gets a `Finished` record. Native and `Command` services
can mix in one host. The same preflight applies: the signed state must
assign every registered service to this node. The embedding API takes a
keystore path, never a seed string.
- [ ] Example: a `kv` daemon keyed by the verified principal (state kept
      across calls, typed identity, push to the caller).
- [ ] e2e on the loopback fixtures: works through `wires call` and `wires
      mcp`; `wires watch` shows the same record shape as a CLI service; a
      refused caller never reaches the handler; stdin/stdout digests match.

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
