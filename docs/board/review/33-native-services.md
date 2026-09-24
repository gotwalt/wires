# 33 — Wires-native services: the host runtime as a library

**Lane:** N · **Depends on:** 28 · **Status:** in review (2026-09-23): Phases 0–2 done (Rust, Python, TypeScript) and merged to main; packaging (wheel, npm) is the open follow-up
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

**Phase 2: generated bindings.** (Changed 2026-09-23: Phase 1 made `wires`
a library, so the bindings depend on it directly; the planned split into a
separate `wires-service` runtime crate would only trim what the bindings
compile in, and waits until that matters.) The language-facing surface is a callback interface made of chunks
(`read_stdin() -> Option<Bytes>`, `write_stdout(Bytes)`, `write_stderr(Bytes)`,
return the exit code), since generated bindings can't cross generics or
`AsyncRead`. Python via UniFFI (already used for the iOS companion; also
gives Swift/Kotlin); TypeScript via napi-rs unless a UniFFI Node backend
proves good enough when evaluated.
- [x] `bindings/` (package `wires-ffi`, UniFFI 0.32, foreign module `wires`):
      `Service` (a foreign class; synchronous `call(call) -> int` on a
      blocking thread), `Call` (caller, `principal()`, role, args, id;
      blocking `read_stdin` / `read_all_stdin` / `write_stdout` /
      `write_stderr`; `push_to_caller`), `HostBuilder` → `Host`
      (`serve()` blocks until `stop()` or Ctrl-C).
- [x] Python: `.scripts/build-python.sh` (`make python`) builds the cdylib
      and the generated `wires.py`; `bindings/python/examples/kv.py` is the
      kv example in Python.
- [x] Acceptance: `.scripts/demo-native-service.sh --lang python` (`make demo-python`), a
      real loopback fabric with the Python process as the host, called by
      the shipped `wires`: set/get/keys with state kept; the handler's exit
      code and stderr; bob refused (77) by name; `push_to_caller` reaching
      `wires inbox`; the host's log through alice's `wires watch --mine`.
- [x] TypeScript/Node: `bindings/node/` (package `wires-node`, napi-rs 3,
      npm package `wires`). A service is `(call) => number | Promise<number>`
      on Node's event loop; `Call`'s stdio methods return Promises;
      `HostBuilder` chains; `host.serve()` resolves on `stop()` or Ctrl-C.
      `.scripts/build-node.sh` (`make node`) builds the addon, the napi
      loader and the `index.d.ts` generated from `lib.rs` into
      `target/node/wires`; `bindings/node/examples/kv.mts` is the kv example
      (Node runs it directly). `make demo-node` runs the same acceptance,
      plus a `tsc` typecheck of the example against the generated types.
- [ ] Packaging: a wheel (maturin, `bindings = "uniffi"`) and an npm package.

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
- 2026-09-23, Python: a foreign handler runs on `spawn_blocking`, so a
  caller's disconnect can't abort it (its next read or write fails); an
  exception ends the call with exit 1 and its text on the caller's stderr,
  like an uncaught exception in a CLI; stdout/stderr are closed when the
  handler returns even if Python keeps the `Call`. Stdio is `bytes` on the
  foreign side (`Vec<u8>`): the one place the no-bare-`Vec<u8>` rule gives
  way, since a binding has no newtypes to offer. The demo runs Python from
  uv (`uv run --managed-python`, 3.13; uv 0.7.6 has no managed 3.14 stable).
- 2026-09-23, macOS firewall: the demo's Python host raised the "accept
  incoming connections?" dialog (an interpreter can't be signed the way
  `macos-sign.sh` signs our binaries). `HostBuilder::bind_loopback()`
  (Python: `bind_loopback()`, kv.py `--loopback`) binds IP only on
  `127.0.0.1`/`::1` and turns off iroh's port mapper, whose multicast
  gateway discovery is what prompts (iroh's `PortmapperConfig` docs); other
  callers still reach the host through its relay. Checked with `lsof`: the
  host holds only loopback UDP sockets, and no prompt appeared.
- Observed: a `set` that pushes took ~3 s: `push_to_caller` waits while the
  host tries to deliver directly to a caller with no receiver listening,
  then queues. The same as a CLI child's `wires push`; not a bindings issue.
- 2026-09-23, TypeScript: the JS handler is a `ThreadsafeFunction` called
  with `call_async_catch` (plain `call_async` turns a thrown error into a
  fatal exception that kills Node); a sync throw, an async throw and a
  rejected Promise all end the call with exit 1 and the message on stderr.
  It returns `number | Promise<number>` (`Either`). Everything runs on
  napi's tokio runtime (`tokio_rt`), the host included. The crate has
  `test = false`: an addon has no test harness to link, so its acceptance
  is `make demo-node`. The demo script is now one, with `--lang`.

### Integrator review fixes (2026-09-24)

- **B1.** `serve_until` now stops everything it started once `shutdown`
  resolves (or push ends, or the push sockets fail to bind): the refresh
  loop (a `oneshot` whose sender is dropped; `refresh_loop` selects on it),
  `router.shutdown()` (which aborts in-flight sessions, so native handlers
  are aborted too), `endpoint.close()`, and the child push directory. The
  embedded host's endpoint also takes its address hints from its own
  keystore (`transport::bind_with(.., hints_from)`; `pull_now` likewise), so
  it now reads nothing from `$WIRES_HOME` (L4: code fixed, not the doc).
  e2e `a_stopped_host_closes_its_endpoint`; the demo sends SIGTERM, the
  example calls `stop()`, and the Python / Node process must exit 0 on its
  own within 10 s, having printed `kv: stopped`.
- **B2.** `Task` keeps its `JoinHandle` (and the exit code once reaped)
  instead of moving it into `wait()`, and aborts it on `Drop`. This fixed a
  real bug the new tests found: the bridge races `wait()` against the
  caller leaving, so the dropped `wait` future took the handle with it and
  the following `kill()` reached nothing; the handler ran on detached and
  the session hung on its stdout. (The old `TaskProcess` test missed it
  because its closure dropped its stdout at once.) Tests:
  `dropping_the_running_service_aborts_its_handler`,
  `a_kill_after_a_dropped_wait_still_stops_the_handler`.
- **B3.** e2e: `native_and_cli_services_share_one_host` (a `host.json` CLI
  service beside `Kv`: one gate, one log), `push_allow_refuses_a_caller_in_none_of_its_roles`
  (exit 1, `push refused: …`, a `Denied` push record),
  `each_verified_person_gets_their_own_kv` (alice and bob both admitted,
  separate namespaces). embed.rs: a native/`host.json` name collision is now
  refused at `build` (`service t is both registered here and in host.json;
  pick one`) rather than silently resolved by the gate; `load_embedded` and
  `HostBuilder::host_json` (empty services beside native ones; CLI services
  alone; v1 and a missing file refused with the path). transport: the bridge
  tests drive `native::start` (TaskProcess / `in_process` deleted);
  `a_native_service_is_stopped_and_finished_when_the_dialer_vanishes`
  checks `Finished` exit -1.
- **M1.** The bindings' `serve` no longer takes Ctrl-C unless asked:
  Python `serve(handle_ctrl_c=False)` (UniFFI default), Node
  `serve(handleCtrlC?: boolean)`. The stop signal is made at `build`, so
  `stop()` before `serve()` makes it return at once. The examples stop on
  SIGTERM/SIGINT themselves (Python serves on a thread so the main thread
  can take signals). `Host::serve` (Rust) keeps Ctrl-C, documented.
- **M2.** protocol.md §5: a Rust handler is aborted; a Python/JS handler's
  next read or write fails. Also documents `also_require`, the name
  collision, the keystore-only hints, what `serve_until` stops, Ctrl-C.
- **M3.** usage.md "Host: native services" (keystore setup, Rust, Python,
  TypeScript, the demo; layout lists `bindings/`); testing.md lists the
  native demo. README: no line added. The candidate ("write a service in
  Rust, Python or TypeScript") dies to "any MCP SDK already lets me write a
  server in Python"; what's distinctive (same gate, log and identity as a
  CLI service) is the existing pitch, not a new line.
- **M4.** Board row 33: "bindings that depend on `wires` directly".
- **L1.** `Call` is no longer `Clone` (nothing needed it; documented: share
  it in an `Arc`). `Call::principal()` is `&Principal` and `Call::id()` is
  `CallId` (no role admits without a principal; a host without a call log,
  tests only, names the call with a fresh id). The bindings follow.
- **L2.** Documented on `HostBuilder::service` and in protocol.md:
  `also_require` is CLI-only; a handler checks `Call::role` /
  `Call::principal` itself. No `HostBuilder::also_require` (it needs the
  gate to read native rules; not worth it until someone asks).
- **L3.** kv.py / kv.mts: a failed push after `set` is logged to the host's
  stderr and the call still exits 0.
- **Sweep.** One `wires::SharedIo` (in `native.rs`) replaces both bindings'
  stdio plumbing (locks, close, write, `READ_ALL_MAX`, read-all); the
  `Principal` mapping is a `From` impl per binding (each needs its own
  derive, so the struct can't be shared). `WiresError::failed(&anyhow::Error)`
  (+ `msg`), node's `failed_by`. `Binding::Endpoint` is `#[cfg(test)]`.
  `HostConfig::read` is the shared helper of `load` / `load_embedded`.
  `examples/kv.rs` → `examples/kv/{main,store}.rs`, the e2e tests include
  `store.rs` (no `allow(dead_code)`). Demo: `nativehost`, header rewritten,
  trap is a `cleanup` function (no stray `p=""`), `tsc --typeRoots` instead
  of a `sed` of tsconfig, and a `throw` verb (kv.py, kv.mts) asserted as
  exit 1 with its message. "(card 33)" gone from the package descriptions,
  build scripts and examples. The bindings' Rust tests drive the foreign
  path (`run_foreign`, which `Foreign` uses): a raise is exit 1 plus
  stderr; stdio is closed after the handler returns though the foreign
  side kept it. The builds-once test stays (binding-specific).
