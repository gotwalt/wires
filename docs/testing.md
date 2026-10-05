# Testing wires

Plain Cargo (see [CLAUDE.md](../CLAUDE.md)). There is no CI: run `make lint
test` before pushing.

## Automated tests

```bash
cargo test --workspace            # everything: unit + proptest + e2e + doctests
cargo test -p library             # the pure crate (and its doctests)
cargo test -p wires <name>        # one test, or a module path prefix (e.g. e2e::)
cargo test -p wires -- --nocapture
```

What's covered:

- **`library`** — property tests (`proptest`), example unit tests and runnable
  doctests for node identity, the network string and its login settings,
  admission (`check_admitted`: node and person bans), the signed policy
  (head, items, root-signed service entries, bans, policy updates and their
  `apply`, caller views, `Fresh`), roles, `authorize`, directory and session
  frames, invocations, IdP claims and push frames.
- **`wires`** — each role's command functions, the keystore (round-trips,
  file modes, flag → env → file → keystore precedence), the session
  transport over in-memory pipes and over **real loopback QUIC** (two iroh
  endpoints on localhost, no relay or discovery), the host's log line for a
  call and for a refusal (`host/call_trace.rs`, `host/transport.rs`), and
  `e2e/`: the whole stack over hermetic loopback. That is the policy
  deciding each call, `also_require`, removal with no restart and
  unassigned services (`e2e/services_host.rs`); what a service child can and
  can't reach, and its `WIRES_ID_TOKEN` and `WIRES_CALLER`
  (`e2e/service_child.rs`); the first run from empty keystores (`init`,
  `role set`, `directory add`, `service add`, `network`, `join`, `serve`,
  `policy push`, `login <network>`, `services`, `call`), then removal by
  person from a second machine, by node, and `restore` (`e2e/first_run.rs`);
  hosts following a directory by subscription and the `lenient` / `strict`
  freshness rule (`e2e/follow.rs`); callers' views: what a caller's
  keystore holds, a grant or revocation reaching a running `wires mcp`,
  `resolve` (`e2e/views.rs`); the web gateway's OAuth and MCP paths
  (`e2e/gateway.rs`); and an embedded host serving the native `kv` example
  (`e2e/native.rs`). `directory/tests.rs` covers the directory over
  loopback: the admin publishing to it and dialing no host, the first
  directory starting empty and taking the first publish, who it admits (a
  node the policy names, or a caller whose ID token verifies), hosts
  fetching the whole policy and callers their views, a caller refused the
  whole policy, a restart from `directory.redb`, refusing tampered, mixed
  and older policies and a stranger's `Fresh`, catching up from a replica.
- **Help text** — `help_snapshots.rs` holds every command's `--help` and
  `--help-all`, the MCP `instructions` and the key error messages as files
  in `wires/snapshots/`; after an intended change, `WIRES_BLESS=1 cargo test
  -p wires help_snapshots` rewrites them, and the diff is the review.

## Lint and format

```bash
make lint        # cargo clippy --workspace --all-targets -- -D warnings; shellcheck
make fmt-check   # cargo fmt --check; shfmt -d
```

## The live demo

`.scripts/demo-remote-cli.sh --quiet` is the end-to-end check on real
processes, run as card 41's first run: the admin's `init`, roles, two
directories named `label=<node id>`, one service and `wires network`; two
hosts that `wires join <network>` and serve one service from
`.scripts/fixtures/host.json`, both also the network's directories, empty
until the admin's `wires policy push`; then callers whose whole onboarding
is `wires login <network>` (against the hermetic `dev-mock-idp`). It
asserts a caller that hasn't joined listing and dialing nothing, `wires
services` / `wires call` (arguments and stdin) / `wires mcp`, a signed-in
person in no role calling nothing, an analyst the hosts'
`also_require` refuses (exit 77), `.shell id` refused by `sqlite3 -safe`, a
push and `wires inbox` (and `--wait`), failover to the spare, and `wires
remove <email>`: exit 77 with nothing on stdout, and pushes refused at send
and at fetch. All on loopback in a fresh `mktemp -d`, every step asserted.
`.scripts/demo-push.sh --quiet` does the same for push (a build service that
calls the agent back, a locked caller), and
`.scripts/demo-native-service.sh --lang python|node` (`make demo-python`,
`make demo-node`) for a native service written in Python or TypeScript: the
kv example as the host, called with the shipped `wires`, down to a clean
`stop()` (Python needs `uv`, TypeScript Node >= 22.18; the node demo also
typechecks the example against the generated `index.d.ts`). All three build
what they need with Cargo (`WIRES_BIN` and `WIRES_DEV_BIN` point them at
binaries you built); `--keep` leaves the temporary keystores behind to poke
at.
