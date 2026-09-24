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
  doctests for identity, badges (memberships), invites and their login
  settings, the signed policy (head, items, root-signed service entries,
  bans, policy updates and their `apply`, caller views, `Fresh`), roles, the
  registry and `authorize`, directory and session frames, invocations, call
  records and the call log, IdP claims and push frames.
- **`wires`** — each role's command functions, the keystore (round-trips,
  file modes, flag → env → file → keystore precedence), the session transport
  over in-memory pipes and over **real loopback QUIC** (two iroh endpoints on
  localhost, no relay or discovery), and `e2e/`: the whole stack over
  hermetic loopback (the registry deciding each call, `also_require`,
  removal with no restart, unassigned services, push by the policy and by a
  call's push capability, what a service child can and can't reach, the
  record stream keyed by person, the web gateway's OAuth and MCP paths,
  hosts following a directory by subscription and the `lenient` / `strict`
  freshness rule (`e2e/follow.rs`), and callers' views: what a caller's
  keystore holds, a grant or revocation reaching a running `wires mcp`,
  `resolve` (`e2e/views.rs`)), and `directory/tests.rs`: the directory over
  loopback (the admin publishing to it and dialing no host, hosts fetching
  the whole policy and callers their views, a caller refused the whole
  policy, a restart from `directory.redb`, refusing tampered, mixed and
  older policies and a stranger's `Fresh`, catching up from a replica).
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
processes: two hosts implementing one service from
`.scripts/fixtures/host.json`, both also the network's directories, a caller
that logs in (a bare `wires login`, against the hermetic `dev-mock-idp`) and
runs `wires services` / `wires call` / `wires mcp` /
`wires inbox`, a read-only caller stopped on its own machine, an analyst the
hosts' `also_require` refuses, a reader on `wires watch`, failover and removal, all on
loopback in a fresh `mktemp -d`, every step asserted.
`.scripts/demo-push.sh --quiet` does the same for push, and
`.scripts/demo-native-service.sh --lang python|node` (`make demo-python`,
`make demo-node`) for a native service written in Python or TypeScript:
the kv example as the host, called with the shipped `wires`, down to a
clean `stop()` (Python needs `uv`, TypeScript Node >= 22.18; the node demo
also typechecks the example against the generated `index.d.ts`). All three
build what they need with Cargo; `--keep` leaves the temporary keystores
behind to poke at. Keep their paths short: macOS limits unix-socket paths
to 104 bytes.
