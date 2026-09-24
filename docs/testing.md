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
  doctests for identity, memberships, invites, the signed state, roles,
  the registry and `authorize`, state-sync and session frames, invocations,
  call records and the call log, IdP claims and push frames.
- **`wires`** — each role's command functions, the keystore (round-trips,
  file modes, flag → env → file → keystore precedence), the session transport
  over in-memory pipes and over **real loopback QUIC** (two iroh endpoints on
  localhost, no relay or discovery), and `e2e/`: the whole stack over
  hermetic loopback (the registry deciding each call, `also_require`,
  removal with no restart, unassigned services, push by the state and by a
  call's push capability, what a service child can and can't reach, nothing
  sent to a bystander, the record stream keyed by person, and the web
  gateway's OAuth and MCP paths).

## Lint and format

```bash
make lint        # cargo clippy --workspace --all-targets -- -D warnings; shellcheck
make fmt-check   # cargo fmt --check; shfmt -d
```

## The live demo

`.scripts/demo-remote-cli.sh --quiet` is the end-to-end check on real
processes: two hosts implementing one service from
`.scripts/fixtures/host.json`, a caller that logs in (against the hermetic
`dev-mock-idp`) and runs `wires services` / `wires call` / `wires mcp` /
`wires inbox`, a reader on `wires watch`, failover and removal, all on
loopback in a fresh `mktemp -d`, every step asserted.
`.scripts/demo-push.sh --quiet` does the same for push. Both build what they
need with Cargo; `--keep` leaves the state behind to poke at. Keep state paths short: macOS
limits unix-socket paths to 104 bytes.
