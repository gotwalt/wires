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
  doctests for identity, memberships, the committed roster and its inclusion
  proofs, fabric keys and re-keys, the channel envelope/chain/admission/replay
  codecs, invocations, call records, IdP claims and push frames.
- **`wires`** — each role's command functions, the keystore (round-trips,
  file modes, flag → env → file → keystore precedence), the session transport
  over in-memory pipes and over **real loopback QUIC** (two iroh endpoints on
  localhost, no relay or discovery), and `e2e/`: the whole stack over
  hermetic loopback (onboarding, IdP, channel directory, push).

Timing-sensitive gossip e2e tests
(`e2e::directory::a_joined_caller_finds_calls_…`) can flake when the machine
is loaded; re-run it alone before chasing it.

## Lint and format

```bash
make lint        # cargo clippy --workspace --all-targets -- -D warnings; shellcheck
make fmt-check   # cargo fmt --check; shfmt -d
```

## The live demo

`.scripts/demo-remote-cli.sh --quiet` is the end-to-end check on real
processes: a host exposing one tool from `.scripts/fixtures/host.json`, a
caller that logs in (against the hermetic `dev-mock-idp`) and runs `wires
call` / `wires mcp`, and an observer on `wires watch`, all on loopback in a
fresh `mktemp -d`, every step asserted. It builds what it needs with Cargo;
`--keep` leaves the state behind to poke at. Keep state paths short: macOS
limits unix-socket paths to 104 bytes.
