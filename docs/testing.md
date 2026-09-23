# Testing wires

How the project is tested, and how to exercise it by hand. Everything runs
through Bazel — never `cargo build`/`cargo test` (see [CLAUDE.md](../CLAUDE.md)).

## Automated tests

```bash
bazel test //...                      # everything
bazel test //library:library_test     # library unit + property tests
bazel test //library:library_doc_test # doctests
bazel test //wires:wires_test         # CLI fns + the loopback QUIC test
```

What's covered:

- **`//library`** — property tests (`proptest`) + example unit tests + runnable
  doctests for identity, grants, tickets, policy/CRL, and the session frame
  codec (round-trips, stream-splitting, tamper/expiry/revocation rejection).
- **`//wires:wires_test`** —
  - the offline command functions (`run_keygen` / `run_grant` / `run_revoke`):
    determinism, ticket acceptance, idempotent revocation;
  - the **keystore**: file round-trips, `0600` permissions, clobber protection,
    resolver precedence (flag → env → file → keystore);
  - the **transport**: the `NodeIdentity`↔iroh key bridge, `Frame` round-trips
    over a `tokio::io::duplex` pipe, and a **real loopback QUIC test** — two
    iroh endpoints on localhost, dial → handshake → `serve` execs `cat` →
    stdin echoes back on stdout → exit `0`, plus an untrusted-grant rejection.

The loopback test is the end-to-end proof of Flow A and runs hermetically (no
network, no relay) by dialing a localhost `EndpointAddr` directly.

### Useful flags

```bash
bazel test --config=debug //wires:wires_test    # stream output, no cache, long timeout
bazel test --test_output=errors //...           # show failing test logs
bazel test --test_arg=--nocapture //wires:wires_test
```

## Lint and format (run before committing)

```bash
aspect lint //...      # clippy + shellcheck (expect empty "results")
format                 # rustfmt + shfmt + buildifier
```

(Both are on `PATH` after `bazel run //tools:bazel_env`; see the README dev
setup.)

## Manual: the offline ceremony (no network)

Fully local, deterministic — exercises keys, grants, tickets, and the CRL:

```bash
export WIRES_HOME="$(mktemp -d)/wires"
bazel build //wires
bin=bazel-bin/wires/wires

"$bin" advanced keygen --save-node --save-root        # writes 0600 node.seed + root.seed
ls -l "$WIRES_HOME"                          # confirm permissions

# the saved node id (re-derive from the seed file to read it back):
NODE_ID=$("$bin" advanced keygen --node-seed "$(tr -d '\n' < "$WIRES_HOME/node.seed")" \
  | awk '/^node_id/{print $2}')

TICKET=$("$bin" advanced grant --subject "$NODE_ID" --target "$NODE_ID" --scope tool:rg --ttl 3600)
echo "ticket: ${TICKET:0:32}…"

"$bin" advanced revoke --subject "$NODE_ID"           # updates $WIRES_HOME/crl.json in place
cat "$WIRES_HOME/crl.json"
```

## Manual: a live session

`.scripts/demo-remote-cli.sh` is the live session: a host exposing one tool
from a `host.json` (`.scripts/fixtures/host.json`), a caller that logs in and runs `wires call` / `wires mcp`,
and an observer on `wires watch`, all on loopback in a fresh `mktemp -d`, every
step asserted. Run it with `--keep` to poke at the state afterwards.

Across machines, `serve` and the callers need a relay to rendezvous (the
default n0 relays, which require internet, or a self-hosted one:
`bazel run //relay -- --listen 127.0.0.1:3340`, then `--relay-url` on each
side).

> **Note:** even with `--relay-url`, address discovery (node id → address)
> currently uses iroh's n0 DNS, so a no-internet box may not resolve the peer
> yet. See the discovery limits in [deployment.md](deployment.md). The
> automated loopback tests avoid this by addressing localhost directly.

## CI

CI should run `bazel test //...` (and optionally `aspect lint //...`). The
loopback QUIC test gives end-to-end coverage of the transport without needing a
relay or network egress, so it is safe in a sandbox.
