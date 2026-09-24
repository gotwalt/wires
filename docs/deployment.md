# Deploying wires

Patterns for running wires beyond one machine. For the command reference see
[usage.md](usage.md); for the recorded two-machine run see
[demo.md](demo.md); for tests see [testing.md](testing.md).

## What you deploy

| Piece | Command | Listens? |
| ----- | ------- | -------- |
| **Host** (runs the CLIs) | `wires serve host.json` | No TCP listener, no firewall port opened; binds UDP for QUIC |
| **Caller** (the agent side) | `wires call`, or `wires mcp` for MCP-only clients | No |
| **Web gateway** (for Claude.ai and other remote-MCP clients) | `wires gateway` | HTTP, behind TLS you provide (a tunnel or proxy) |
| **Reader** | `wires watch` | No |
| **Admin** | `wires init` / `invite` / `remove` / `role` / `service`, one-shot | No |

A host dials out (to peers directly, or through a relay), and unauthenticated
peers are refused at the QUIC handshake.

## Building

Build natively on the machine that runs it: `cargo build --release -p wires`
(→ `target/release/wires`), or `docker build -t wires .` for a distroless
image. The `Dockerfile` builds on whatever architecture the Docker host is
(arm64 on a Mac, x86_64 on Linux); nothing cross-compiles.

The image holds only `wires`. A **host** image must also contain the binaries
its `host.json` execs (`sqlite3`, `gh`, …): build your own image from the
`Dockerfile`'s `build` stage output (`/usr/local/bin/wires`) plus those binaries.

## Running a host

A host is a member like any other. It joins once, then runs `serve`:

```bash
wires id                       # send this to the admin
wires join <token>             # the admin's `wires invite <id>` output
wires serve --check host.json  # validate; print what it implements
wires serve host.json          # refuses to start unless the signed state assigns every service here
```

Run `serve` under a process supervisor (card 08 used `systemd-run --user`),
from the directory that relative paths in `host.json` commands resolve
against.

The admin assigns services to the host (`wires service add … --host
<name>`) before it starts. If the host was offline when that state was
pushed, it needs the newer state first: a fresh `wires invite` token for it
carries it (re-joining never rolls back).

**The keystore must be writable and must persist.** `$WIRES_HOME` holds the
host's node key and membership, and the host rewrites its signed state at
runtime: every admin change is pushed to it (`state.json`). It also holds the
call log (`call-log.jsonl`), the push queue and the control socket (`run/`).
A read-only or throwaway keystore loses those on restart.

**Secrets.** Every secret input resolves **flag → environment variable →
`--…-file` → keystore**. Don't pass `--node-seed` on the command line or in
the environment: argv leaks through `ps`, and `serve` execs children. Keep the
node key as a file, either in the keystore or mounted and read with
`--node-seed-file`. The root key (`root.seed`) stays on the admin's machine,
and a host never holds it.

**Kubernetes** (untested): a persistent, writable `$WIRES_HOME` (a PVC or
a StatefulSet volume), `replicas: 1` (the node key is the host's address, so
replicas sharing a key are not a load balancer), and no `Service` or
`Ingress`.

## Reachability and discovery

Three layers, most self-contained first:

- **A local hints file.** `$WIRES_HOME/hints`: one line per node, `<node
  id> <ip:port>…`. A running `serve` writes its own line to `run/hint`;
  copy it into the callers', readers' and admin's hints. Every endpoint
  `wires` binds uses it. The addresses are unsigned hints: iroh still
  authenticates the peer's key, so a wrong address can only fail to connect.
- **Self-hosted relay**: run upstream
  [`iroh-relay`](https://docs.rs/iroh-relay) and pass `--relay-url` to
  `serve`, `call`, `mcp`, `inbox` and `watch`, for NAT traversal between egress-only
  peers that can both reach it. Keep it one logical endpoint: two peers only
  rendezvous on the *same* relay.
- **n0 DNS discovery and relays** (the default): resolves a node id to
  addresses, but needs outbound internet.

For a private or air-gapped network, run your own relay so nothing depends on
n0.

## Provisioning and revocation

- **Add a member:** the joiner runs `wires id`; the admin runs
  `wires invite <id> --name <label>` and hands back the token; the joiner runs
  `wires join <token>`. The root key never leaves the admin's machine.
- **Remove a member:** `wires remove <label>`. The new signed state is pushed
  to the hosts first, with no import and no restart. `serve` re-reads its
  state once per connection, so the removed member's next call is refused:
  exit `77`, `wires: denied by responder: <reason>` on its stderr, and a `✗`
  record in the host's log. There is no shared key to rotate.
- **Expiry:** memberships and the signed state expire after `--ttl` (default
  `30d`), and nothing renews them yet. Any admin command signs a fresh state;
  re-issue memberships with `wires invite <id>`.
- **Rotate a node key:** the node id changes with the key, so remove the old
  id and invite the new one.

## A web gateway

`wires gateway` serves the services each signed-in user may call as a remote
MCP server (Streamable HTTP, OAuth 2.1), for clients that can't run a CLI
or a stdio server: Claude.ai's custom connectors, the MCP Inspector. It is
one member node that calls **as** each web user:

1. The user adds `https://<gateway>/mcp` as a connector. The client finds
   the gateway's OAuth metadata, registers (Client ID Metadata Document, or
   DCR), and opens the gateway's consent page.
2. The gateway sends the user to Google with `nonce` = the hash of **the
   gateway's** node key (as `wires login` does for a caller's own node).
3. On every call, the gateway presents that user's ID token in the session
   `Hello`. The host verifies Google's signature and the nonce against the
   dialing node (the gateway) under its own `identity.issuers`, checks the
   registry, runs the call and records the user as the caller.

What this changes, honestly:

- **The gateway holds every signed-in user's live identity.** A token bound
  to the gateway's key is only useful to the gateway, but the gateway can
  use it for anything that user may call until it expires (about an hour).
  Trust the gateway like any service that holds your users' sessions.
- **Sessions last as long as the Google ID token.** Google omits `nonce` when
  it refreshes a token, so a refreshed token couldn't be bound to the
  gateway. The gateway issues no refresh tokens; the client reconnects (one
  click with a live Google session).
- **Only IdP roles admit a web user.** The gateway offers a service only if a
  role other than `member` matches the user's verified identity. `member`
  admits the gateway's node, not the person behind it. A user the state lets
  call nothing is refused at sign-in.
- Push, inbox and `watch` aren't offered through the gateway.

To run one:

1. **An OAuth client** at the IdP of type *Web application* (Google Cloud
   Console → Credentials), with the redirect URI
   `https://<gateway>/oauth/callback`.
2. **Hosts trust it:** add its client id to each host's `host.json`
   `identity.issuers[].audiences` for `https://accounts.google.com`, and
   restart `serve`.
3. **The gateway joins** like any member (`wires id`, `wires invite`,
   `wires join`). The registry's roles decide what each user sees.
4. **TLS in front.** The gateway speaks plain HTTP. `deploy/gateway/` runs
   it next to `cloudflared` on a Cloudflare Tunnel whose ingress routes the
   public host to `http://wires-gateway:8080`. Turn Cloudflare's Browser
   Integrity Check off for that host: MCP clients register and exchange
   tokens from servers, with non-browser user agents.

```bash
cd deploy/gateway && cp .env.example .env    # client id/secret, tunnel token
docker compose build
docker compose run --rm wires-gateway id       # → the admin: wires invite <id> --name gateway
docker compose run --rm wires-gateway join <token>
docker compose up -d
curl https://<gateway>/.well-known/oauth-protected-resource/mcp
```

The keystore volume holds the node key, membership and signed state, the
key that signs DCR client ids (`gateway-client-key`), and the live sessions
(`gateway-sessions.json`, keyed by token hash, so a restart signs no one out).
