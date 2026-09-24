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
| **Directory** (holds the signed policy for everyone else) | `wires serve host.json` on a host the policy lists, or `wires directory serve` | No TCP listener; binds UDP for QUIC |
| **Admin** | `wires init` / `invite` / `remove` / `issuer` / `role` / `service` / `directory` / `state push` / `state settings`, one-shot | No |

A host dials out (to peers directly, or through a relay). Any key can
complete the QUIC handshake; one without a valid badge, or banned by the signed policy, is refused at
its first message, before anything runs, and isn't written to the call log.
`wires login` binds a loopback TCP port only for the browser redirect.

## Building

Build natively on the machine that runs it: `cargo build --release -p wires`
(→ `target/release/wires`), or `docker build -t wires .` for a distroless
image. The `Dockerfile` builds on whatever architecture the Docker host is
(arm64 on a Mac, x86_64 on Linux); nothing cross-compiles.

The image holds only `wires`: enough for a caller, a reader, or the web
gateway (`deploy/gateway/` runs it as `wires gateway`). A **host** image must also contain the binaries
its `host.json` execs (`sqlite3`, `gh`, …): build your own image from the
`Dockerfile`'s `build` stage output (`/usr/local/bin/wires`) plus those binaries.

## Running a host

A host is a member like any other. It joins once, then runs `serve`:

```bash
wires id                       # send this to the admin
wires join <token>             # the admin's `wires invite <id>` output
wires serve --check host.json  # validate; print what it implements
wires serve host.json          # refuses to start unless the signed policy assigns every service here
```

Run `serve` under a process supervisor (card 08 used `systemd-run --user`),
from the directory that relative paths in `host.json` commands resolve
against.

The admin assigns services to the host (`wires service add … --host
<name>`) before it starts. If the host's copy of the policy predates that,
`serve` fetches the newer policy from a directory when it starts; with no
directory up, a fresh `wires invite` token for it carries it (re-joining
never rolls back). While it runs, it checks a directory for a newer policy
every 5 minutes. An admin edit that reaches no directory exits 1; `wires
state push` re-publishes the stored policy once one is up.

### Run services as a separate Unix user

A service's child gets a minimal environment and is told neither
`WIRES_HOME` nor where the operator's socket is, but it runs as `serve`'s
own user and can find the keystore at its default path. So a service a
caller can steer into reading or writing files can reach whatever that user
can: the host's node key (which signs the call log) and the operator's push
socket included. `wires` doesn't switch users itself; put it in the
service's `command`:

```json
"orders-db": { "command": ["sudo", "-u", "svc", "--", "sqlite3", "-safe", "-readonly", "orders.db"] }
```

A service running as another user can't reach the per-call push socket (a
0700 directory owned by `serve`'s user) until you open that directory to
it. Isolating each call properly is an open question (a rootless microVM,
[card 32](board/backlog/32-service-sandbox-OPEN.md)).

A service's fixed command must also be safe against any trailing arguments
the caller adds, including option-like ones; `"end_of_options": true` puts
`--` before them, for CLIs that honour it. Don't run `serve` from the
admin's keystore: it refuses one holding `root.seed`.

**Directories.** Hosts and callers fetch the signed policy from a directory,
and the admin publishes every edit to them (`wires directory add <node>`). A
host the policy lists runs the directory itself inside `serve`; a node that
hosts nothing runs one with `wires directory serve` (its own keystore, joined
like any node, no `host.json`). Calls don't need a directory; joining,
edits and bans spreading do, so run two on different machines.

### Keystore and secrets


**The keystore must be writable and must persist.** `$WIRES_HOME` holds the
host's node key and membership, and the host rewrites its signed policy at
runtime: it fetches every admin change from a directory (`policy.json`; a
host that is also a directory keeps `directory.redb` too). It also holds the
call log (`call-log.jsonl`), the push queue and the operator's control socket
(`run/`). The services' push socket is not in it: `serve` makes a private
directory for that under `$XDG_RUNTIME_DIR` (else the temp dir) at start and
removes it at exit, so the runtime or temp dir must be writable too.
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
  `serve`, `call`, `mcp`, `gateway`, `inbox` and `watch`, for NAT traversal between egress-only
  peers that can both reach it. Keep it one logical endpoint: two peers only
  rendezvous on the *same* relay.
- **n0 DNS discovery and relays** (the default): resolves a node id to
  addresses, but needs outbound internet.

For a private or air-gapped network, run your own relay so nothing depends on
n0.

## Provisioning and removal

- **Add a member:** the joiner runs `wires id`; the admin runs
  `wires invite <id> --name <label>` and hands back the token; the joiner runs
  `wires join <token>`. The token's badge (its root-signed membership) is
  what admits the node: the invite edits no policy and publishes nothing. The
  root key never leaves the admin's machine.
- **Remove a member:** `wires remove <label>`. The node is banned in a new
  signed policy until its badge would expire, and the policy is published to
  the directories, with no import and no restart. `serve` re-reads its policy
  once per connection, so from the moment a host has the new policy, the removed
  node's next call there is refused: exit `77`, `wires: denied by host: not
  a member of this network` on its stderr. The host traces the refusal
  rather than logging it (a banned key can't write to the log). A host that is a directory has the new policy at once; any other host
  follows a directory's subscription and has it within a second. There is no shared key to rotate.
- **Expiry:** a badge (membership) expires after its `--ttl` (default and
  most `30d`), the signed policy after its `--state-ttl` (default `90d`), and
  nothing renews them yet. Any admin edit signs a fresh policy (never
  shortening its life), and so does an invite when the stored policy has
  expired; re-issue badges with `wires invite <id>`.
- **Rotate a node key:** the node id changes with the key, so remove the old
  id and invite the new one.

## A web gateway

`wires gateway` serves the services each signed-in user may call as a remote
MCP server (Streamable HTTP, OAuth 2.1), for the web clients people already
use for remote tool calling: Claude.ai's custom connectors, the MCP
Inspector. It is one member node that calls **as** each web user:

1. The user adds `https://<gateway>/mcp` as a connector. The client finds
   the gateway's OAuth metadata, registers (Client ID Metadata Document, or
   DCR), and opens the gateway's consent page.
2. The gateway sends the user to Google with `nonce` = the hash of **the
   gateway's** node key (as `wires login` does for a caller's own node).
3. On every call, the gateway presents that user's ID token in the session
   `Hello`. The host verifies Google's signature and the nonce against the
   dialing node (the gateway) under the policy's trusted issuers, checks the
   registry, runs the call and records it with the user as the verified
   principal (the dialing node is the gateway's).

What this changes, honestly:

- **The gateway holds every signed-in user's live identity.** A token bound
  to the gateway's key is only useful to the gateway, but the gateway can
  use it for anything that user may call until it expires (about an hour).
  Trust the gateway like any service that holds your users' sessions.
- **Sessions last as long as the Google ID token.** Google omits `nonce` when
  it refreshes a token, so a refreshed token couldn't be bound to the
  gateway. The gateway issues no refresh tokens; the client reconnects (one
  click with a live Google session).
- **Only the user's identity admits a web user.** Every role needs a
  verified identity, so the gateway's node alone is in no role: the gateway
  offers a service only if a role matches the web user's own verified
  identity. A user the policy lets call nothing is refused at sign-in.
- Push, inbox and `watch` aren't offered through the gateway (an `inbox`
  MCP tool is designed, parked: [card 31](board/backlog/31-inbox-delivery.md)).

To run one:

1. **An OAuth client** at the IdP of type *Web application* (Google Cloud
   Console → Credentials), with the redirect URI
   `https://<gateway>/oauth/callback`.
2. **Hosts trust it:** the admin adds its client id to the audiences the
   policy accepts from Google (`wires issuer set https://accounts.google.com
   --client-id <the CLI's client id> --audience <the CLI's client id>
   --audience <the gateway's client id>`). A host whose `host.json` narrows
   `identity.issuers[].audiences` must list it there too.
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

The keystore volume holds the node key, membership and signed policy, the
key that signs DCR client ids (`gateway-client-key`), and the live sessions
(`gateway-sessions.json`, keyed by token hash, so a restart signs no one out).
