# Deploying wires

Patterns for running wires beyond one machine. For the command reference see
[usage.md](usage.md); for the two-machine demo script see
[demo.md](demo.md); for tests see [testing.md](testing.md).

## What you deploy

| Piece | Command | Listens? |
| ----- | ------- | -------- |
| **Host** (runs the CLIs) | `wires serve host.json` | No TCP listener, no firewall port opened; binds UDP for QUIC |
| **Directory** (holds the signed policy for everyone else) | `wires serve host.json` on a host the policy lists, or `wires directory serve` | No TCP listener; binds UDP for QUIC |
| **Caller** (the agent side) | `wires call`, or `wires mcp` for MCP-only clients | No |
| **Web gateway** (for Claude on the web and other remote-MCP clients) | `wires gateway` | HTTP, behind TLS you provide (a tunnel or proxy) |
| **Admin** | `wires init` / `network` / `issuer` / `role` / `service` / `directory` / `remove` / `restore` / `policy push` / `policy settings`, one-shot | No |

Every node but the admin starts from the network string the admin prints
with `wires network`: a caller runs `wires login <network>`, a host,
directory or gateway `wires join <network>`. The string is the same for
every node and not secret.

A host dials out (to peers directly, or through a relay). Any key can
complete the QUIC handshake; one whose ID token doesn't verify, that the
signed policy bans, or whose person no role matches, is refused at its first
message, before anything runs.
`wires login` binds a loopback TCP port only for the browser redirect.

## Building

Build natively on the machine that runs it: `cargo build --release -p wires`
(→ `target/release/wires`), or `docker build -t wires .` for a distroless
image. The `Dockerfile` builds on whatever architecture the Docker host is
(arm64 on a Mac, x86_64 on Linux); nothing cross-compiles.

The image holds only `wires`: enough for a caller or the web gateway
(`deploy/gateway/` runs it as `wires gateway`). A **host** image must also
contain the binaries its `host.json` execs (`sqlite3`, `gh`, …): build your
own image from the `Dockerfile`'s `build` stage output
(`/usr/local/bin/wires`) plus those binaries.

## Running a host

A host is a node like any other. It joins once, the admin names it, then it
runs `serve`:

```bash
wires join <network>           # prints this node's id: send it to the admin
# admin: wires service add <name> … --host <label>=<node id>
wires serve --check host.json  # validate; print what it implements
wires serve host.json          # serves once the signed policy assigns every service here
```

Run `serve` under a process supervisor (card 08 used `systemd-run --user`),
from the directory that relative paths in `host.json` commands resolve
against.

The admin assigns services to the host (`wires service add … --host
<label>=<node id>`) before it starts. A host that is not a directory and
holds no policy, or one from before that assignment, fetches the newer
policy from a directory when it starts, for up to 8 seconds, and exits
saying why if none answers. While it runs, it follows one directory's
subscription (the next listed one if that directory goes away): each admin
edit arrives within a second as one small update, and a signed freshness
timestamp every 5 minutes (`beat_secs`). An admin edit that reaches no
directory exits 1 (once one has taken a publish from the admin); `wires
policy push` re-publishes the stored policy once one is up.

`serve` writes one log line per call to its stderr (`call finished`, or
`call refused` for an admitted caller), through `tracing`: the service, the
caller's node, the person's issuer, subject and email, the role, the exit
code, the duration and the bytes sent back. That is all wires keeps. To keep
a record, collect `serve`'s output; `RUST_LOG` sets the level as usual.

### Run services as a separate Unix user

A service's child gets a minimal environment and is told neither
`WIRES_HOME` nor where the operator's socket is, but it runs as `serve`'s
own user and can find the keystore at its default path. So a service a
caller can steer into reading or writing files can reach whatever that user
can: the host's node key and the operator's push socket included.

Its environment also holds the caller's ID token (`WIRES_ID_TOKEN`), a
bearer credential until it expires (about an hour with Google), and any
process of the same Unix user can read it from `/proc/<pid>/environ`. One
more reason to run services as another user, and services that shouldn't
see each other's callers' tokens as different users.

`wires` doesn't switch users itself; put it in the service's `command`. The
child's `WIRES_*` variables are what the service reads its caller from, and
`sudo` resets the environment by default, so tell it to keep them. An
untested sketch, with `serve` running as `wires` and the service as `svc`:

```
# /etc/sudoers.d/wires
Defaults:wires env_keep += "WIRES_ID_TOKEN WIRES_CALLER WIRES_CALLER_EMAIL WIRES_CALLER_NODE WIRES_SERVICE WIRES_ROLE WIRES_PUSH_SOCKET WIRES_PUSH_TOKEN"
wires ALL=(svc) NOPASSWD: /usr/bin/sqlite3
```

```json
"orders-db": { "command": ["sudo", "-n", "-u", "svc", "--", "/usr/bin/sqlite3", "-safe", "-readonly", "orders.db"] }
```

A service running as another user can't reach the per-call push socket (a
0700 directory owned by `serve`'s user) until you open that directory to
it. Isolating each call properly is an open question (a rootless microVM,
[card 32](board/backlog/32-service-sandbox-OPEN.md)).

A service's fixed command must also be safe against any trailing arguments
the caller adds, including option-like ones; `"end_of_options": true` puts
`--` before them, for CLIs that honour it. Don't run `serve` from the
admin's keystore: it refuses one holding `root.seed`.

### Keystore and secrets

**The keystore must be writable and must persist.** `$WIRES_HOME` holds the
host's node key and the network string it joined with (`network.json`), and
the host rewrites its signed policy at runtime: every admin change arrives
from a directory (`policy.json`, and the newest freshness timestamp in
`fresh.json`; a host that is also a directory keeps `directory.redb` too).
It also holds the push queue (`push-queue.json`) and the operator's control
socket (`run/`; for a keystore path too long for a unix socket, the socket
goes under `$TMPDIR/wires-<uid>/` or `/tmp/wires-<uid>/` instead). The
services' push socket is not in it: `serve` makes a private directory for
that under `$XDG_RUNTIME_DIR` (else the temp dir) at start and removes it at
exit, so the runtime or temp dir must be writable too. A read-only or
throwaway keystore loses those on restart.

**Secrets.** `$WIRES_HOME` picks the keystore (else
`$XDG_CONFIG_HOME/wires`, else `~/.config/wires`), and every command takes
its node key from there, except that `serve` takes `--node-seed` or
`--node-seed-file` ahead of it. Don't pass `--node-seed` on the command line:
argv leaks through `ps`, and `serve` execs children. Keep the node key as a
file, either in the keystore or mounted and read with `--node-seed-file`.
The root key (`root.seed`) stays on the admin's machine, and a host never
holds it.

**Kubernetes** (untested): a persistent, writable `$WIRES_HOME` (a PVC or
a StatefulSet volume), `replicas: 1` (the node key is the host's address, so
replicas sharing a key are not a load balancer), and no `Service` or
`Ingress`. For availability, give the service more hosts, each with its own
key: calls spread at random across them, and a caller moves to the next
when one can't be reached. More hosts are more capacity only for a service
that keeps no state between calls: hosts share nothing but the policy, so a
service's memory, its disk and its push queue stay on each host.

## Running a directory

A network needs a **directory**: hosts, callers and the gateway get the
policy from one. It holds the newest signed policy (`directory.redb`), signs
a freshness timestamp for it every 5 minutes, takes each admin publish,
hands each host the whole policy and then every change by subscription, and
hands each caller its view (the services that caller may use). It never
decides a call: hosts decide from their own copy, so calls keep working with
every directory down. Signing in (for the view), listing services, and
edits and removals spreading need one.

Where to run it:

- **On a host.** When the policy lists a host's node (`wires directory add
  <label>=<node id>`), its `wires serve` runs the directory on the same
  endpoint. The simplest small network: one always-on host that is also the
  directory. A host listed while it runs starts the directory at its next
  restart.
- **Alone**, with `wires directory serve` on a node that hosts nothing (no
  `host.json`), for example on the gateway machine, with its own keystore
  (the gateway never uses its own node as its directory;
  `deploy/gateway/compose.yml` has an optional `wires-directory` service
  for this). It refuses the admin's keystore and a node the policy (or the
  network string) doesn't list.

A new directory starts **empty** and takes its first policy from the
admin's next publish:

```bash
wires id                                   # on the directory node
wires directory add dir1=<id>              # admin: prints the node's next steps
wires network                              # admin: the string now names it, if it is one of the first two
wires join <network>                       # on the directory node
wires directory serve                      # or `wires serve host.json` on a host; waits for the first publish
wires policy push                          # admin
```

No step fails by design: until a directory has taken a publish from the
admin, an edit that reaches none says so and exits 0. After that, a new
directory added to a running network gets the policy from the edit that
lists it (`directory add` publishes to it) or from a replica.

Run two, on different machines: each follows the other as a replica, so one
that missed an edit catches up, and hosts and callers fail over between
them. The admin publishes every edit to all of them (an edit that reaches
none exits 1, once one has taken a publish). `--max-subscribers` (default
4,096) caps each of two pools of subscriptions one directory serves at once:
hosts and other directories in one, and long-running callers' views
(`wires mcp`, gateway sessions, `wires inbox --wait`) in the other, so
callers can't crowd out hosts. One person may hold at most 16 view
subscriptions, and each ends when its ID token expires (the client
subscribes again with a fresh one). Its
keystore must persist: losing `directory.redb` loses nothing (the admin's
`wires policy push`, or a replica, restores it), but the node key is what
the policy lists.

**When no directory answers**, hosts keep deciding from the policy they hold
under the default `lenient` freshness, and say so in their trace. Under
`wires policy settings --freshness strict` a host refuses every call once
the last freshness timestamp it holds lapses (15 minutes by default,
`--fresh-secs`), so a ban is honoured everywhere within that time or nothing
is served.

## Reachability and discovery

Three layers, most self-contained first:

- **A local hints file.** `$WIRES_HOME/hints`: one line per node, `<node
  id> <ip:port>…`. A running `serve` writes its own line to `run/hint`;
  copy it into the callers' and the admin's hints. Every endpoint `wires`
  binds uses it. The addresses are unsigned hints: iroh still authenticates
  the peer's key, so a wrong address can only fail to connect.
- **Self-hosted relay**: run upstream
  [`iroh-relay`](https://docs.rs/iroh-relay) and pass `--relay-url` to
  `serve`, `directory serve` and `gateway`, for NAT traversal between
  egress-only peers that can both reach it. Keep it one logical endpoint: two
  peers only rendezvous on the *same* relay. A caller's commands take no relay
  flag: a host publishes its home relay with its address through n0
  discovery, and the caller dials the relay that address names, so without
  n0 DNS a caller behind NAT has no way to reach a host on your relay.
- **n0 DNS discovery and relays** (the default): resolves a node id to
  addresses, but needs outbound internet.

For a private or air-gapped network, run your own relay for hosts, directories
and the gateway, and give callers a hints line for each host and directory
they must reach: with no n0 DNS, a caller reaches only addresses its hints
file names, since it can't be told to use your relay.

## Provisioning and removal

- **Add a person:** give them the network string; they run `wires login
  <network>`. Whether they may call anything is the policy's roles: add a
  role matcher that admits them (`wires role set`), or rely on one that
  already does (`*@example.com`). Nothing on the admin's side happens per
  machine.
- **Add a host or directory:** it runs `wires join <network>` and sends its
  node id; the admin names it once, `--host <label>=<id>` or `wires
  directory add <label>=<id>`. The root key never leaves the admin's
  machine.
- **Remove a person:** `wires remove alice@example.com`. A person ban in a
  new signed policy, published to the directories, with no restart. `serve`
  re-reads its policy once per connection, so from the moment a host has the
  new policy, that person's next call there, from any machine, is refused:
  exit `77`, `wires: denied by host: not admitted to this network: no role
  in this network matches <email>, or you were removed: ask your admin` on
  their stderr. Directories refuse them a view. A host that is a directory
  has the new policy at once; any other host follows a directory's
  subscription and has it within a second. Disabling the account at the IdP also cuts them
  off, within one token lifetime. There is no shared key to rotate.
- **Remove a machine:** `wires remove <label>` takes a host or directory
  out: a node ban, and the node is dropped from every service's hosts and
  from the directories. Callers whose view predates the removal can still
  dial it until their view is refreshed (see
  [usage.md § Known trade-offs](usage.md#known-trade-offs)).
- **Undo:** `wires restore <email|label>`. Bans don't expire otherwise. A
  restored node is not put back into services or directories: add it again.
- **Expiry:** the signed policy expires after its `--policy-ttl` (default
  `90d` from the last edit), and nothing renews it automatically. Any admin
  edit signs a fresh one, never shortening its life.
- **Rotate a node key:** the node id changes with the key: name the new id
  with a new label, then `wires remove` the old one.

## A web gateway

`wires gateway` serves the services each signed-in user may call as a remote
MCP server (Streamable HTTP, OAuth 2.1), so a team can bring the web clients
it already uses: Claude's custom connectors on the web, the MCP Inspector.
It is one node that calls **as** each web user:

1. The user adds `https://<gateway>/mcp` as a connector. The client finds
   the gateway's OAuth metadata, registers (Client ID Metadata Document, or
   DCR), and opens the gateway's consent page.
2. The gateway sends the user to the IdP with `nonce` = the hash of **the
   gateway's** node key (as `wires login` does for a caller's own node).
3. On every call, the gateway presents that user's ID token in the session
   `Hello`. The host verifies the IdP's signature and the nonce against the
   dialing node (the gateway) under the policy's trusted issuers, checks the
   policy, and runs the call with the user as the verified principal (its
   log line names the gateway's node as the caller node). The service gets
   that user's ID token, whose `aud` is the gateway's OAuth client.

What this changes:

- **The gateway holds every signed-in user's live identity.** A token bound
  to the gateway's key is useless to any other node, but the gateway can use
  it for anything that user may call until it expires (about an hour). Trust
  the gateway like any service that holds your users' sessions.
- **Sessions last as long as the Google ID token.** Google omits `nonce` when
  it refreshes a token, so a refreshed token couldn't be bound to the
  gateway. The gateway issues no refresh tokens; the client reconnects (one
  click with a live Google session).
- **Only the user's identity admits a web user.** The gateway holds no
  credential of its own and is in no role: it offers a service only if a
  role matches the web user's own verified identity. A user no role
  matches, or whom the policy lets call nothing, is refused at sign-in.
- Push and the inbox aren't offered through the gateway (an `inbox` MCP
  tool is designed, parked: [card 31](board/backlog/31-inbox-delivery.md)).

To run one:

1. **An OAuth client** at the IdP of type *Web application* (Google Cloud
   Console → Credentials), with the redirect URI
   `https://<gateway>/oauth/callback`.
2. **Hosts trust it:** the admin adds its client id to the audiences the
   policy accepts from Google (`wires issuer set https://accounts.google.com
   --client-id <the CLI's client id> --audience <the CLI's client id>
   --audience <the gateway's client id>`). A host whose `host.json` narrows
   `identity.issuers[].audiences` must list it there too.
3. **The gateway joins** like a host: `wires join <network>`, with a network
   string that names a directory. It asks a directory for each signed-in
   user's view (and follows it for as long as the session lives), so it
   refuses to start when its network string names none, and it never uses
   its own node. The policy's roles decide what each user sees.
4. **TLS in front.** The gateway speaks plain HTTP. `deploy/gateway/` runs
   it next to `cloudflared` on a Cloudflare Tunnel whose ingress routes the
   public host to `http://wires-gateway:8080`. Turn Cloudflare's Browser
   Integrity Check off for that host: MCP clients register and exchange
   tokens from servers, with non-browser user agents.

```bash
cd deploy/gateway && cp .env.example .env    # client id/secret, tunnel token
docker compose build
docker compose run --rm wires-gateway join <network>    # the admin's `wires network`
docker compose up -d
curl https://<gateway>/.well-known/oauth-protected-resource/mcp
```

The keystore volume holds the node key, the network string
(`network.json`), the key that signs DCR client ids
(`gateway-client-key`), and the live sessions (`gateway-sessions.json`,
keyed by token hash, so a restart signs no one out). Users' views are held
in memory and fetched again after a restart.

To run the directory on the same machine, as its own node, start the
optional service with its own keystore volume, have the admin list it, and
join it as in [Running a directory](#running-a-directory):

```bash
docker compose --profile directory run --rm wires-directory id     # → the admin: wires directory add <label>=<id>
docker compose --profile directory run --rm wires-directory join <network>
docker compose --profile directory up -d
```

Then the admin runs `wires policy push` if this is the network's first
directory, and the gateway joins with the string `wires network` prints
once the directory is listed.
