# Deploying wires

Patterns for running wires beyond one machine: images, hosts, and a
self-hosted relay. For the command reference and the walkthrough see the
[README](../README.md); for the recorded two-machine run see
[demo.md](demo.md); for tests see [testing.md](testing.md).

## What you deploy

| Piece | Command | Listens? | Container image |
| ----- | ------- | -------- | --------------- |
| **Host** (runs the CLIs) | `wires serve host.json` | No TCP listener, no firewall port opened; binds UDP for QUIC | compose your own: `wires` plus the CLIs it exposes |
| **Caller** (the agent side) | `wires call`, or `wires mcp` for MCP-only clients | No TCP listener | `//wires:image` |
| **Observer** | `wires watch` | No TCP listener | `//wires:image` |
| **Relay** (optional rendezvous) | `relay` | **Yes**, HTTP | `//relay:image` |

A host dials out (to peers directly, or through a relay), and unauthenticated
peers are refused at the QUIC handshake. The relay is the one piece that
listens: it's the shared rendezvous point, and it forwards packets it can't
read.

## Building and loading the images

The OCI images cross-compile to a distroless Linux base via the Zig CC
toolchain:

```bash
bazel build //relay:image //wires:image          # build the images
bazel run   //relay:image.load                    # docker load the relay locally
docker run --rm -p 3340:3340 relay:latest         # (the tag is stamped at build time)
```

`rust_image` (see `tools/oci/rust_image.bzl`) emits the image filegroup, a
`<name>.load` target (`docker load`), and stamped `repo_tags`. To push to a
registry, `docker tag` + `docker push` after a load, or add an `oci_push` target.

The x86_64 cross-compile from macOS is currently broken (curve25519-dalek's
SIMD backend; see card 08's notes). Card 08 built natively on the Linux host
instead.

A **host** image must also contain the binaries its `host.json` execs
(`sqlite3`, `gh`, …), so build an app-specific image that layers `wires` plus
your tools. `//wires:image` is the starting point.

## Running a host

A host is a member like any other. It joins once, then runs `serve`:

```bash
wires id                       # send this to the admin
wires join <token>             # the admin's `wires invite <id>` output
wires serve --check host.json  # validate; print who may run what
wires serve host.json          # prints "share to bootstrap: <ticket>" for the admin's next invite
```

Run `serve` under a process supervisor (card 08 used `systemd-run --user`),
from the directory that relative paths in `host.json` commands resolve
against.

**The keystore must be writable and must persist.** `$WIRES_HOME` holds the
host's node key and credentials, and the host rewrites them at runtime: every
`wires invite` and `wires remove` re-keys the channel, and the host adopts the
new roster head, proof directory and channel key from the channel. It also
holds the channel log (`topics/`) and the control socket (`run/`). A read-only
or throwaway keystore loses those on restart.

**Secrets.** Every secret input resolves **flag → environment variable →
`--…-file` → keystore**. Don't pass `--node-seed` on the command line or in
the environment: argv leaks through `ps`, and `serve` execs children. Keep the
node key as a file, either in the keystore or mounted and read with
`--node-seed-file`. The root key (`root.seed`) stays on the admin's machine,
and a host never holds it.

**Kubernetes.** The manifests that used to be here predated `host.json` and
assumed a read-only keystore, so they were cut. A manifest needs a
persistent, writable `$WIRES_HOME` (a PVC or a StatefulSet volume),
`replicas: 1` (the node key is the host's address, so replicas sharing a key
are not a load balancer), and no `Service` or `Ingress`. We haven't tested
one yet.

## Self-hosted relay on Kubernetes

Unlike a host, the relay **is** a server: it listens on HTTP and is the
shared rendezvous both peers connect to. So it gets a `Service`.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: wires-relay }
spec:
  replicas: 1                          # see "one logical relay" below
  selector: { matchLabels: { app: wires-relay } }
  template:
    metadata: { labels: { app: wires-relay } }
    spec:
      containers:
        - name: relay
          image: registry.example.com/relay:<tag>     # //relay:image
          args: ["--listen=0.0.0.0:3340"]
          ports: [{ containerPort: 3340 }]
          env: [{ name: RUST_LOG, value: "info" }]
          securityContext: { runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false }
---
apiVersion: v1
kind: Service
metadata: { name: wires-relay }
spec:
  selector: { app: wires-relay }
  ports: [{ port: 3340, targetPort: 3340 }]
```

Nodes point at it with `--relay-url http://wires-relay.<ns>.svc:3340`.

- **Plain HTTP / TLS.** The relay runs plain HTTP (no cert). Terminate TLS at
  an Ingress/LoadBalancer for external clients (then use an `https://` relay
  URL), or keep it plain inside a trusted network.
- **One logical relay.** Two peers can only rendezvous if they reach the *same*
  relay, so keep the relay a single logical endpoint: `replicas: 1`, or a
  `Service` with session affinity / a stable external address. It is stateless
  and keyless, so failover is just "restart it", but don't round-robin two
  peers onto different replicas.

## Reachability and discovery

Three layers, most self-contained first:

- **Addresses from the channel.** A host's announcement on the channel
  carries its direct addresses and relay URL, so a caller that has read it
  dials without a discovery service. The addresses are unsigned hints: iroh
  still authenticates the peer's key, so a wrong address can only fail to
  connect.
- **Self-hosted relay** (`--relay-url` on `serve`, `call`, `watch` and
  `login`) for NAT traversal between egress-only peers that can both reach it.
- **n0 DNS discovery and relays** (the default): resolves a node id to
  addresses, but needs outbound internet.

For a private or air-gapped network, run your own relay so nothing depends on
n0.

## Provisioning and revocation

- **Add a member:** the joiner runs `wires id`; the admin runs
  `wires invite <id> --name <label>` and hands back the token; the joiner runs
  `wires join <token>`. The root key never leaves the admin's machine.
- **Remove a member:** `wires remove <label>`. The re-key goes out on the
  channel, and hosts adopt it with no import and no restart. `serve` re-reads
  the roster head once per connection, so the removed member's next call is
  refused: exit `77`, `wires: denied by responder: <reason>` on its stderr,
  and a `✗` record on the channel.
- **Expiry:** memberships and roster heads expire after `--ttl` (default
  `30d`), and nothing renews them yet. Re-issue with `wires invite <id>`.
- **Rotate a node key:** the node id changes with the key, so remove the old
  id and invite the new one.
