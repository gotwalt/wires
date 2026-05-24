# Deploying wires

Patterns for running wires in production — containers, Kubernetes, and a
self-hosted relay. For the command reference and the local walkthrough see the
[README](../README.md); for tests see [testing.md](testing.md).

## What you deploy

| Piece | Binary | Inbound port? | Container image |
| ----- | ------ | ------------- | --------------- |
| **Responder** (the tool host) | `wires serve` | **No** — egress-only | compose your own (wires + the tool/MCP binary) |
| **Dialer / shim** (the agent side) | `wires connect` | No — egress-only | `//wires:image` (self-contained) |
| **Relay** (rendezvous) | `relay` | **Yes** — HTTP | `//relay:image` (self-contained) |

The defining property: a **responder has no inbound port**. It dials out to a
relay and is reachable only by node id + a valid grant. The **relay** is the one
piece that *does* listen — it's the shared rendezvous point.

## Building and loading the images

The OCI images cross-compile to a distroless Linux base (via the Zig CC
toolchain) for both `arm64` and `x86_64`:

```bash
bazel build //relay:image //wires:image          # build the images
bazel run   //relay:image.load                    # docker load the relay locally
docker run --rm -p 3340:3340 relay:latest         # (tag is stamped from git)
```

`rust_image` (see `tools/oci/rust_image.bzl`) emits the image filegroup, a
`<name>.load` target (`docker load`), and git-stamped `repo_tags`. To push to a
registry, `docker tag` + `docker push` after a load, or add an `oci_push` target.

The **relay** and **dialer** images are self-contained. A **responder** image
must also contain the binary it execs (`rg`, an MCP server, …), so build an
app-specific image that layers `wires` plus your tool — `//wires:image` is the
starting point, or copy the `rust_image` pattern with both binaries in the tar.

## Secrets and the keystore in Kubernetes

`wires` resolves every secret/CRL input as **flag → env → `--…-file` → keystore**
(`~/.config/wires`, overridable via `$WIRES_HOME`). In Kubernetes this maps
cleanly onto **files**:

- the **node key** → a `Secret`, mounted as a file, read with `--node-seed-file`
  (do **not** use `--node-seed`/env: argv leaks via `ps`, and `serve` execs a
  child that inherits its environment);
- the **trust root** (`--trust-root`) and **scope** → public config in a
  `ConfigMap`;
- the **CRL** → a `ConfigMap` file, read with `--crl-file` (edit + `kubectl
  apply` to revoke);
- the **root signing key** and **grant minting** stay **off-cluster** (operator
  laptop / HSM); the cluster never holds `root.seed`.

## Responder on Kubernetes (egress-only)

```yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: wires-config }
data:
  trust-root: "<ROOT_ID hex>"      # public — the root id grants are verified against
  scope: "mcp.myserver"
  crl.json: '{"revoked":[]}'       # re-apply to revoke
---
apiVersion: v1
kind: Secret
metadata: { name: wires-node-key }  # the pod's private identity == its address
stringData:
  node.seed: "<32-byte ed25519 seed hex>"   # ideally synced from Vault/KMS
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: wires-responder }
spec:
  replicas: 1                        # identity is the address — see "scaling" below
  selector: { matchLabels: { app: wires-responder } }
  template:
    metadata: { labels: { app: wires-responder } }
    spec:
      automountServiceAccountToken: false
      containers:
        - name: wires
          image: registry.example.com/my-responder:<tag>   # wires + the tool binary
          args:
            - "serve"
            - "--node-seed-file=/etc/wires/node.seed"
            - "--trust-root=$(TRUST_ROOT)"
            - "--scope=$(SCOPE)"
            - "--crl-file=/etc/wires/crl.json"
            - "--relay-url=http://wires-relay.wires.svc:3340"   # see relay below
            - "--"
            - "my-mcp-server"
            - "--config=/etc/mcp/config.toml"
          env:
            - { name: TRUST_ROOT, valueFrom: { configMapKeyRef: { name: wires-config, key: trust-root } } }
            - { name: SCOPE,      valueFrom: { configMapKeyRef: { name: wires-config, key: scope } } }
          volumeMounts:
            - { name: node-key, mountPath: /etc/wires/node.seed, subPath: node.seed, readOnly: true }
            - { name: crl,      mountPath: /etc/wires/crl.json,  subPath: crl.json,  readOnly: true }
          securityContext:
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            allowPrivilegeEscalation: false
          livenessProbe:                       # no HTTP port to probe
            exec: { command: ["/bin/sh", "-c", "pgrep -x wires"] }
      volumes:
        - { name: node-key, secret:    { secretName: wires-node-key, defaultMode: 0400 } }
        - { name: crl,      configMap: { name: wires-config, items: [{ key: crl.json, path: crl.json }] } }
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: wires-responder }
spec:
  podSelector: { matchLabels: { app: wires-responder } }
  policyTypes: [Ingress, Egress]
  ingress: []                          # nothing reaches it on any port
  egress:
    - {}                               # tighten to DNS + the relay in practice
```

There is deliberately **no `Service` and no `Ingress`** — nothing inbound.

**Scaling caveat.** A node id *is* the address, and tickets embed the target
node id, so identity must be stable (the `Secret` gives that across restarts —
no PVC needed). But that means `replicas: 1` is intentional: N replicas sharing
one `node.seed` advertise the *same* node id, which is not a load balancer.
A wires responder is naturally a single-identity workload; fan a capability out
by running several responders, each with its own key and a ticket per replica.

**The child's secrets** (DB password, API key) are mounted into the same pod and
**never leave it** — the agent only ever holds a capability to *reach* the
responder.

## Dialer / agent side

The agent (Claude Code, a job, another pod) runs `wires connect` with **its
own** node key — its own `Secret` if in-cluster — and the ticket it was issued:

```yaml
args: ["connect",
       "--node-seed-file=/etc/wires/node.seed",
       "--relay-url=http://wires-relay.wires.svc:3340",
       "--ticket=$(TICKET)"]
```

It dials out and reaches the responder across any boundary — different
namespace, cluster, or cloud — with no VPC peering and no inbound exposure on
either side. `//wires:image` is self-contained for this use.

## Self-hosted relay on Kubernetes

Unlike the responder, the relay **is** a server: it listens on HTTP and is the
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

- **Plain HTTP / TLS.** The relay runs plain HTTP (no cert) — terminate TLS at
  an Ingress/LoadBalancer for external clients (then use an `https://` relay
  URL), or keep it plain inside a trusted network.
- **One logical relay.** Two peers can only rendezvous if they reach the *same*
  relay, so keep the relay a single logical endpoint: `replicas: 1`, or a
  `Service` with session affinity / a stable external address. It is stateless
  and keyless, so failover is just "restart it" — but don't round-robin two
  peers onto different replicas.

## Reachability and discovery

Three layers, most-self-contained first:

- **Direct addresses in the ticket** (air-gapped friendly). At grant time,
  embed where the responder is reachable:
  `wires grant … --addr <ip:port> [--addr …] [--relay-url <url>]`. The dialer
  uses these directly and needs **no discovery service**. The responder logs its
  node id and bound sockets at startup; combine that port with the responder's
  reachable IP / Service / LoadBalancer address. These hints are unsigned —
  iroh still authenticates the peer to the target's key, so a wrong address only
  fails to connect.
- **Self-hosted relay** (`--relay-url`) for NAT traversal / holepunch between
  egress-only peers that can both reach the relay.
- **n0 DNS discovery** (the default) when a ticket carries no `--addr`: resolves
  a node id → addresses, but needs outbound internet.

For a private / air-gapped cluster, prefer **`--addr` + a self-hosted relay**
so nothing depends on n0.

`pair` is not implemented; mint grants out-of-band with `wires grant` and
distribute tickets (e.g. as a `Secret` in the agent's namespace).

## Provisioning and rotation

- **Issue:** on the operator's machine, `wires grant --subject <agent-id>
  --target <responder-id> --scope <s> --ttl <secs>` → hand the ticket to the
  agent. The root key never leaves that machine.
- **Revoke:** edit the responder's CRL `ConfigMap` (or `wires revoke
  --crl-file <path>` against a synced copy) and `kubectl apply`; the projected
  file updates. Pair short TTLs with the CRL so revocation is bounded even
  without a restart.
- **Rotate a node key:** write a new `Secret`, re-issue tickets/grants for the
  new node id (the id changes with the key).
