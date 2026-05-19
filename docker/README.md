# Docker deploy for `wires-host`

This directory packages `wires-host` as a single-service Docker Compose
deployment for a dedicated Linux host (the project's reference deploy
target is `workbench`). State persists in a named Docker volume; the
container shares the host's network namespace so that Tailscale Funnel
(running on the host) can publish the ticket HTTP page over public HTTPS.

## First-time install on the deploy host

Prerequisites on the host:

- Docker Engine + Compose v2 installed.
- Tailscale installed and logged in (`sudo tailscale up`).
- Funnel and HTTPS certs enabled for this node in the tailnet admin panel
  (one-time toggle at https://login.tailscale.com/admin/dns and
  https://login.tailscale.com/admin/settings/funnel).

Then:

```bash
git clone <repo-url> ~/src/wires
cd ~/src/wires

# 1. Seed the wires-mcp config (one-time per host).
cp docker/wires-mcp.toml.example docker/wires-mcp.toml
${EDITOR:-nano} docker/wires-mcp.toml   # edit public_url to your Funnel hostname

# 2. Build and start both services. Polls /:10000 (wires-host) and /_health
#    (wires-mcp) to confirm both are up.
./docker/deploy.sh

# 3. Publish both services via Tailscale Funnel.
./docker/funnel.sh up all
```

The Funnel URLs are printed by `funnel.sh`. wires-host's ticket page is at
`https://<workbench>:10000/`; wires-mcp's OAuth surface is at
`https://<workbench>/` (Funnel `:443`, no port in the URL).

> **Reclamation warning:** `funnel.sh up all` overwrites any prior `:443`
> Funnel mapping on this node. If something else was on `:443`, it loses
> its public Funnel exposure. Run `tailscale funnel status` first to see
> what's there.

### Port convention

| Local listen | Service | Funnel public |
|---|---|---|
| `127.0.0.1:10000` | wires-host ticket | Funnel `:10000` |
| `127.0.0.1:10001` | wires-mcp (HTTPS via Funnel) | Funnel `:443` |
| `127.0.0.1:10002+` | reserved for future wires-* services | tbd |

Both services share `network_mode: host`, so the local ports above are
ports on the deploy host itself; pick non-conflicting locals when adding
new services. Tailscale Funnel is independently limited to three public
ports — `443`, `8443`, `10000` — so adding a third wires service means
either sharing one of those slots via a sub-path or moving an existing
mapping. The `SERVICES` array at the top of `docker/funnel.sh` is the
single source of truth for which wires service holds which Funnel slot.

## Subsequent rollouts

```bash
./docker/deploy.sh                  # pulls, rebuilds, recreates, verifies
./docker/deploy.sh --no-pull        # deploy uncommitted local changes
./docker/deploy.sh --no-verify      # skip the HTTP healthcheck polls on :10000 and :10001
```

The named volume `wires-host-data` carries `iroh.secret` and all tenant
state through container recreates, so the host's `EndpointId` (and thus
the published ticket) is stable across rollouts.

## Remote invocation

To deploy from a developer machine without SSH'ing first:

```bash
ssh workbench 'bash -lc "cd ~/src/wires && ./docker/deploy.sh"'
```

## Inspecting the running host

```bash
# Tail logs
docker compose -f docker/compose.yaml logs -f wires-host

# Re-print the host ticket
docker compose -f docker/compose.yaml exec wires-host \
  wires-host --data-dir /data ticket --no-qr

# Open a shell in a one-off container (useful for poking the volume)
docker run --rm -it -v wires-host-data:/data --entrypoint /bin/sh \
  debian:bookworm-slim
```

## Backup and restore

Back up the data volume to a tarball:

```bash
docker run --rm \
  -v wires-host-data:/src \
  -v "$PWD:/out" \
  debian:bookworm-slim \
  tar -C /src -czf "/out/wires-host-$(date +%F).tgz" .
```

Same recipe for wires-mcp:

```bash
docker run --rm \
  -v wires-mcp-data:/src \
  -v "$PWD:/out" \
  debian:bookworm-slim \
  tar -C /src -czf "/out/wires-mcp-$(date +%F).tgz" .
```

The wires-mcp volume holds the JWT signing key (`token_signing.ed25519`),
gateway OAuth state (`gateway.redb`), and per-user wires agent data
(`users/<root>/`). Treat its backups as security-sensitive — anyone with
the signing key can mint valid wires-mcp JWTs.

Restore the same tarball into a fresh volume:

```bash
docker volume create wires-host-data
docker run --rm \
  -v wires-host-data:/dst \
  -v "$PWD:/in" \
  debian:bookworm-slim \
  tar -xzf /in/wires-host-YYYY-MM-DD.tgz -C /dst
```

After restoring, `./docker/deploy.sh` to start against the restored state.

## Tailscale Funnel

```bash
./docker/funnel.sh up all   # publish all wires services (host + mcp)
./docker/funnel.sh up host  # just wires-host (Funnel :10000)
./docker/funnel.sh up mcp   # just wires-mcp  (Funnel :443)
./docker/funnel.sh status   # see current mappings
./docker/funnel.sh down mcp # remove only the wires-mcp mapping; host stays up
./docker/funnel.sh down all # remove every wires-* Funnel mapping on this node
```

The script wraps `tailscale funnel`; it does not manage admin-policy
permissions or HTTPS cert provisioning, both of which are tailnet-wide
toggles done once in the Tailscale admin panel.

Funnel slot assignments are baked into the script's `SERVICES` catalog at
the top of `docker/funnel.sh`. Adding a third wires-* service later means
adding one line to that array. Tailscale Funnel itself supports only three
public ports — `443`, `8443`, `10000` — so adding services means either
sharing a port via sub-paths or moving an existing service.

## Troubleshooting

- **`Cannot connect to the Docker daemon`** — start Docker (or your VM
  runtime). `deploy.sh` cannot continue without it.
- **`wires-host` poll times out** — check `docker compose logs wires-host`
  for a bind error on `0.0.0.0:10000` (another process is using the port)
  or an iroh endpoint failure.
- **`wires-mcp` poll times out** — check `docker compose logs wires-mcp`
  for a bind error on the address in `wires-mcp.toml`, or a TOML parse
  error if `public_url` was edited incorrectly.
- **`docker/wires-mcp.toml is missing`** — first-deploy step skipped.
  `cp docker/wires-mcp.toml.example docker/wires-mcp.toml`, edit
  `public_url`, re-run `./docker/deploy.sh`.
- **Funnel URL returns 502** — the matching container is down. Confirm
  with `curl http://127.0.0.1:10000/` (wires-host) or
  `curl http://127.0.0.1:10001/_health` (wires-mcp).
- **wires-mcp public_url changed; clients see 401/invalid issuer** — the
  TOML's `public_url` is part of every issued JWT. If you change it, all
  outstanding tokens become invalid; clients must re-authorize.
- **EndpointId changed after redeploy** — the named volume was destroyed.
  Restore from backup if available; otherwise every paired tenant must
  re-pair against the new ticket.
