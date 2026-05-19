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
./docker/deploy.sh                  # builds, starts, prints the ticket
./docker/funnel.sh up               # publishes the ticket page on Funnel :10000
```

The Funnel URL is printed by `funnel.sh up` (look for the line under
`Funnel on:`). Visiting it returns the host's ticket page; agents and
operators use the base64 ticket to pair against this host.

### Port convention

`wires-host` listens on `127.0.0.1:10000` inside the container (overridden
from the binary's default `:8089` via `compose.yaml`). The `10000`+ range
is reserved for wires services going forward — e.g. `wires-mcp` is
planned for `:10001`. This sidesteps privileged ports entirely and gives
each wires service a predictable home.

Tailscale Funnel is independently limited to three public ports — `443`,
`8443`, `10000`. `funnel.sh` defaults to publishing on `:10000` because
`:443` is usually already in use on a shared host; override via
`WIRES_FUNNEL_HTTPS_PORT` if you need a different one.

## Subsequent rollouts

```bash
./docker/deploy.sh                  # pulls, rebuilds, recreates, verifies
./docker/deploy.sh --no-pull        # deploy uncommitted local changes
./docker/deploy.sh --no-verify      # skip the HTTP healthcheck poll (e.g. when running with `--no-http`)
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
./docker/funnel.sh up      # publish 127.0.0.1:10000 on Funnel :10000
./docker/funnel.sh status  # see current mapping
./docker/funnel.sh down    # remove just this script's Funnel mapping
```

The script wraps `tailscale funnel`; it does not manage admin-policy
permissions or HTTPS cert provisioning, both of which are tailnet-wide
toggles done once in the Tailscale admin panel.

Override the defaults with env vars when needed:

```bash
WIRES_FUNNEL_HTTPS_PORT=443 ./docker/funnel.sh up    # public Funnel port (443, 8443, or 10000)
WIRES_HOST_HTTP_PORT=10000  ./docker/funnel.sh up    # local port to forward to (matches compose.yaml)
WIRES_FUNNEL_PATH=/host/    ./docker/funnel.sh up    # serve under a sub-path
```

`funnel.sh down` removes only the mapping for the configured
`(WIRES_FUNNEL_HTTPS_PORT, WIRES_FUNNEL_PATH)` pair, not every Funnel rule
on the node — so other services using Funnel on this host stay up.

## Troubleshooting

- **`Cannot connect to the Docker daemon`** — start Docker (or your VM
  runtime). `deploy.sh` cannot continue without it.
- **Ticket HTTP poll times out** — check `docker compose logs wires-host`
  for a bind error on `0.0.0.0:10000` (another process is using the port)
  or an iroh endpoint failure.
- **Funnel URL returns 502** — the container is down, or its HTTP server
  was disabled. Confirm with `curl http://127.0.0.1:10000/` on the host.
- **EndpointId changed after redeploy** — the named volume was destroyed.
  Restore from backup if available; otherwise every paired tenant must
  re-pair against the new ticket.
