# wires-host Docker deploy — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package `wires-host` as a Docker Compose service that runs persistently on a single Linux host, with operator scripts for build+rollover and Tailscale Funnel management.

**Architecture:** A new top-level `docker/` directory contains a four-stage cargo-chef Dockerfile (chef → planner → builder → runtime on `debian:bookworm-slim`), a Compose file that runs the binary with `network_mode: host` and a named data volume, a `deploy.sh` build+rollover script, a `funnel.sh` Tailscale Funnel helper, and a README. No code changes to `wires-host`; the compose-level `stop_signal: SIGINT` works around the binary's `SIGINT`-only shutdown handler.

**Tech Stack:** Docker (Compose v2), `lukemathwalker/cargo-chef:latest-rust-1-bookworm`, `debian:bookworm-slim` runtime, bash, Tailscale CLI.

**Spec:** `docs/superpowers/specs/2026-05-18-wires-host-docker-deploy-design.md`

---

## File structure

All new files live under `docker/` at the repo root.

| Path | Responsibility |
|---|---|
| `docker/Dockerfile` | Multi-stage build that produces `wires-host:local` from the workspace. |
| `docker/Dockerfile.dockerignore` | Prunes the build context (excludes `target/`, `Wires/`, etc.). |
| `docker/compose.yaml` | Single-service compose file with host networking + named volume. |
| `docker/deploy.sh` | Operator script: pull → build → up → verify → print ticket. |
| `docker/funnel.sh` | Tailscale Funnel helper: `up` / `down` / `status` subcommands. |
| `docker/README.md` | Walkthrough: first-boot, Funnel, rollouts, backup. |

No existing files are modified.

---

## Pre-flight: verify Docker is available

- [ ] **Step 1: Check Docker daemon is reachable**

Run: `docker version`
Expected: client + server version block. If the server section says "Cannot connect to the Docker daemon," start Docker Desktop / OrbStack / your daemon before proceeding.

- [ ] **Step 2: Check Compose v2 is available**

Run: `docker compose version`
Expected: `Docker Compose version v2.x` or newer. If `docker compose` is not recognized but `docker-compose` is, install Compose v2 first — the scripts in this plan use the v2 `docker compose` (space, not hyphen) form.

---

## Task 1: Add `Dockerfile.dockerignore`

**Why first:** Without this, the build context includes `target/` (several GB) and the `Wires/` Xcode app, both of which slow `docker build` and force cache invalidation on unrelated changes.

**Files:**
- Create: `docker/Dockerfile.dockerignore`

- [ ] **Step 1: Create the file**

```
# docker/Dockerfile.dockerignore
target/
data/
Wires/
.git/
docs/
*.md
.DS_Store
.claude/
```

- [ ] **Step 2: Verify the build context shrinks**

Run from the repo root:

```bash
docker build -f docker/Dockerfile --target nonexistent .. 2>&1 | head -5
```

You don't have a Dockerfile yet, so the build will fail — but watch the `transferring context:` line printed by BuildKit before the failure. It should be in the low MBs (workspace source), not GBs. If it's huge, something in `Dockerfile.dockerignore` is wrong.

Skip this step if BuildKit isn't available; the real verification happens in Task 2.

- [ ] **Step 3: Commit**

```bash
git add docker/Dockerfile.dockerignore
git commit -m "docker: add Dockerfile.dockerignore to prune the build context"
```

---

## Task 2: Write the Dockerfile

**Files:**
- Create: `docker/Dockerfile`

- [ ] **Step 1: Create the Dockerfile**

```dockerfile
# docker/Dockerfile
# syntax=docker/dockerfile:1.7

# --- chef: provides cargo-chef on Debian Bookworm with stable Rust ---------
FROM lukemathwalker/cargo-chef:latest-rust-1-bookworm AS chef
WORKDIR /app

# --- planner: produces a recipe describing every dependency ----------------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# --- builder: pre-builds deps from the recipe, then builds wires-host ------
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cook only the deps required by wires-host; this layer is cached as long
# as recipe.json is unchanged (i.e. workspace deps haven't shifted).
RUN cargo chef cook --release --locked -p wires-host --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p wires-host

# --- runtime: minimal Debian with the binary and a non-root user -----------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /data --shell /usr/sbin/nologin wires
COPY --from=builder /app/target/release/wires-host /usr/local/bin/wires-host
USER wires
WORKDIR /data
EXPOSE 8089/tcp
ENTRYPOINT ["wires-host"]
CMD ["--data-dir", "/data"]
```

- [ ] **Step 2: Build the image**

Run from the repo root:

```bash
docker build -f docker/Dockerfile -t wires-host:local .
```

This will be slow on first run — cargo-chef cooks the entire dep tree (iroh, redb, rustls, …). Subsequent rebuilds after a code-only change should be much faster.

Expected: ends with `naming to docker.io/library/wires-host:local`. If `cargo chef cook` fails because Rust 1.95 features are missing, the base image's bundled toolchain is too old — verify `rust-toolchain.toml` still says `channel = "stable"` (it pulls the current stable via rustup at first cargo invocation).

- [ ] **Step 3: Verify the binary runs in the container**

```bash
docker run --rm wires-host:local --help
```

Expected: clap's help output for `wires-host`, including `--data-dir`, `--ticket-hint-ttl`, `--qr`, `--no-qr`, `--http-bind`, `--no-http`, and the `ticket` subcommand. If you get "command not found," the runtime stage didn't copy the binary correctly.

- [ ] **Step 4: Verify non-root user owns /data**

```bash
docker run --rm --entrypoint /bin/sh wires-host:local -c 'id && ls -ld /data'
```

Expected: `uid=10001(wires) gid=10001(wires) groups=10001(wires)` and `/data` owned by `wires:wires`.

- [ ] **Step 5: Commit**

```bash
git add docker/Dockerfile
git commit -m "docker: multi-stage cargo-chef Dockerfile for wires-host"
```

---

## Task 3: Write `compose.yaml`

**Files:**
- Create: `docker/compose.yaml`

- [ ] **Step 1: Create the compose file**

```yaml
# docker/compose.yaml
services:
  wires-host:
    build:
      context: ..
      dockerfile: docker/Dockerfile
    image: wires-host:local
    container_name: wires-host
    network_mode: host
    volumes:
      - wires-host-data:/data
    restart: unless-stopped
    environment:
      RUST_LOG: "warn,wires_host=info,wires_net=info,wires_node=info"
    stop_signal: SIGINT
    stop_grace_period: 10s

volumes:
  wires-host-data:
    name: wires-host-data
```

- [ ] **Step 2: Validate compose syntax**

```bash
docker compose -f docker/compose.yaml config
```

Expected: the compose file is echoed back, normalized and resolved. Any syntax errors are reported here. The `build.context` resolves to the repo root.

- [ ] **Step 3: Bring the service up**

```bash
docker compose -f docker/compose.yaml up -d
```

Expected: `Container wires-host  Started`. `network_mode: host` only works on Linux — on macOS / Docker Desktop the container starts but the host-networking semantics differ (the container shares the VM's namespace, not your Mac's). For local smoke-testing on macOS, this is acceptable; the production target is Linux.

- [ ] **Step 4: Verify the ticket HTTP server is reachable**

```bash
sleep 3
curl -fsS http://127.0.0.1:8089/ | head -5
```

Expected: HTML output from `ticket_http.rs`. If you get "connection refused," check `docker compose logs wires-host` — likely the binary failed to bind. On macOS, `localhost` may not route into the container under host networking; that's a known Docker Desktop limitation and not a code issue.

- [ ] **Step 5: Verify the host ticket is printable on demand**

```bash
docker compose -f docker/compose.yaml exec -T wires-host wires-host --data-dir /data ticket --no-qr
```

Expected: a single base64 string ending with no newline (one line of output). This is the host ticket.

- [ ] **Step 6: Verify identity persists across container recreate**

```bash
TICKET_BEFORE=$(docker compose -f docker/compose.yaml exec -T wires-host wires-host --data-dir /data ticket --no-qr)
docker compose -f docker/compose.yaml down
docker compose -f docker/compose.yaml up -d
sleep 3
TICKET_AFTER=$(docker compose -f docker/compose.yaml exec -T wires-host wires-host --data-dir /data ticket --no-qr)
# Tickets carry an addrs-TTL hint that may differ, but the EndpointId encoded
# inside MUST match. Easier signal: check the iroh.secret hash is stable.
docker compose -f docker/compose.yaml exec -T wires-host \
  sh -c 'sha256sum /data/iroh.secret'
```

Expected: same SHA256 before and after the down/up cycle (the volume preserved `iroh.secret`). `TICKET_BEFORE` and `TICKET_AFTER` may differ in their hint fields but encode the same EndpointId. If the SHA changes, the volume isn't actually persisting — check `docker volume ls` for `wires-host-data`.

- [ ] **Step 7: Bring it back down**

```bash
docker compose -f docker/compose.yaml down
```

- [ ] **Step 8: Commit**

```bash
git add docker/compose.yaml
git commit -m "docker: compose service with host networking and named data volume"
```

---

## Task 4: Write `deploy.sh`

**Files:**
- Create: `docker/deploy.sh` (executable, mode 0755)

- [ ] **Step 1: Create the script**

```bash
#!/usr/bin/env bash
# docker/deploy.sh — build and roll out wires-host.
#
# Run on the deploy host (e.g. `workbench`). Pulls the latest source on the
# current branch, rebuilds the image, recreates the container against the
# named data volume, and verifies the ticket HTTP server comes up.
set -euo pipefail

PULL=1
VERIFY=1
for arg in "$@"; do
  case "$arg" in
    --no-pull)   PULL=0 ;;
    --no-verify) VERIFY=0 ;;
    -h|--help)
      cat <<EOF
Usage: $(basename "$0") [--no-pull] [--no-verify]

  --no-pull    Skip git fetch/pull; deploy the current working tree.
  --no-verify  Skip the HTTP healthcheck poll on :8089.
EOF
      exit 0 ;;
    *)
      echo "unknown flag: $arg" >&2
      exit 64 ;;
  esac
done

cd "$(git rev-parse --show-toplevel)"

if [[ "$PULL" -eq 1 ]]; then
  git fetch --tags origin
  git pull --ff-only
fi

SHA="$(git rev-parse --short HEAD)"
echo "==> deploying wires-host at $SHA"

docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml up -d

if [[ "$VERIFY" -eq 1 ]]; then
  echo "==> waiting for ticket HTTP on :8089"
  ok=0
  for _ in $(seq 1 15); do
    if curl -fsS -o /dev/null http://127.0.0.1:8089/; then
      ok=1
      break
    fi
    sleep 1
  done
  if [[ "$ok" -ne 1 ]]; then
    echo "!! ticket HTTP did not come up; recent logs:" >&2
    docker compose -f docker/compose.yaml logs --tail=200 wires-host >&2
    exit 1
  fi
  echo "==> ticket HTTP up"
fi

echo "==> current ticket:"
docker compose -f docker/compose.yaml exec -T wires-host \
  wires-host --data-dir /data ticket --no-qr
echo
```

- [ ] **Step 2: Mark it executable**

```bash
chmod +x docker/deploy.sh
```

- [ ] **Step 3: Verify `--help` works**

```bash
./docker/deploy.sh --help
```

Expected: the usage block from the script. If you get "permission denied," step 2 was skipped.

- [ ] **Step 4: Verify shellcheck is clean (if available)**

```bash
shellcheck docker/deploy.sh || true
```

Expected: no warnings, or shellcheck is not installed. Either is fine.

- [ ] **Step 5: Dry-run with `--no-pull` against a clean working tree**

```bash
./docker/deploy.sh --no-pull
```

Expected: builds (using cargo-chef cache from Task 2/3), brings the service up, polls `:8089` to success, prints the ticket. On macOS this exercises the same code path as production; the `network_mode: host` caveat from Task 3 still applies.

- [ ] **Step 6: Tear down to leave the workspace clean**

```bash
docker compose -f docker/compose.yaml down
```

- [ ] **Step 7: Commit**

```bash
git add docker/deploy.sh
git commit -m "docker: deploy.sh build+rollover script"
```

---

## Task 5: Write `funnel.sh`

**Files:**
- Create: `docker/funnel.sh` (executable, mode 0755)

- [ ] **Step 1: Create the script**

```bash
#!/usr/bin/env bash
# docker/funnel.sh — manage the Tailscale Funnel for wires-host's ticket page.
#
# Run on the deploy host. Tailscale must already be installed, logged in,
# and granted Funnel permission in the tailnet admin panel.
set -euo pipefail

PORT="${WIRES_HOST_HTTP_PORT:-8089}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <up|down|status>

  up      Publish http://127.0.0.1:$PORT via Tailscale Funnel on :443.
  down    Tear down all Funnel mappings on this node.
  status  Print current serve/funnel configuration.

Environment:
  WIRES_HOST_HTTP_PORT  Override the local port (default: 8089).
EOF
}

require_tailscale() {
  if ! command -v tailscale >/dev/null 2>&1; then
    echo "tailscale CLI not on PATH" >&2
    exit 1
  fi
  if ! tailscale status --self=true --peers=false >/dev/null 2>&1; then
    echo "tailscale is not logged in; run 'sudo tailscale up' first" >&2
    exit 2
  fi
}

case "${1:-}" in
  up)
    require_tailscale
    sudo tailscale funnel --bg --https=443 --set-path=/ "http://127.0.0.1:$PORT"
    sudo tailscale funnel status
    ;;
  down)
    require_tailscale
    sudo tailscale funnel reset
    ;;
  status)
    require_tailscale
    sudo tailscale funnel status
    ;;
  *)
    usage
    exit 64
    ;;
esac
```

- [ ] **Step 2: Mark it executable**

```bash
chmod +x docker/funnel.sh
```

- [ ] **Step 3: Verify usage**

```bash
./docker/funnel.sh
```

Expected: prints the usage block and exits 64 (no subcommand given).

```bash
./docker/funnel.sh --help 2>&1 || true
./docker/funnel.sh bogus 2>&1 || true
```

Both should print the usage block. (`--help` is not a real flag, but the case fallthrough treats anything unknown as the usage path.)

- [ ] **Step 4: Verify `status` short-circuits cleanly when Tailscale is absent**

If you're running on a machine without Tailscale installed:

```bash
./docker/funnel.sh status
```

Expected: `tailscale CLI not on PATH` and exit code 1. If Tailscale is installed but not logged in, expect `tailscale is not logged in; run 'sudo tailscale up' first` and exit code 2. If Tailscale is installed and logged in, expect `tailscale funnel status` output (which may be "No serve/funnel config" on a fresh node).

- [ ] **Step 5: Verify shellcheck is clean (if available)**

```bash
shellcheck docker/funnel.sh || true
```

- [ ] **Step 6: Commit**

```bash
git add docker/funnel.sh
git commit -m "docker: funnel.sh Tailscale Funnel helper"
```

---

## Task 6: Write `docker/README.md`

**Files:**
- Create: `docker/README.md`

- [ ] **Step 1: Create the README**

````markdown
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
./docker/funnel.sh up               # publishes the ticket page on :443
```

The Funnel URL is printed by `funnel.sh up` (look for the line under
`Funnel on:`). Visiting it returns the host's ticket page; agents and
operators use the base64 ticket to pair against this host.

## Subsequent rollouts

```bash
./docker/deploy.sh                  # pulls, rebuilds, recreates, verifies
./docker/deploy.sh --no-pull        # deploy uncommitted local changes
./docker/deploy.sh --no-verify      # skip the HTTP healthcheck poll
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
./docker/funnel.sh up      # publish :8089 on Funnel :443
./docker/funnel.sh status  # see current mapping
./docker/funnel.sh down    # remove all Funnel mappings on this node
```

The script wraps `tailscale funnel`; it does not manage admin-policy
permissions or HTTPS cert provisioning, both of which are tailnet-wide
toggles done once in the Tailscale admin panel.

## Troubleshooting

- **`Cannot connect to the Docker daemon`** — start Docker (or your VM
  runtime). `deploy.sh` cannot continue without it.
- **Ticket HTTP poll times out** — check `docker compose logs wires-host`
  for a bind error on `0.0.0.0:8089` (another process is using the port)
  or an iroh endpoint failure.
- **Funnel URL returns 502** — the container is down, or its HTTP server
  was disabled. Confirm with `curl http://127.0.0.1:8089/` on the host.
- **EndpointId changed after redeploy** — the named volume was destroyed.
  Restore from backup if available; otherwise every paired tenant must
  re-pair against the new ticket.
````

- [ ] **Step 2: Render the README locally if a markdown previewer is handy**

(Optional sanity check that the code fences render correctly.)

- [ ] **Step 3: Commit**

```bash
git add docker/README.md
git commit -m "docker: README walkthrough for build, deploy, funnel, backup"
```

---

## Task 7: Final smoke test

**Why this exists:** Verifies the full operator flow end-to-end after all
files are in place.

**Files:** None modified.

- [ ] **Step 1: Run the full deploy on a clean state**

```bash
docker compose -f docker/compose.yaml down -v   # nuke any leftover state
./docker/deploy.sh --no-pull
```

Expected: build runs (cached from earlier tasks), container comes up,
healthcheck passes, ticket prints. Note: `down -v` removes the named
volume, so the EndpointId on the next run will be brand-new.

- [ ] **Step 2: Verify rollover preserves identity**

```bash
SHA_BEFORE=$(docker compose -f docker/compose.yaml exec -T wires-host \
  sha256sum /data/iroh.secret | awk '{print $1}')
./docker/deploy.sh --no-pull
SHA_AFTER=$(docker compose -f docker/compose.yaml exec -T wires-host \
  sha256sum /data/iroh.secret | awk '{print $1}')
[[ "$SHA_BEFORE" == "$SHA_AFTER" ]] && echo "OK: identity preserved" \
  || echo "FAIL: iroh.secret changed across rollover"
```

Expected: `OK: identity preserved`.

- [ ] **Step 3: Tear down**

```bash
docker compose -f docker/compose.yaml down
```

(Leave the volume intact — `down` without `-v` keeps it.)

- [ ] **Step 4: No commit**

This task is verification only.

---

## Acceptance criteria (from the spec)

Tie each criterion to a task:

| Criterion | Verified in |
|---|---|
| `docker compose build` succeeds from a clean checkout | Task 2 step 2 + Task 3 step 2 |
| `docker compose up -d` starts the container; running log line appears | Task 3 step 3 |
| Host ticket prints in logs every start AND via `exec … ticket --no-qr` | Task 3 step 5 |
| `EndpointId` stable across `down && up` | Task 3 step 6, Task 7 step 2 |
| Funnel URL returns the ticket HTTP page after `funnel.sh up` | Manual after install on real Tailscale host (covered in README) |
| Re-deploy after a `wires-host` source edit is faster than cold build (cargo-chef cache hit) | Implicit in Task 2's design; can be informally checked by editing `wires-host/src/main.rs` and re-running `deploy.sh` |

---

## Notes for the executing engineer

- **Local vs production target.** Plan steps that exercise `docker compose up` will succeed on macOS via Docker Desktop or OrbStack, but `network_mode: host` has degraded semantics on non-Linux. The intended deploy target is a Linux host (`workbench`). Treat local smoke tests as syntax/structure validation; the Funnel test in particular is only meaningful on the actual deploy host.
- **First build is slow.** Cold cargo-chef + iroh dep tree on amd64 Linux ≈ 5–10 min. Subsequent builds after a `wires-host` source edit should be well under a minute.
- **Do not modify `wires-host` source.** The compose-level `stop_signal: SIGINT` is the explicit workaround for the binary's `SIGINT`-only shutdown handler. If a future cleanup adds a `SIGTERM` handler to `wires-host`, the `stop_signal:` line can be removed from compose.yaml.
