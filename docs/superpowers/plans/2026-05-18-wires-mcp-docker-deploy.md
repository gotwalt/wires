# wires-mcp Docker deploy — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `wires-mcp` as a second compose service in `docker/compose.yaml`, sharing a multi-binary Dockerfile with `wires-host`, with operator-edited TOML config, separate persistent volume, `:443` Funnel mapping, and a reworked `funnel.sh` that manages both services from a single catalog.

**Architecture:** One Dockerfile gains a `runtime-base` shared stage and two final stages (`runtime-host`, `runtime-mcp`); compose's `build.target:` selects which one each service uses. wires-mcp binds `127.0.0.1:10001` per its TOML, mounted read-only from `docker/wires-mcp.toml` (gitignored, copied from a committed `.example`). `deploy.sh` builds both binaries in one `cargo build`, polls both `/`-class endpoints, prints wires-host's ticket. `funnel.sh` is rewritten around a `SERVICES` array so future wires-* services need only a one-line addition.

**Tech Stack:** Docker Compose v2, cargo-chef on Rust stable, axum (wires-mcp HTTP), Tailscale Funnel.

**Spec:** `docs/superpowers/specs/2026-05-18-wires-mcp-docker-deploy-design.md`

---

## File structure

All edits live under `docker/`, with two new files:

| Path | Action | Responsibility |
|---|---|---|
| `docker/Dockerfile` | edit | Add `runtime-base` shared stage and `runtime-mcp` stage; rename existing runtime to `runtime-host`; cook + build both binaries in one pass. |
| `docker/compose.yaml` | edit | Set `build.target: runtime-host` on existing service; add `wires-mcp` service with `target: runtime-mcp`, bind-mount of `wires-mcp.toml`, separate `wires-mcp-data` volume. |
| `docker/wires-mcp.toml.example` | create | Operator template with `public_url`, `bind`, `data_dir`. |
| `.gitignore` | edit | Add `docker/wires-mcp.toml`. |
| `docker/deploy.sh` | edit | Pre-flight check for `docker/wires-mcp.toml`; poll both `127.0.0.1:10000/` and `127.0.0.1:10001/_health`. |
| `docker/funnel.sh` | rewrite | Service catalog (`host`, `mcp`); `up/down/status [service|all]` subcommands. |
| `docker/README.md` | edit | Add MCP setup walkthrough; update Funnel/backup sections. |

No Rust changes. Two known gaps in `wires-mcp` (hardcoded log filter, no `info` subcommand) are spec-acknowledged follow-ups; not in this plan.

---

## Pre-flight: verify Docker + Compose

- [ ] **Step 1: Confirm Docker daemon is reachable**

Run: `docker version`
Expected: client + server version block. If the server section says "Cannot connect to the Docker daemon," start your daemon before proceeding. On the dev mac in this codebase the daemon is typically off; the plan defers daemon-dependent verifications to `workbench` where they'll run real.

- [ ] **Step 2: Confirm Compose v2 is available**

Run: `docker compose version`
Expected: `Docker Compose version v2.x` or newer.

---

## Task 1: Rename the existing runtime stage and factor out `runtime-base`

This is a no-functional-change refactor that prepares the Dockerfile for the second runtime stage Task 2 will add. Doing it as its own task keeps the cargo-chef-aware diff in Task 2 small and easy to review.

**Files:**
- Modify: `docker/Dockerfile`

- [ ] **Step 1: Read the current Dockerfile**

Read `docker/Dockerfile`. Confirm it ends with:

```dockerfile
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

- [ ] **Step 2: Replace the runtime stage with `runtime-base` + `runtime-host`**

```dockerfile
# Shared runtime base: debian-slim, ca-certificates, non-root `wires` user.
# Both runtime-host and runtime-mcp build on top of this to avoid duplication.
FROM debian:bookworm-slim AS runtime-base
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 --create-home --home-dir /data --shell /usr/sbin/nologin wires
USER wires
WORKDIR /data

# Final image for wires-host. Compose selects this with `build.target: runtime-host`.
FROM runtime-base AS runtime-host
COPY --from=builder /app/target/release/wires-host /usr/local/bin/wires-host
EXPOSE 10000/tcp
ENTRYPOINT ["wires-host"]
CMD ["--data-dir", "/data"]
```

Note: `EXPOSE 8089/tcp` becomes `EXPOSE 10000/tcp` to match the compose-level `--http-bind 0.0.0.0:10000` override. `EXPOSE` is informational under `network_mode: host`; updating it just keeps the Dockerfile honest about the listen port the deploy actually uses.

- [ ] **Step 3: Verify the file ends correctly**

Read `docker/Dockerfile`. Confirm: no `runtime` stage remains; both `runtime-base` and `runtime-host` are present; the `chef`, `planner`, and `builder` stages are unchanged.

- [ ] **Step 4: Commit**

```bash
git add docker/Dockerfile
git commit -m "docker: factor out runtime-base; rename runtime → runtime-host"
```

---

## Task 2: Add the `runtime-mcp` target and build both binaries

**Files:**
- Modify: `docker/Dockerfile`

- [ ] **Step 1: Update the `builder` stage to cook and build both binaries**

Find the `builder` stage (currently builds only `wires-host`):

```dockerfile
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked -p wires-host --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p wires-host
```

Replace with:

```dockerfile
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Cook the union of deps required by wires-host and wires-mcp; the cached
# layer is invalidated only when recipe.json changes (i.e. workspace deps
# shift), not on source-only edits to either binary.
RUN cargo chef cook --release --locked \
    -p wires-host -p wires-mcp --recipe-path recipe.json
COPY . .
# Single `cargo build` invocation so both binaries share the same workspace
# crate cache; two separate invocations would recompile every shared crate
# (wires-core, wires-crypto, wires-store, wires-net, wires-node) twice.
RUN cargo build --release --locked -p wires-host -p wires-mcp
```

- [ ] **Step 2: Add the `runtime-mcp` stage after `runtime-host`**

Append to `docker/Dockerfile`:

```dockerfile

# Final image for wires-mcp. Compose selects this with `build.target: runtime-mcp`.
FROM runtime-base AS runtime-mcp
COPY --from=builder /app/target/release/wires-mcp /usr/local/bin/wires-mcp
EXPOSE 10001/tcp
ENTRYPOINT ["wires-mcp"]
CMD ["serve"]
```

- [ ] **Step 3: Verify the file structure**

Read `docker/Dockerfile`. Confirm the stage order and names:

1. `FROM lukemathwalker/cargo-chef:... AS chef`
2. `FROM chef AS planner`
3. `FROM chef AS builder` — now cooks + builds both `-p wires-host -p wires-mcp`
4. `FROM debian:bookworm-slim AS runtime-base`
5. `FROM runtime-base AS runtime-host`
6. `FROM runtime-base AS runtime-mcp`

- [ ] **Step 4: Commit**

```bash
git add docker/Dockerfile
git commit -m "docker: build wires-mcp alongside wires-host; add runtime-mcp target"
```

---

## Task 3: Add the operator config template and gitignore the real copy

**Files:**
- Create: `docker/wires-mcp.toml.example`
- Modify: `.gitignore`

- [ ] **Step 1: Create the template**

```toml
# wires-mcp gateway config — copy to docker/wires-mcp.toml and edit
# `public_url` to match your Funnel hostname before first deploy.
# The copy is gitignored and operator-specific; this .example file is committed.

# Public-facing base URL (no trailing slash). Used as `iss`, `aud`, and
# RFC 8707 `resource` on every issued JWT. Must be stable once tokens are
# in the wild — renaming workbench or moving wires-mcp invalidates every
# outstanding token and forces every OAuth client to re-authorize.
public_url = "https://workbench.tail63ef5.ts.net"

# Where wires-mcp listens inside the container. Funnel reverse-proxies
# from public :443 to this address. Must match deploy.sh's verify poll.
bind = "127.0.0.1:10001"

# Filesystem root inside the container; backed by the wires-mcp-data
# named volume.
data_dir = "/data"
```

Write this content to `docker/wires-mcp.toml.example`.

- [ ] **Step 2: Add the real copy to `.gitignore`**

Read `.gitignore`. Append (in an appropriate section, or at the end):

```
# Operator-edited wires-mcp config (template lives at docker/wires-mcp.toml.example)
docker/wires-mcp.toml
```

- [ ] **Step 3: Verify the ignore works**

Run from the repo root:

```bash
echo "test" > docker/wires-mcp.toml
git check-ignore docker/wires-mcp.toml
echo "exit: $?"
rm docker/wires-mcp.toml
```

Expected: `git check-ignore` prints `docker/wires-mcp.toml` and exits 0. If `git check-ignore` exits 1, the gitignore entry didn't match — fix it before committing.

- [ ] **Step 4: Commit**

```bash
git add docker/wires-mcp.toml.example .gitignore
git commit -m "docker: add wires-mcp.toml.example template; gitignore the real copy"
```

---

## Task 4: Wire wires-host's compose service to the new build target

This is a one-key change (`build.target: runtime-host`) plus matching `EXPOSE` cleanup, isolated as its own task so it lands before the wires-mcp service in Task 5.

**Files:**
- Modify: `docker/compose.yaml`

- [ ] **Step 1: Add `target: runtime-host` to the wires-host service's `build:` block**

Read `docker/compose.yaml`. Replace:

```yaml
    build:
      context: ..
      dockerfile: docker/Dockerfile
```

with:

```yaml
    build:
      context: ..
      dockerfile: docker/Dockerfile
      target: runtime-host
```

- [ ] **Step 2: Validate compose syntax**

```bash
docker compose -f docker/compose.yaml config
```

Expected: the compose file is echoed back, normalized. Confirm `build.target: runtime-host` appears under `wires-host` in the output.

- [ ] **Step 3: Commit**

```bash
git add docker/compose.yaml
git commit -m "docker: pin wires-host service to the runtime-host build target"
```

---

## Task 5: Add the wires-mcp service to compose

**Files:**
- Modify: `docker/compose.yaml`

- [ ] **Step 1: Add the second service and the second volume**

Read `docker/compose.yaml`. After the existing `wires-host:` service block (before the top-level `volumes:` block), insert:

```yaml

  wires-mcp:
    build:
      context: ..
      dockerfile: docker/Dockerfile
      target: runtime-mcp
    image: wires-mcp:local
    container_name: wires-mcp
    network_mode: host
    volumes:
      - wires-mcp-data:/data
      # Operator-edited TOML mounted read-only so the binary can't
      # accidentally overwrite the operator's edits.
      - ./wires-mcp.toml:/etc/wires-mcp/config.toml:ro
    restart: unless-stopped
    environment:
      WIRES_MCP_CONFIG: /etc/wires-mcp/config.toml
      # RUST_LOG is documentation-only today — wires-mcp's main.rs hardcodes
      # the filter to "info". Setting it anticipates a future binary fix.
      RUST_LOG: "info,wires_mcp=info"
    stop_signal: SIGINT
    stop_grace_period: 10s
```

Then update the top-level `volumes:` block from:

```yaml
volumes:
  wires-host-data:
    name: wires-host-data
```

to:

```yaml
volumes:
  wires-host-data:
    name: wires-host-data
  wires-mcp-data:
    name: wires-mcp-data
```

- [ ] **Step 2: Compose config requires the wires-mcp.toml file to exist for `config` to resolve**

`docker compose config` resolves bind-mount paths but does not require the source to exist (it issues a warning at worst). To make the rest of this task's verification meaningful, create a temporary `docker/wires-mcp.toml` from the template:

```bash
cp docker/wires-mcp.toml.example docker/wires-mcp.toml
```

(Recall the file is gitignored — it won't show in `git status` after this copy.)

- [ ] **Step 3: Validate compose syntax**

```bash
docker compose -f docker/compose.yaml config
```

Expected: both `wires-host` and `wires-mcp` services appear in the normalized output. Under `wires-mcp.volumes`, confirm both the named volume and the bind-mount of the absolute path to `docker/wires-mcp.toml` mounted at `/etc/wires-mcp/config.toml` with `read_only: true`. Under `volumes:`, confirm both `wires-host-data` and `wires-mcp-data` are declared with explicit `name:` overrides.

- [ ] **Step 4: Clean up the temporary config file**

```bash
rm docker/wires-mcp.toml
```

- [ ] **Step 5: Commit**

```bash
git add docker/compose.yaml
git commit -m "docker: add wires-mcp compose service with mounted config + separate volume"
```

---

## Task 6: Rewrite `funnel.sh` around a service catalog

**Files:**
- Modify: `docker/funnel.sh`

- [ ] **Step 1: Replace the script's contents**

Overwrite `docker/funnel.sh` with:

```bash
#!/usr/bin/env bash
# docker/funnel.sh — manage Tailscale Funnel mappings for wires services.
#
# Run on the deploy host. Tailscale must already be installed, logged in,
# and granted Funnel permission in the tailnet admin panel.
set -euo pipefail

# Service catalog. Add an entry per wires service that needs Funnel.
# Format (space-separated): <name> <funnel_https_port> <local_port> <funnel_path>
# Funnel public port must be one of 443, 8443, 10000 (Tailscale's only
# Funnel-supported public ports).
SERVICES=(
  "host  10000  10000  /"
  "mcp     443  10001  /"
)

usage() {
  cat <<EOF
Usage: $(basename "$0") <up|down|status> [host|mcp|all]

  up [name]     Publish service(s) via Tailscale Funnel.
                Default: all.
  down [name]   Remove service(s)' Funnel mapping. Targeted — leaves
                other Funnel rules on this node untouched.
                Default: all.
  status        Print current serve/funnel configuration.

Services:
EOF
  for row in "${SERVICES[@]}"; do
    # shellcheck disable=SC2086
    set -- $row
    printf "  %-6s Funnel :%s%s -> 127.0.0.1:%s\n" "$1" "$2" "$4" "$3"
  done
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

apply() {
  local action="$1" target="$2"
  local matched=0
  for row in "${SERVICES[@]}"; do
    # shellcheck disable=SC2086
    set -- $row
    local svc="$1" fport="$2" lport="$3" fpath="$4"
    if [[ "$target" != "all" && "$target" != "$svc" ]]; then
      continue
    fi
    matched=1
    case "$action" in
      up)
        sudo tailscale funnel --bg --https="$fport" --set-path="$fpath" \
          "http://127.0.0.1:$lport"
        ;;
      down)
        sudo tailscale funnel --https="$fport" --set-path="$fpath" off
        ;;
    esac
  done
  if [[ "$matched" -eq 0 ]]; then
    echo "unknown service: $target (known: $(printf "%s " "${SERVICES[@]%% *}" | sed 's/ $//'), all)" >&2
    exit 64
  fi
}

case "${1:-}" in
  up|down)
    require_tailscale
    apply "$1" "${2:-all}"
    tailscale funnel status
    ;;
  status)
    require_tailscale
    tailscale funnel status
    ;;
  *)
    usage
    exit 64
    ;;
esac
```

- [ ] **Step 2: Verify the script is still executable**

```bash
ls -l docker/funnel.sh
```

Expected: `-rwxr-xr-x …`. (`Write` preserves the executable bit on overwrites, but verify anyway.) If it's not, `chmod +x docker/funnel.sh`.

- [ ] **Step 3: Verify usage output**

Run with no args:

```bash
./docker/funnel.sh
```

Expected: exit 64; usage block includes both service rows:

```
  host   Funnel :10000/ -> 127.0.0.1:10000
  mcp    Funnel :443/ -> 127.0.0.1:10001
```

- [ ] **Step 4: Verify unknown-service handling**

Run:

```bash
./docker/funnel.sh up bogus 2>&1; echo "exit: $?"
```

Expected: stderr says `unknown service: bogus (known: host mcp, all)`; exit 64. (If Tailscale is installed on this Mac, `require_tailscale` will pass and the error will come from `apply`. If Tailscale is not installed, the error will come from `require_tailscale` instead with `tailscale CLI not on PATH` and exit 1 — either is fine, the point is the script doesn't silently no-op.)

- [ ] **Step 5: Run shellcheck if available**

```bash
shellcheck docker/funnel.sh || true
```

Report any findings. The two `# shellcheck disable=SC2086` directives in the script are intentional — SC2086 warns about word-splitting the unquoted `$row`, but the splitting is exactly what we want.

- [ ] **Step 6: Commit**

```bash
git add docker/funnel.sh
git commit -m "docker: rewrite funnel.sh around a per-service catalog (host, mcp)"
```

---

## Task 7: Extend `deploy.sh` for two services

**Files:**
- Modify: `docker/deploy.sh`

- [ ] **Step 1: Read the existing script**

Read `docker/deploy.sh`. Confirm its current shape: arg-parse, optional `git pull --ff-only`, `docker compose build`, `docker compose up -d`, single-endpoint poll of `127.0.0.1:10000/`, then `docker compose exec wires-host wires-host --data-dir /data ticket --no-qr`.

- [ ] **Step 2: Add the pre-flight config check (right after `cd "$(git rev-parse --show-toplevel)"`)**

Replace:

```bash
cd "$(git rev-parse --show-toplevel)"

if [[ "$PULL" -eq 1 ]]; then
```

with:

```bash
cd "$(git rev-parse --show-toplevel)"

# Pre-flight: wires-mcp's bind-mount source must exist before `docker compose
# up` tries to mount it. Fail clearly instead of letting Docker emit a cryptic
# mount error mid-deploy.
if [[ ! -f docker/wires-mcp.toml ]]; then
  echo "!! docker/wires-mcp.toml is missing." >&2
  echo "   Copy docker/wires-mcp.toml.example to docker/wires-mcp.toml" >&2
  echo "   and edit public_url before running ./docker/deploy.sh again." >&2
  exit 1
fi

if [[ "$PULL" -eq 1 ]]; then
```

- [ ] **Step 3: Update the echo banner**

Replace:

```bash
echo "==> deploying wires-host at $SHA"
```

with:

```bash
echo "==> deploying wires-host + wires-mcp at $SHA"
```

- [ ] **Step 4: Replace the single-endpoint poll with a multi-endpoint loop**

Find the block:

```bash
if [[ "$VERIFY" -eq 1 ]]; then
  echo "==> waiting for ticket HTTP on :10000"
  ok=0
  for _ in $(seq 1 15); do
    if curl -fsS -o /dev/null http://127.0.0.1:10000/; then
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
```

Replace with:

```bash
if [[ "$VERIFY" -eq 1 ]]; then
  for endpoint in \
      "http://127.0.0.1:10000/" \
      "http://127.0.0.1:10001/_health"; do
    echo "==> waiting for $endpoint"
    ok=0
    for _ in $(seq 1 15); do
      if curl -fsS -o /dev/null "$endpoint"; then
        ok=1
        break
      fi
      sleep 1
    done
    if [[ "$ok" -ne 1 ]]; then
      echo "!! $endpoint did not come up; recent logs:" >&2
      docker compose -f docker/compose.yaml logs --tail=200 >&2
      exit 1
    fi
    echo "==> $endpoint up"
  done
fi
```

Notes on the change: the log dump on failure now drops the `wires-host` service argument, so logs from both services appear — useful when wires-mcp is the one that failed.

- [ ] **Step 5: Update the `--no-verify` help text to reflect both polls**

Replace:

```bash
  --no-verify  Skip the HTTP healthcheck poll on :10000.
```

with:

```bash
  --no-verify  Skip the HTTP healthcheck polls on :10000 and :10001.
```

- [ ] **Step 6: Verify the updated script**

```bash
./docker/deploy.sh --help
```

Expected: usage block prints; `--no-verify` description mentions both ports.

```bash
./docker/deploy.sh --no-pull 2>&1 | head -5
```

Expected: exit code 1; the first line says `!! docker/wires-mcp.toml is missing.` (Docker daemon state doesn't matter for this check — it happens before any `docker` invocation.)

- [ ] **Step 7: Run shellcheck if available**

```bash
shellcheck docker/deploy.sh || true
```

Report any findings.

- [ ] **Step 8: Commit**

```bash
git add docker/deploy.sh
git commit -m "docker: deploy.sh — preflight wires-mcp.toml + poll both services"
```

---

## Task 8: Update `docker/README.md`

**Files:**
- Modify: `docker/README.md`

- [ ] **Step 1: Read the current README to find the "First-time install" section**

Read `docker/README.md`. The current `## First-time install on the deploy host` section ends with `./docker/funnel.sh up               # publishes the ticket page on Funnel :10000`. The "Subsequent rollouts" section starts after it.

- [ ] **Step 2: Replace the first-time-install commands with a multi-step block**

Find:

```bash
git clone <repo-url> ~/src/wires
cd ~/src/wires
./docker/deploy.sh                  # builds, starts, prints the ticket
./docker/funnel.sh up               # publishes the ticket page on Funnel :10000
```

Replace with:

````markdown
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
````

- [ ] **Step 2b: Update the Port convention section**

Find the existing block (added by the prior port-10000 commit):

```markdown
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
```

Replace with:

```markdown
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
```

Also find this stale rollouts comment (`docker/deploy.sh --no-verify`):

```markdown
./docker/deploy.sh --no-verify      # skip the HTTP healthcheck poll (e.g. when running with `--no-http`)
```

Replace with:

```markdown
./docker/deploy.sh --no-verify      # skip the HTTP healthcheck polls on :10000 and :10001
```

- [ ] **Step 3: Find and replace the Tailscale Funnel section**

Find the section starting with `## Tailscale Funnel` (the block listing `up`/`status`/`down` commands).

Replace the command block:

```bash
./docker/funnel.sh up      # publish 127.0.0.1:10000 on Funnel :10000
./docker/funnel.sh status  # see current mapping
./docker/funnel.sh down    # remove just this script's Funnel mapping
```

with:

```bash
./docker/funnel.sh up all   # publish all wires services (host + mcp)
./docker/funnel.sh up host  # just wires-host (Funnel :10000)
./docker/funnel.sh up mcp   # just wires-mcp  (Funnel :443)
./docker/funnel.sh status   # see current mappings
./docker/funnel.sh down mcp # remove only the wires-mcp mapping; host stays up
./docker/funnel.sh down all # remove every wires-* Funnel mapping on this node
```

And remove the old "Override the defaults with env vars" block beneath it (it documented `WIRES_FUNNEL_HTTPS_PORT` etc., which no longer exist in the rewritten script). Replace it with:

```markdown
Funnel slot assignments are baked into the script's `SERVICES` catalog at
the top of `docker/funnel.sh`. Adding a third wires-* service later means
adding one line to that array. Tailscale Funnel itself supports only three
public ports — `443`, `8443`, `10000` — so adding services means either
sharing a port via sub-paths or moving an existing service.
```

- [ ] **Step 4: Add a backup section for wires-mcp's volume**

Find the existing backup block:

```bash
docker run --rm \
  -v wires-host-data:/src \
  -v "$PWD:/out" \
  debian:bookworm-slim \
  tar -C /src -czf "/out/wires-host-$(date +%F).tgz" .
```

Append (after the existing block, before "Restore the same tarball into a fresh volume:"):

````markdown
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
````

- [ ] **Step 5: Update the troubleshooting bullets to mention :10001**

Find:

```markdown
- **Ticket HTTP poll times out** — check `docker compose logs wires-host`
  for a bind error on `0.0.0.0:10000` (another process is using the port)
  or an iroh endpoint failure.
- **Funnel URL returns 502** — the container is down, or its HTTP server
  was disabled. Confirm with `curl http://127.0.0.1:10000/` on the host.
```

Replace with:

```markdown
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
```

- [ ] **Step 6: Verify the README renders sensibly**

Optional: open `docker/README.md` in a markdown previewer. Confirm code fences are balanced and section headings step down one level at a time.

```bash
grep -c '^```' docker/README.md
```

Expected: an even number (every fence has a matching close).

- [ ] **Step 7: Commit**

```bash
git add docker/README.md
git commit -m "docker: README — wires-mcp setup, two-service Funnel + backup"
```

---

## Task 9: End-to-end smoke test (deferred to workbench)

**Files:** none modified.

This task is verification-only and runs on `workbench` after the branch is merged. Recording it as a task keeps the acceptance criteria visible.

- [ ] **Step 1: On workbench, copy and edit the config**

```bash
ssh workbench
cd ~/src/wires
git pull --ff-only
cp docker/wires-mcp.toml.example docker/wires-mcp.toml
${EDITOR:-nano} docker/wires-mcp.toml   # confirm public_url; save & quit
```

- [ ] **Step 2: Deploy both services**

```bash
./docker/deploy.sh --no-pull
```

Expected: build runs, both containers come up, both endpoints respond 200, wires-host ticket prints. First wires-mcp build adds dep cooking time vs. wires-host alone, but cargo-chef caches the planned recipe so source-only re-deploys stay fast.

- [ ] **Step 3: Verify identity persistence**

```bash
HOST_SHA_BEFORE=$(docker compose -f docker/compose.yaml exec -T wires-host \
  sha256sum /data/iroh.secret | awk '{print $1}')
MCP_SHA_BEFORE=$(docker compose -f docker/compose.yaml exec -T wires-mcp \
  sha256sum /data/token_signing.ed25519 | awk '{print $1}')

docker compose -f docker/compose.yaml down
docker compose -f docker/compose.yaml up -d
sleep 5

HOST_SHA_AFTER=$(docker compose -f docker/compose.yaml exec -T wires-host \
  sha256sum /data/iroh.secret | awk '{print $1}')
MCP_SHA_AFTER=$(docker compose -f docker/compose.yaml exec -T wires-mcp \
  sha256sum /data/token_signing.ed25519 | awk '{print $1}')

[[ "$HOST_SHA_BEFORE" == "$HOST_SHA_AFTER" ]] && echo "OK: wires-host identity preserved"
[[ "$MCP_SHA_BEFORE"  == "$MCP_SHA_AFTER"  ]] && echo "OK: wires-mcp identity preserved"
```

Expected: both OK lines.

- [ ] **Step 4: Bring Funnel up**

```bash
./docker/funnel.sh up all
```

Expected: both Funnel rules listed in `tailscale funnel status` output.

- [ ] **Step 5: Verify public URLs from the dev machine**

From the dev mac (not workbench):

```bash
curl -fsS -w "\nHTTP %{http_code}\n" \
  https://workbench.tail63ef5.ts.net:10000/ -o /dev/null

curl -fsS -w "\nHTTP %{http_code}\n" \
  https://workbench.tail63ef5.ts.net/_health
```

Expected: first returns 200 (HTML body suppressed by `-o /dev/null`); second returns `ok` with HTTP 200.

- [ ] **Step 6: Verify targeted `funnel.sh down`**

```bash
ssh workbench '~/src/wires/docker/funnel.sh down mcp'
ssh workbench '~/src/wires/docker/funnel.sh status'
```

Expected: only the `:10000` (wires-host) Funnel rule remains; the `:443` rule for wires-mcp is gone.

```bash
ssh workbench '~/src/wires/docker/funnel.sh up mcp'
```

Expected: the `:443` rule is restored.

- [ ] **Step 7: No commit**

Verification only.

---

## Acceptance criteria (mapped to tasks)

| Criterion | Verified in |
|---|---|
| Dockerfile builds both wires-host and wires-mcp images | Task 2 (structure) + Task 9 step 2 (real build) |
| `runtime-base` factored out; both targets minimal | Tasks 1, 2 |
| `wires-mcp.toml.example` committed; real copy gitignored | Task 3 step 3 |
| `compose config` shows both services with correct targets | Tasks 4 step 2, 5 step 3 |
| Operator-edited TOML mounted read-only | Task 5 step 3 |
| Both `wires-host-data` and `wires-mcp-data` declared with explicit `name:` | Task 5 step 3 |
| `funnel.sh up host|mcp|all` produces correct mappings | Task 6 step 3 + Task 9 step 4 |
| `funnel.sh down mcp` is targeted (host stays up) | Task 9 step 6 |
| `deploy.sh` fails fast if `wires-mcp.toml` missing | Task 7 step 6 |
| `deploy.sh` polls both `/` and `/_health` | Task 7 step 4 |
| Both volumes preserve identity across `down && up` | Task 9 step 3 |
| Public URL serves the wires-mcp `/_health` endpoint | Task 9 step 5 |
| README walks first-time, rollouts, Funnel (host/mcp/all), backup, troubleshooting | Task 8 |

---

## Notes for the executing engineer

- **Local vs production.** Tasks 1–8 are repository edits with mostly-static verification (`docker compose config`, shellcheck, `--help` output). Docker-daemon-dependent verification (building, running, polling) lives in Task 9 and is intended for `workbench`, not the dev mac. Daemon checks may also work locally if you have Docker running, but `network_mode: host` semantics differ on macOS.
- **First wires-mcp build adds dep cooking time.** Cargo-chef cooks the union of dep trees, so the first build after Task 2 lands will be longer than a pure-wires-host build. Subsequent builds reuse the deps layer and are fast.
- **The compose-level `RUST_LOG` for wires-mcp is no-op today.** The binary hardcodes `EnvFilter::new("info")`. Setting it in compose anticipates a future binary fix; not setting it would also work. Leave it in for documentation value.
- **Do not edit `wires-mcp` source code as part of this plan.** Two known limitations (hardcoded log filter, no `info` subcommand) are spec-acknowledged follow-ups. If they bother you while implementing, file a separate plan; do not bundle them.
- **Funnel `:443` reclamation is unilateral.** Running `funnel.sh up mcp` overwrites whatever else was on Funnel `:443`. The operator confirmed nothing useful was there on workbench. The README's reclamation warning makes the behavior explicit for future readers.
