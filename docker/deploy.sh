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
  --no-verify  Skip the HTTP healthcheck polls on :10000 and :10001.
EOF
      exit 0 ;;
    *)
      echo "unknown flag: $arg" >&2
      exit 64 ;;
  esac
done

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
  git fetch --tags origin
  git pull --ff-only
fi

SHA="$(git rev-parse --short HEAD)"
echo "==> deploying wires-host + wires-mcp at $SHA"

docker compose -f docker/compose.yaml build
docker compose -f docker/compose.yaml up -d

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

echo "==> current ticket:"
docker compose -f docker/compose.yaml exec -T wires-host \
  wires-host --data-dir /data ticket --no-qr
echo
