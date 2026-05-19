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
