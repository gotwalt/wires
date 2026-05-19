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
