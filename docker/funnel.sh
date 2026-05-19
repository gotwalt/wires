#!/usr/bin/env bash
# docker/funnel.sh — manage the Tailscale Funnel for wires-host's ticket page.
#
# Run on the deploy host. Tailscale must already be installed, logged in,
# and granted Funnel permission in the tailnet admin panel.
set -euo pipefail

# Local listen port: where wires-host's ticket HTTP server binds inside the
# host's network namespace. Defaults to 10000 to match the wires-* port
# convention (10000+ reserved for wires services).
PORT="${WIRES_HOST_HTTP_PORT:-10000}"

# Tailscale Funnel public port. Funnel only supports three values: 443, 8443,
# 10000. Default to 10000 — :443 is most often already in use on a shared
# host, and 8443 collides with default `tailscale serve` setups. Override
# via WIRES_FUNNEL_HTTPS_PORT if your environment frees one of the others.
FUNNEL_PORT="${WIRES_FUNNEL_HTTPS_PORT:-10000}"

# Path on the Funnel hostname under which the ticket page is served.
FUNNEL_PATH="${WIRES_FUNNEL_PATH:-/}"

usage() {
  cat <<EOF
Usage: $(basename "$0") <up|down|status>

  up      Publish http://127.0.0.1:$PORT via Tailscale Funnel on :$FUNNEL_PORT$FUNNEL_PATH.
  down    Remove just the wires-host Funnel mapping ( :$FUNNEL_PORT$FUNNEL_PATH ).
  status  Print current serve/funnel configuration.

Environment:
  WIRES_HOST_HTTP_PORT    Local port wires-host listens on (default: 10000).
  WIRES_FUNNEL_HTTPS_PORT Tailscale Funnel public port: 443, 8443, or 10000
                          (default: 10000).
  WIRES_FUNNEL_PATH       Path under the Funnel hostname (default: /).
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
    sudo tailscale funnel --bg --https="$FUNNEL_PORT" --set-path="$FUNNEL_PATH" \
      "http://127.0.0.1:$PORT"
    sudo tailscale funnel status
    ;;
  down)
    require_tailscale
    # Targeted removal: only this script's (port, path) mapping. Other
    # Funnel/serve mappings on this node are left untouched.
    sudo tailscale funnel --https="$FUNNEL_PORT" --set-path="$FUNNEL_PATH" off
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
