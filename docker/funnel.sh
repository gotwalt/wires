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
