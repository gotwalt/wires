#!/usr/bin/env bash
#
# Demo endpoint A: boot a wires responder that execs `rg`, scoped to `tools.rg`.
#
# It provisions a small set of demo keys (an operator/root key, plus a node key
# each for the server and the agent), starts `wires serve`, then mints a
# capability ticket — carrying the server's direct localhost address — and drops
# it where connect.sh can read it. Everything logs to stderr so you can watch
# the handshake and session.
#
# Run this in one terminal, then run ./.scripts/connect.sh in another.
#
#   WIRES_DEMO_DIR   shared state dir (default /tmp/wires-demo)
#   WIRES_PATTERN    the pattern rg searches stdin for (default TODO)
#   RUST_LOG         log level (default info)

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
WIRES="${WIRES_BIN:-$repo/bazel-bin/wires/wires}"
DEMO="${WIRES_DEMO_DIR:-/tmp/wires-demo}"
SCOPE="tools.rg"
PATTERN="${WIRES_PATTERN:-TODO}"

log() { printf '\033[36m[serve-rg]\033[0m %s\n' "$*" >&2; }

if [ ! -x "$WIRES" ]; then
	log "building //wires (first run) ..."
	bazel build //wires >/dev/null 2>&1
fi

op="$DEMO/operator"
srv="$DEMO/server"
agt="$DEMO/agent"
mkdir -p "$op" "$srv" "$agt"

# Operator holds the root (signing) key; server and agent each hold a node key.
[ -f "$op/root.seed" ] || WIRES_HOME="$op" "$WIRES" keygen --save-root >/dev/null
[ -f "$srv/node.seed" ] || WIRES_HOME="$srv" "$WIRES" keygen --save-node >/dev/null
[ -f "$agt/node.seed" ] || WIRES_HOME="$agt" "$WIRES" keygen --save-node >/dev/null

node_id() { "$WIRES" keygen --node-seed "$(tr -d '\n' <"$1/node.seed")" | awk '/^node_id/{print $2}'; }
root_id() { "$WIRES" keygen --root-seed "$(tr -d '\n' <"$op/root.seed")" | awk '/^root_id/{print $2}'; }

ROOT_ID="$(root_id)"
SERVER_ID="$(node_id "$srv")"
AGENT_ID="$(node_id "$agt")"
log "operator root id : $ROOT_ID"
log "server   node id : $SERVER_ID"
log "agent    node id : $AGENT_ID"

# Start the responder; tee its log so we can read the bound UDP port from it.
rm -f "$DEMO/ticket" "$DEMO/membership"
srvlog="$DEMO/serve.log"
: >"$srvlog"
log "starting: wires serve --scope $SCOPE -- rg --line-number --color never $PATTERN"
WIRES_HOME="$srv" RUST_LOG="${RUST_LOG:-info}" \
	"$WIRES" serve \
	--trust-root "$ROOT_ID" \
	--scope "$SCOPE" \
	-- rg --line-number --color never "$PATTERN" \
	2> >(tee -a "$srvlog" >&2) &
serve_pid=$!
trap 'log "stopping responder"; kill "$serve_pid" 2>/dev/null || true' EXIT INT TERM

# Wait for the responder to log its bound IPv4 socket, then take the port.
log "waiting for the responder to bind ..."
port=""
for _ in $(seq 1 50); do
	port="$(grep -oE '0\.0\.0\.0:[0-9]+' "$srvlog" | head -1 | cut -d: -f2 || true)"
	[ -n "$port" ] && break
	sleep 0.2
done
[ -n "$port" ] || {
	log "responder never reported a port; see $srvlog"
	exit 1
}
log "responder bound; dialable at 127.0.0.1:$port"

# Mint a ticket binding the agent to tools.rg on this server, with a direct
# address so the dialer needs no discovery. (Root key from the operator home.)
ticket="$(WIRES_HOME="$op" "$WIRES" grant \
	--subject "$AGENT_ID" \
	--target "$SERVER_ID" \
	--scope "$SCOPE" \
	--ttl 3600 \
	--addr "127.0.0.1:$port")"
printf '%s\n' "$ticket" >"$DEMO/ticket"
log "minted ticket -> $DEMO/ticket"

# Mint the agent's fabric membership (root-signed). The dialer must present it
# on every session — serve verifies inclusion before checking the grant.
membership="$(WIRES_HOME="$op" "$WIRES" member \
	--subject "$AGENT_ID" \
	--ttl 3600)"
printf '%s\n' "$membership" >"$DEMO/membership"
log "minted membership -> $DEMO/membership"
log "ready: run ./.scripts/connect.sh in another terminal (Ctrl-C here to stop)."

wait "$serve_pid"
