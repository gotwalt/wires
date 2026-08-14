#!/usr/bin/env bash
#
# Demo endpoint B: read stdin and proxy it over wires to the rg responder
# started by ./.scripts/serve-rg.sh, printing rg's matches to stdout.
#
# `wires connect` forwards our stdin to the remote `rg`'s stdin and streams its
# stdout/stderr back; rg searches the piped text for the responder's pattern
# (default TODO). Connection logs go to stderr so they never mix into stdout.
#
# Examples:
#   printf 'a\nTODO: x\nb\n' | ./.scripts/connect.sh
#   ./.scripts/connect.sh < some-file.txt
#
# Run this directly from the repo root -- NOT via `bazel run //.scripts:...`.
#
# Like serve-rg.sh, this keeps its state in the sticky $WIRES_DEMO_DIR so you
# can iterate on the happy path without re-provisioning keys. The revocation
# demo (.scripts/demo-revoke.sh) uses a fresh `mktemp -d` instead.
#
#   WIRES_DEMO_DIR   shared state dir (default /tmp/wires-demo)
#   RUST_LOG         log level (default info)

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
WIRES="${WIRES_BIN:-$repo/bazel-bin/wires/wires}"
DEMO="${WIRES_DEMO_DIR:-/tmp/wires-demo}"
agt="$DEMO/agent"

log() { printf '\033[35m[connect]\033[0m %s\n' "$*" >&2; }

if [ ! -x "$WIRES" ]; then
	log "building //wires (first run) ..."
	bazel build //wires >/dev/null 2>&1
fi

# Wait for serve-rg.sh to publish the ticket + membership (and the agent key it
# provisioned).
log "waiting for $DEMO/ticket (start ./.scripts/serve-rg.sh first) ..."
for _ in $(seq 1 100); do
	[ -s "$DEMO/ticket" ] && [ -s "$DEMO/membership" ] && [ -f "$agt/node.seed" ] && break
	sleep 0.2
done
if [ ! -s "$DEMO/ticket" ] || [ ! -s "$DEMO/membership" ] || [ ! -f "$agt/node.seed" ]; then
	log "no ticket/membership yet — is ./.scripts/serve-rg.sh running?"
	exit 1
fi

ticket="$(cat "$DEMO/ticket")"

# Install the membership once, into the agent's keystore. After this the dial
# is the drop-in form -- `wires connect --ticket <T>` and nothing else, which
# is exactly what goes in an MCP client's `command` / `args`.
WIRES_HOME="$agt" "$WIRES" import --membership-file "$DEMO/membership" >/dev/null
log "dialing the rg responder over wires (piping stdin through to rg) ..."

# Use the agent's node key (the membership's member and the grant's subject).
# connect presents the installed membership + the ticket and bridges our stdio.
exec env WIRES_HOME="$agt" RUST_LOG="${RUST_LOG:-info}" \
	"$WIRES" connect --ticket "$ticket"
