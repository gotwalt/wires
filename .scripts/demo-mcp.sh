#!/usr/bin/env bash
#
# Demo: an unmodified stdio MCP server, running behind `wires serve` on
# "another machine", driven over a wires session by a dialer that has nothing
# but a ticket. Neither side knows a network is involved.
#
# This is the Phase 1 wedge in one unattended script. It provisions an
# operator/server/agent trio, commits a roster, installs credentials with
# `wires import`, starts the responder over the bundled fake MCP server, and
# drives a real MCP conversation through it -- then ASSERTS that the captured
# stdout is byte-clean JSON-RPC and that the tool's answer names the verified
# caller.
#
# Unlike serve-rg.sh / connect.sh (which keep sticky state in $WIRES_DEMO_DIR
# for fast iteration on the happy path), this script provisions a fresh
# `mktemp -d` every run: a stale state dir silently poisons a rerun.
#
# Run it directly from the repo root -- NOT via `bazel run //.scripts:...`.
#
#   ./.scripts/demo-mcp.sh            narrated, paced for screen capture
#   ./.scripts/demo-mcp.sh --quiet    assertions only
#   ./.scripts/demo-mcp.sh --keep     leave the state dir behind
#
# Note: the first dial spends ~1s in n0 discovery even though the ticket
# carries a direct 127.0.0.1 address. There is no --offline flag; a recording
# absorbs the pause.

set -euo pipefail

QUIET=""
KEEP=""
for arg in "$@"; do
	case "$arg" in
	--quiet) QUIET=1 ;;
	--keep) KEEP=1 ;;
	*)
		printf 'usage: %s [--quiet] [--keep]\n' "$0" >&2
		exit 2
		;;
	esac
done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
WIRES="${WIRES_BIN:-$repo/bazel-bin/wires/wires}"
SCOPE="mcp.demo"

D="$(mktemp -d)"
SERVE_PID=""
trap 'if [ -n "$SERVE_PID" ]; then kill "$SERVE_PID" 2>/dev/null || true; fi; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

say() { [ -n "$QUIET" ] || printf '\033[36m[demo]\033[0m %s\n' "$*" >&2; }
run() { [ -n "$QUIET" ] || printf '\033[2m     $ %s\033[0m\n' "$*" >&2; }
ok() { printf '\033[32m[ok]\033[0m   %s\n' "$*" >&2; }
# Indent a command's stdout under the narration, trimming the (long, random)
# state-dir prefix and wrapping to 80 columns -- and swallow it in --quiet.
indent() {
	if [ -n "$QUIET" ]; then
		cat >/dev/null
	else
		sed "s|$D/||" | fold -s -w 74 | sed 's/^/     /' >&2
	fi
}
bad() {
	printf '\033[31m[FAIL]\033[0m %s\n' "$*" >&2
	exit 1
}
step() {
	[ -n "$QUIET" ] || {
		printf '\n\033[1;36m[demo] %s\033[0m\n' "$*" >&2
		sleep 0.6
	}
}

if [ ! -x "$WIRES" ]; then
	say "building //wires (first run) ..."
	bazel build //wires >/dev/null 2>&1
fi

# --------------------------------------------------------------------------
step "1/5  three keystores: an operator, a server, an agent"
# --------------------------------------------------------------------------
op="$D/operator"
srv="$D/server"
agt="$D/agent"
mkdir -p "$op" "$srv" "$agt"

WIRES_HOME="$op" "$WIRES" keygen --save-root >/dev/null
WIRES_HOME="$srv" "$WIRES" keygen --save-node >/dev/null
WIRES_HOME="$agt" "$WIRES" keygen --save-node >/dev/null

# There is no `wires id`; re-derive the ids from the saved seeds.
node_id() { "$WIRES" keygen --node-seed "$(tr -d '\n' <"$1/node.seed")" | awk '/^node_id/{print $2}'; }
ROOT_ID="$("$WIRES" keygen --root-seed "$(tr -d '\n' <"$op/root.seed")" | awk '/^root_id/{print $2}')"
SERVER_ID="$(node_id "$srv")"
AGENT_ID="$(node_id "$agt")"
say "operator root : ${ROOT_ID:0:16}..."
say "server   node : ${SERVER_ID:0:16}..."
say "agent    node : ${AGENT_ID:0:16}..."

# --------------------------------------------------------------------------
step "2/5  commit a roster over both machines, then \`wires import\`"
# --------------------------------------------------------------------------
run "wires roster add --member <server>; wires roster add --member <agent>"
WIRES_HOME="$op" "$WIRES" roster add --member "$SERVER_ID" >/dev/null
WIRES_HOME="$op" "$WIRES" roster add --member "$AGENT_ID" >/dev/null

run "wires roster commit --ttl 3600 --out \$D/proofs"
commit="$(WIRES_HOME="$op" "$WIRES" roster commit --ttl 3600 --out "$D/proofs")"
HEAD="$(printf '%s\n' "$commit" | awk '/^head /{print $2}')"
say "$(printf '%s\n' "$commit" | head -1)"

WIRES_HOME="$op" "$WIRES" member --subject "$SERVER_ID" --ttl 3600 >"$D/server-membership"
WIRES_HOME="$op" "$WIRES" member --subject "$AGENT_ID" --ttl 3600 >"$D/agent-membership"

# The responder needs its own membership + proof (it presents a HandshakeAck so
# a dialer can verify the service), plus the head it will enforce.
run "# on the server -- it needs its own credentials plus the head:"
run "wires import --membership-file M --inclusion-proof-file P --roster-head H"
WIRES_HOME="$srv" "$WIRES" import \
	--membership-file "$D/server-membership" \
	--inclusion-proof-file "$D/proofs/$SERVER_ID.proof" \
	--roster-head "$HEAD" | indent

run "# on the agent:"
run "wires import --membership-file M --inclusion-proof-file P"
WIRES_HOME="$agt" "$WIRES" import \
	--membership-file "$D/agent-membership" \
	--inclusion-proof-file "$D/proofs/$AGENT_ID.proof" | indent

say "after that one import, \`wires connect --ticket T\` needs no other flags."

# --------------------------------------------------------------------------
step "3/5  the server machine: an MCP server it did not have to modify"
# --------------------------------------------------------------------------
run "wires serve --trust-root R --scope $SCOPE -- python3 fake-mcp-server.py"
WIRES_HOME="$srv" "$WIRES" serve \
	--trust-root "$ROOT_ID" \
	--scope "$SCOPE" \
	-- python3 "$repo/.scripts/fake-mcp-server.py" \
	2>"$D/serve.log" &
SERVE_PID=$!

port=""
for _ in $(seq 1 50); do
	port="$(grep -oE '0\.0\.0\.0:[0-9]+' "$D/serve.log" | head -1 | cut -d: -f2 || true)"
	[ -n "$port" ] && break
	sleep 0.2
done
[ -n "$port" ] || bad "responder never reported a bound port; see $D/serve.log"
say "responder listening (pid $SERVE_PID), dialable at 127.0.0.1:$port"

TICKET="$(WIRES_HOME="$op" "$WIRES" grant \
	--subject "$AGENT_ID" \
	--target "$SERVER_ID" \
	--scope "$SCOPE" \
	--ttl 3600 \
	--addr "127.0.0.1:$port")"
say "minted a ticket for the agent (${#TICKET} base64 chars)"

# --------------------------------------------------------------------------
step "4/5  the client machine: a real MCP conversation over the session"
# --------------------------------------------------------------------------
run "printf '<4 JSON-RPC lines>' | wires connect --ticket \$TICKET >out.json"
# Every 2026-07-28 client request carries its protocol version and client
# capabilities in `_meta` -- the rev is stateless, so nothing is inferred from
# the connection. wires does not read any of it; it moves the bytes.
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}'
set +e
printf '%s\n' \
	'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{'"$META"'}}' \
	'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
	'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{'"$META"'}}' \
	'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_secret_of_the_day","arguments":{},'"$META"'}}' |
	WIRES_HOME="$agt" "$WIRES" connect --ticket "$TICKET" \
		>"$D/out.json" 2>"$D/connect.log"
rc=$?
set -e

# --------------------------------------------------------------------------
step "5/5  assertions -- this is the part that matters"
# --------------------------------------------------------------------------
[ "$rc" -eq 0 ] || {
	sed 's/^/     /' "$D/connect.log" >&2
	bad "connect exited $rc, expected 0"
}
ok "connect exited 0"

lines="$(wc -l <"$D/out.json" | tr -d ' ')"
[ "$lines" -eq 3 ] || bad "expected 3 JSON-RPC responses on stdout, got $lines"
ok "stdout carried exactly 3 JSON-RPC responses ($(wc -c <"$D/out.json" | tr -d ' ') bytes)"

if command -v jq >/dev/null 2>&1; then
	jq -c . <"$D/out.json" >/dev/null || bad "stdout was not clean JSON-RPC"
	last="$(tail -1 "$D/out.json")"
	text="$(printf '%s' "$last" | jq -r '.result.content[0].text')"
else
	while read -r l; do
		printf '%s' "$l" | python3 -m json.tool >/dev/null || bad "stdout was not clean JSON-RPC"
	done <"$D/out.json"
	text="$(tail -1 "$D/out.json" | python3 -c \
		'import json,sys; print(json.load(sys.stdin)["result"]["content"][0]["text"])')"
fi
ok "every line parses as JSON -- no banner, no log line, no framing leaked in"

case "$text" in
*"${AGENT_ID:0:16}"*) ok "the tool named the verified caller: ${AGENT_ID:0:16}..." ;;
*) bad "tool output did not name the caller: $text" ;;
esac
case "$text" in
*"roster v1"*) ok "the tool saw roster version 1" ;;
*) bad "tool output did not carry the roster version: $text" ;;
esac

printf '%s\n' "$TICKET" >"$D/ticket"
[ -n "$QUIET" ] || {
	printf '\n\033[1m  %s\033[0m\n\n' "$text" >&2
	cat >&2 <<-EOF
		  Drop this into any MCP client config -- the server is just there:

		    {"mcpServers": {"demo": {
		      "command": "wires",
		      "args": ["connect", "--ticket", "${TICKET:0:20}...${TICKET: -6}"]
		    }}}

		  Full ticket (rerun with --keep to retain it):
		    $D/ticket
	EOF
}
