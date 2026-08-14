#!/usr/bin/env bash
#
# Demo: revocation, without re-keying anything.
#
# Act 1 dials an MCP server over wires and gets the secret. Act 2 is one line
# from the operator -- either advancing the roster head with the agent left out
# (`--mode roster`, the default) or appending the agent to the responder's CRL
# (`--mode crl`). Act 3 reruns the IDENTICAL dial: same ticket, same key, same
# proof file, same responder process. It exits 77 with zero bytes on stdout.
#
# Nothing was re-keyed, nothing re-imaged, no token re-issued, no auth server
# contacted -- and the responder was never restarted. `wires serve` re-reads
# `crl.json` and `roster-head.json` per connection.
#
# Unlike serve-rg.sh / connect.sh (which keep sticky state in $WIRES_DEMO_DIR
# for fast iteration on the happy path), this script provisions a fresh
# `mktemp -d` every run: a stale state dir silently poisons a rerun.
#
# Run it directly from the repo root -- NOT via `bazel run //.scripts:...`.
#
#   ./.scripts/demo-revoke.sh                 roster mode, paced for capture
#   ./.scripts/demo-revoke.sh --mode crl      CRL mode
#   ./.scripts/demo-revoke.sh --quiet         assertions only
#   ./.scripts/demo-revoke.sh --keep          leave the state dir behind
#
# Note: each dial spends ~1s in n0 discovery even though the ticket carries a
# direct 127.0.0.1 address. There is no --offline flag; a recording absorbs it.

set -euo pipefail

MODE="roster"
QUIET=""
KEEP=""
while [ $# -gt 0 ]; do
	case "$1" in
	--mode)
		MODE="${2:-}"
		shift 2
		;;
	--mode=*)
		MODE="${1#--mode=}"
		shift
		;;
	--quiet)
		QUIET=1
		shift
		;;
	--keep)
		KEEP=1
		shift
		;;
	*)
		printf 'usage: %s [--mode roster|crl] [--quiet] [--keep]\n' "$0" >&2
		exit 2
		;;
	esac
done
case "$MODE" in
roster | crl) ;;
*)
	printf 'unknown --mode %s (want roster or crl)\n' "$MODE" >&2
	exit 2
	;;
esac

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
WIRES="${WIRES_BIN:-$repo/bazel-bin/wires/wires}"
SCOPE="mcp.demo"
EXIT_DENIED=77

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
# Print a long line indented and wrapped to 80 columns, in an ANSI color.
wrapped() {
	printf '%s\n' "$2" | fold -s -w 72 | while IFS= read -r l; do
		printf '\033[%sm     %s\033[0m\n' "$1" "$l" >&2
	done
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

# Every 2026-07-28 client request carries its protocol version and client
# capabilities in `_meta` -- the rev is stateless.
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}'

# The one MCP conversation both acts run, verbatim.
dial() {
	printf '%s\n' \
		'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{'"$META"'}}' \
		'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{'"$META"'}}' \
		'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_secret_of_the_day","arguments":{},'"$META"'}}' |
		WIRES_HOME="$agt" "$WIRES" connect --ticket "$TICKET" >"$1" 2>"$2"
}

# ==========================================================================
# Setup (off camera): operator + server + agent, roster v1, responder up.
# ==========================================================================
op="$D/operator"
srv="$D/server"
agt="$D/agent"
mkdir -p "$op" "$srv" "$agt"

WIRES_HOME="$op" "$WIRES" keygen --save-root >/dev/null
WIRES_HOME="$srv" "$WIRES" keygen --save-node >/dev/null
WIRES_HOME="$agt" "$WIRES" keygen --save-node >/dev/null

node_id() { "$WIRES" keygen --node-seed "$(tr -d '\n' <"$1/node.seed")" | awk '/^node_id/{print $2}'; }
ROOT_ID="$("$WIRES" keygen --root-seed "$(tr -d '\n' <"$op/root.seed")" | awk '/^root_id/{print $2}')"
SERVER_ID="$(node_id "$srv")"
AGENT_ID="$(node_id "$agt")"

WIRES_HOME="$op" "$WIRES" roster add --member "$SERVER_ID" >/dev/null
WIRES_HOME="$op" "$WIRES" roster add --member "$AGENT_ID" >/dev/null
commit="$(WIRES_HOME="$op" "$WIRES" roster commit --ttl 3600 --out "$D/proofs")"
HEAD="$(printf '%s\n' "$commit" | awk '/^head /{print $2}')"

WIRES_HOME="$op" "$WIRES" member --subject "$SERVER_ID" --ttl 3600 >"$D/server-membership"
WIRES_HOME="$op" "$WIRES" member --subject "$AGENT_ID" --ttl 3600 >"$D/agent-membership"
WIRES_HOME="$srv" "$WIRES" import \
	--membership-file "$D/server-membership" \
	--inclusion-proof-file "$D/proofs/$SERVER_ID.proof" \
	--roster-head "$HEAD" >/dev/null
WIRES_HOME="$agt" "$WIRES" import \
	--membership-file "$D/agent-membership" \
	--inclusion-proof-file "$D/proofs/$AGENT_ID.proof" >/dev/null

WIRES_HOME="$srv" "$WIRES" serve \
	--trust-root "$ROOT_ID" \
	--scope "$SCOPE" \
	-- python3 "$repo/.scripts/fake-mcp-server.py" \
	2>"$D/serve.log" &
SERVE_PID=$!
PID_BEFORE="$SERVE_PID"

port=""
for _ in $(seq 1 50); do
	port="$(grep -oE '0\.0\.0\.0:[0-9]+' "$D/serve.log" | head -1 | cut -d: -f2 || true)"
	[ -n "$port" ] && break
	sleep 0.2
done
[ -n "$port" ] || bad "responder never reported a bound port; see $D/serve.log"

TICKET="$(WIRES_HOME="$op" "$WIRES" grant \
	--subject "$AGENT_ID" \
	--target "$SERVER_ID" \
	--scope "$SCOPE" \
	--ttl 3600 \
	--addr "127.0.0.1:$port")"

say "mode          : $MODE"
say "agent  node   : ${AGENT_ID:0:16}..."
say "responder pid : $SERVE_PID on 127.0.0.1:$port (roster v1)"

# ==========================================================================
step "ACT 1  it works"
# ==========================================================================
run "printf '<3 JSON-RPC lines>' | wires connect --ticket \$TICKET"
set +e
dial "$D/before.json" "$D/before.err"
rc_before=$?
set -e

[ "$rc_before" -eq 0 ] || {
	sed 's/^/     /' "$D/before.err" >&2
	bad "act 1: connect exited $rc_before, expected 0"
}
before_lines="$(wc -l <"$D/before.json" | tr -d ' ')"
[ "$before_lines" -eq 3 ] || bad "act 1: expected 3 responses, got $before_lines"
if command -v jq >/dev/null 2>&1; then
	SECRET_TEXT="$(tail -1 "$D/before.json" | jq -r '.result.content[0].text')"
else
	SECRET_TEXT="$(tail -1 "$D/before.json" | python3 -c \
		'import json,sys; print(json.load(sys.stdin)["result"]["content"][0]["text"])')"
fi
case "$SECRET_TEXT" in
*"${AGENT_ID:0:16}"*) : ;;
*) bad "act 1: tool output did not name the caller: $SECRET_TEXT" ;;
esac
ok "act 1: exit 0, 3 JSON-RPC responses, secret revealed"
[ -n "$QUIET" ] || printf '\033[1m     %s\033[0m\n' "$SECRET_TEXT" >&2

# ==========================================================================
step "ACT 2  the operator changes their mind -- one line"
# ==========================================================================
if [ "$MODE" = "roster" ]; then
	run "wires roster remove --member ${AGENT_ID:0:16}...  &&  wires roster commit"
	WIRES_HOME="$op" "$WIRES" roster remove --member "$AGENT_ID" | indent
	commit2="$(WIRES_HOME="$op" "$WIRES" roster commit --ttl 3600 --out "$D/proofs2")"
	HEAD2="$(printf '%s\n' "$commit2" | awk '/^head /{print $2}')"
	say "$(printf '%s\n' "$commit2" | head -1)"
	# A commit bumps the version, which invalidates EVERY member's proof --
	# including the responder's own. So the server re-imports its new proof
	# alongside the new head. That is the whole update: two small tokens.
	run "wires import --inclusion-proof-file P2 --roster-head H2   # server"
	WIRES_HOME="$srv" "$WIRES" import \
		--inclusion-proof-file "$D/proofs2/$SERVER_ID.proof" \
		--roster-head "$HEAD2" | indent
	say "the removed agent gets no new proof. Revocation IS omission --"
	say "the operator will never mint a newer proof for a removed member."
else
	run "wires revoke --subject A        # appends to the server's crl.json"
	WIRES_HOME="$srv" "$WIRES" revoke --subject "$AGENT_ID" | indent
fi

say "no key rotated. No image rebuilt. No token re-issued. No auth server."
if kill -0 "$SERVE_PID" 2>/dev/null; then
	say "the responder is still the same process, pid $SERVE_PID -- not restarted."
else
	bad "act 2: the responder died; the point of this demo is that it does not"
fi

# ==========================================================================
step "ACT 3  the same dial, now dead"
# ==========================================================================
run "printf '<3 JSON-RPC lines>' | wires connect --ticket \$TICKET   # identical"
set +e
dial "$D/after.json" "$D/after.err"
rc_after=$?
set -e

[ "$rc_after" -eq "$EXIT_DENIED" ] || {
	sed 's/^/     /' "$D/after.err" >&2
	bad "act 3: connect exited $rc_after, expected $EXIT_DENIED"
}
ok "act 3: connect exited $EXIT_DENIED (denied)"

[ ! -s "$D/after.json" ] || bad "act 3: stdout was not empty -- the client saw bytes!"
ok "act 3: 0 bytes on stdout -- the MCP client never saw a byte of the tool"

# The reason arrives on the DIALER's terminal. serve.log is not consulted.
REASON="$(grep -m1 'denied by responder' "$D/after.err" || true)"
[ -n "$REASON" ] || {
	sed 's/^/     /' "$D/after.err" >&2
	bad "act 3: the dialer printed no denial reason"
}
[ -n "$QUIET" ] || wrapped 31 "$REASON"

[ "$(kill -0 "$SERVE_PID" 2>/dev/null && echo "$SERVE_PID")" = "$PID_BEFORE" ] ||
	bad "act 3: the responder is not the same live process it was in act 1"
ok "act 3: responder still pid $PID_BEFORE -- never restarted"

# ==========================================================================
step "SUMMARY"
# ==========================================================================
short_reason="${REASON#*denied by responder: }"
printf '     before: exit %-2s · %s responses · secret revealed to %s\n' \
	"$rc_before" "$before_lines" "${AGENT_ID:0:12}..." >&2
printf '     after : exit %-2s · %s bytes on stdout · denied:\n' \
	"$rc_after" "$(wc -c <"$D/after.json" | tr -d ' ')" >&2
wrapped 1 "$short_reason"
