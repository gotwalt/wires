#!/usr/bin/env bash
#
# Demo: run a CLI on another machine from your agent -- reached by key, caller
# verified by an IdP, every call on a channel an observer can watch.
#
# Four keystores on one machine, all loopback:
#
#   workbench -- `wires serve host.json` (.scripts/fixtures/host.json: one
#                tool, db_query, for role analyst = *@example.com, on
#                channel ops). Hosts the channel.
#   observer  -- `wires watch ops`: holds neither the agent's nor the
#                workbench's credentials, and sees every call anyway.
#   agent     -- `wires login` (IdP) then `wires call db_query …` and
#                `wires mcp` (JSON-RPC over pipes).
#   root      -- the human: signs the roster, and later removes the agent.
#
# The IdP is a hermetic loopback OIDC issuer (`wires dev-mock-idp`, built only
# into //wires:wires_dev -- never the shipped binary). `wires login
# --no-browser` prints the sign-in URL and `curl` plays the browser: the mock
# redirects straight back to the login's loopback callback with a code.
# Card 08 swaps it for real Google.
#
# Asserted: an unverified caller is refused (and the refusal is on the
# channel); after login, the observer sees a verified identity line and ▶/■
# for each call naming the agent's email and its SQL (args, stdin, and MCP);
# `.shell id` is refused by sqlite's -safe mode with a nonzero exit on the
# channel; after the root removes the agent, the next call exits 77 with zero
# stdout bytes and a ✗ line on the channel; the responder is one process
# (same pid) throughout.
#
# Run it directly from the repo root -- NOT via `bazel run //.scripts:...`.
#
#   ./.scripts/demo-remote-cli.sh                narrated, paced for watching
#   ./.scripts/demo-remote-cli.sh --quiet        assertions only
#   ./.scripts/demo-remote-cli.sh --keep         leave the state dir behind
#   ./.scripts/demo-remote-cli.sh --with-claude  also let a headless Claude Code
#                                                (`claude -p`, costs money, needs
#                                                auth) query through `wires mcp`

set -euo pipefail

QUIET=""
KEEP=""
WITH_CLAUDE=""
while [ $# -gt 0 ]; do
	case "$1" in
	--quiet)
		QUIET=1
		shift
		;;
	--keep)
		KEEP=1
		shift
		;;
	--with-claude)
		WITH_CLAUDE=1
		shift
		;;
	*)
		printf 'usage: %s [--quiet] [--keep] [--with-claude]\n' "$0" >&2
		exit 2
		;;
	esac
done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
# One crate, two builds: `wires_dev` adds only the hidden `dev-mock-idp`
# subcommand. Everything the demo proves runs on the shipped `wires`.
WIRES="${WIRES_BIN:-$repo/bazel-bin/wires/wires}"
WIRES_DEV="${WIRES_DEV_BIN:-$repo/bazel-bin/wires/wires_dev}"
TOPIC="ops"
EMAIL="alice@example.com"
EXIT_DENIED=77
START=$SECONDS

D="$(mktemp -d)"
IDP_PID=""
WB_PID=""
OBS_PID=""
MCP_PID=""
p=""
trap 'exec 3>&- 2>/dev/null || true; for p in $MCP_PID $OBS_PID $WB_PID $IDP_PID; do kill "$p" 2>/dev/null || true; done; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

say() { [ -n "$QUIET" ] || printf '\033[36m[demo]\033[0m %s\n' "$*" >&2; }
run() { [ -n "$QUIET" ] || printf '\033[2m     $ %s\033[0m\n' "$*" >&2; }
ok() { printf '\033[32m[ok]\033[0m   %s\n' "$*" >&2; }
bad() {
	printf '\033[31m[FAIL]\033[0m %s\n' "$*" >&2
	exit 1
}
step() {
	[ -n "$QUIET" ] || {
		printf '\n\033[1;36m[demo] %s\033[0m\n' "$*" >&2
		sleep 1.5
	}
}
beat() { [ -n "$QUIET" ] || sleep "$1"; }
line() { [ -n "$QUIET" ] || printf '\033[1m     %s\033[0m\n' "$*" >&2; }
show() { [ -n "$QUIET" ] || sed 's/^/     /' "$1" >&2; }

# Poll a file for a fixed string. $3 is the budget in tenths of a second.
wait_for() {
	local file="$1" s="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && grep -qF -- "$s" "$file"; then return 0; fi
		sleep 0.1
	done
	return 1
}
# Poll for one line of $1 containing every remaining fixed string. Budget: 20 s.
wait_line() {
	local file="$1"
	shift
	for _ in $(seq 1 200); do
		if [ -e "$file" ]; then
			local hits
			hits="$(cat "$file")"
			for s in "$@"; do hits="$(printf '%s\n' "$hits" | grep -F -- "$s" || true)"; done
			if [ -n "$hits" ]; then
				printf '%s\n' "$hits" | tail -1
				return 0
			fi
		fi
		sleep 0.1
	done
	return 1
}
# The observer's transcript, for failure messages.
dump() {
	sed 's/^/  observer| /' "$D/obs.out" >&2 || true
	[ -z "${1:-}" ] || sed 's/^/  '"$(basename "$1")"'| /' "$1" | tail -20 >&2
}
alive() { kill -0 "$1" 2>/dev/null; }
# The call id on a ▶/■ line (`HH:MM:SS <responder8> ▶ <id> …`), so a ■ can be
# pinned to its ▶.
call_id() { printf '%s\n' "$1" | awk '{print $4}'; }

if [ ! -x "$WIRES" ] || [ ! -x "$WIRES_DEV" ]; then
	say "building //wires:wires and //wires:wires_dev (first run) ..."
	bazel build //wires:wires //wires:wires_dev >/dev/null 2>&1
fi
command -v sqlite3 >/dev/null || bad "sqlite3 is not on PATH"
command -v curl >/dev/null || bad "curl is not on PATH"

# ==========================================================================
# Setup (off camera): four keystores, one roster, one database, one IdP.
# ==========================================================================
root="$D/root"
wb="$D/workbench"
agent="$D/agent"
obs="$D/observer"
mkdir -p "$root" "$wb" "$agent" "$obs"

WIRES_HOME="$root" "$WIRES" advanced keygen --save-root >/dev/null
for h in "$wb" "$agent" "$obs"; do WIRES_HOME="$h" "$WIRES" advanced keygen --save-node >/dev/null; done
ROOT_ID="$(WIRES_HOME="$root" "$WIRES" advanced keygen --root-seed "$(tr -d '\n' <"$root/root.seed")" | awk '/^root_id/{print $2}')"
node_id() { "$WIRES" advanced keygen --node-seed "$(tr -d '\n' <"$1/node.seed")" | awk '/^node_id/{print $2}'; }
WB_ID="$(node_id "$wb")"
AG_ID="$(node_id "$agent")"
OB_ID="$(node_id "$obs")"
[ -n "$ROOT_ID" ] && [ -n "$WB_ID" ] && [ -n "$AG_ID" ] && [ -n "$OB_ID" ] ||
	bad "setup: could not read the key ids"
AG8="${AG_ID:0:8}"

for id in "$WB_ID" "$AG_ID" "$OB_ID"; do
	WIRES_HOME="$root" "$WIRES" advanced roster add --member "$id" >/dev/null
	WIRES_HOME="$root" "$WIRES" advanced member --subject "$id" --ttl 3600 >"$D/$id.member"
done
commit1="$(WIRES_HOME="$root" "$WIRES" advanced roster commit --ttl 3600 --out "$D/v1")"
HEAD1="$(printf '%s\n' "$commit1" | awk '/^head /{print $2}')"
refresh() { # $1 = home, $2 = node id, $3 = proof dir, $4 = head token
	WIRES_HOME="$1" "$WIRES" advanced import \
		--membership-file "$D/$2.member" \
		--inclusion-proof-file "$3/$2.proof" \
		--roster-head "$4" \
		--fabric-key-file "$3/$2.key" >/dev/null
}
refresh "$wb" "$WB_ID" "$D/v1" "$HEAD1"
refresh "$agent" "$AG_ID" "$D/v1" "$HEAD1"
refresh "$obs" "$OB_ID" "$D/v1" "$HEAD1"

DB="$D/orders.db"
sqlite3 "$DB" <"$repo/.scripts/fixtures/orders.sql"
ORDERS="$(sqlite3 "$DB" 'select count(*) from orders')"

"$WIRES_DEV" dev-mock-idp --email "$EMAIL" >"$D/idp.out" 2>"$D/idp.err" &
IDP_PID=$!
wait_for "$D/idp.out" "client_id " 100 || bad "setup: the mock IdP did not start; see $D/idp.err"
ISSUER="$(awk '/^issuer /{print $2}' "$D/idp.out")"
CLIENT_ID="$(awk '/^client_id /{print $2}' "$D/idp.out")"

say "four keystores on this machine stand in for four machines:"
say "  workbench  ${WB_ID:0:8}...  runs sqlite3 on orders.db; exposes one tool, nothing else"
say "  agent      ${AG8}...  your agent's machine"
say "  observer   ${OB_ID:0:8}...  someone you trust to watch; holds neither end's keys"
say "  root       the human who signs the list of members"
say "and a stand-in IdP at $ISSUER (card 08 swaps in Google)."
beat 5

# ==========================================================================
step "1  the workbench exposes ONE CLI, and requires a verified identity"
# ==========================================================================
# host.json is the fixture with the stand-in IdP's issuer and client id filled
# in; its db_query command names `orders.db`, relative to the workbench's cwd.
HOST_JSON="$D/host.json"
sed -e "s|__ISSUER__|$ISSUER|" -e "s|__CLIENT_ID__|$CLIENT_ID|" \
	"$repo/.scripts/fixtures/host.json" >"$HOST_JSON"
run "wires serve --check host.json"
"$WIRES" serve --check "$HOST_JSON" >"$D/check.out" 2>&1 || {
	dump "$D/check.out"
	bad "1: serve --check rejected host.json"
}
grep -qF "db_query  may run: analyst" "$D/check.out" || {
	dump "$D/check.out"
	bad "1: serve --check did not say who may run db_query"
}
show "$D/check.out"
run "wires serve host.json"
(cd "$D" && WIRES_HOME="$wb" exec "$WIRES" serve "$HOST_JSON" >"$D/wb.out" 2>"$D/wb.err") &
WB_PID=$!
wait_for "$D/wb.err" "share to bootstrap: " 300 || {
	sed 's/^/  workbench| /' "$D/wb.err" >&2
	bad "1: the workbench never printed its audit-topic ticket"
}
# The one thing the workbench hands out: its audit-topic ticket. The observer
# bootstraps from it, and the agent's `tools add --topic-ticket` takes the
# workbench's key and addresses from it -- nothing is decoded by hand.
TICKET="$(grep -m1 '^share to bootstrap: ' "$D/wb.err" | sed 's/^share to bootstrap: //')"
[ -n "$TICKET" ] || bad "1: the workbench printed an empty ticket"
ok "1: workbench is pid $WB_PID, reachable by key ${WB_ID:0:8}... -- one tool, nothing else"
beat 2

# ==========================================================================
step "2  the observer tails the channel -- no key to the agent or the workbench"
# ==========================================================================
run "WIRES_OIDC_ISSUER=$ISSUER WIRES_OIDC_AUDIENCE=$CLIENT_ID wires watch $TOPIC --peer \$TICKET"
WIRES_HOME="$obs" WIRES_OIDC_ISSUER="$ISSUER" WIRES_OIDC_AUDIENCE="$CLIENT_ID" \
	"$WIRES" watch "$TOPIC" --peer "$TICKET" >"$D/obs.out" 2>"$D/obs.err" &
OBS_PID=$!
wait_for "$D/obs.err" "neighbor up" 300 || {
	sed 's/^/  observer| /' "$D/obs.err" >&2
	bad "2: the observer never joined the workbench's mesh"
}
ok "2: observer is live on '$TOPIC'"
beat 2

# ==========================================================================
step "3  the agent calls before signing in -- refused, and the refusal is public"
# ==========================================================================
run "wires tools add db_query --topic-ticket \$TICKET --description '…'"
WIRES_HOME="$agent" "$WIRES" tools add db_query --topic-ticket "$TICKET" \
	--description "Read-only SQL (sqlite3) over the workbench's orders.db; pass the SQL statement as the argument." >/dev/null
grep -q "\"$WB_ID\"" "$agent/tools.json" || {
	dump "$agent/tools.json"
	bad "3: tools add --topic-ticket did not target the workbench's key"
}
run "wires call db_query -- 'select count(*) from orders'"
set +e
WIRES_HOME="$agent" "$WIRES" call db_query -- "select count(*) from orders" >"$D/c0.out" 2>"$D/c0.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] || {
	dump "$D/c0.err"
	bad "3: an unverified call exited $rc, expected $EXIT_DENIED"
}
grep -qF "no identity claim" "$D/c0.err" || {
	dump "$D/c0.err"
	bad "3: refused, but not for the missing identity"
}
[ ! -s "$D/c0.out" ] || bad "3: the refused call wrote to stdout"
DENY0="$(wait_line "$D/obs.out" "✗ ${AG_ID:0:4}… db_query denied: no identity claim for $AG8")" || {
	dump
	bad "3: the no-identity refusal never reached the observer"
}
ok "3: exit $EXIT_DENIED -- no verified identity, no sqlite3; the observer saw it"
line "$DENY0"
beat 3

# ==========================================================================
step "4  the agent signs in with its IdP -- the token is bound to its node key"
# ==========================================================================
run "wires login --topic $TOPIC --peer \$TICKET --issuer $ISSUER --client-id $CLIENT_ID --no-browser"
WIRES_HOME="$agent" "$WIRES" login --topic "$TOPIC" --peer "$TICKET" \
	--issuer "$ISSUER" --client-id "$CLIENT_ID" --client-secret not-so-secret \
	--no-browser >"$D/login.out" 2>"$D/login.err" &
LOGIN_PID=$!
wait_for "$D/login.err" "sign in at" 100 || {
	sed 's/^/  login| /' "$D/login.err" >&2
	bad "4: login printed no sign-in URL"
}
URL="$(grep -m1 -E '^  https?://' "$D/login.err" | sed 's/^  //')"
# The "browser": the mock IdP 302s straight to the login's loopback callback.
curl -fsSL -o /dev/null "$URL" || bad "4: the sign-in round trip failed"
wait "$LOGIN_PID" || {
	sed 's/^/  login| /' "$D/login.err" >&2
	bad "4: wires login failed"
}
grep -qF "is $EMAIL" "$D/login.err" || bad "4: login did not bind $EMAIL"
IDLINE="$(wait_line "$D/obs.out" "🪪 identity $AG8 is $EMAIL (verified by $ISSUER)")" || {
	dump "$D/login.err"
	bad "4: the observer never verified the agent's identity"
}
ok "4: the observer checked the IdP's signature itself -- no wires attestor"
line "$IDLINE"
beat 3

# ==========================================================================
step "5  the agent runs SQL on the workbench -- args, stdin, and MCP"
# ==========================================================================
run "wires call db_query -- 'select count(*) from orders'"
WIRES_HOME="$agent" "$WIRES" call db_query -- "select count(*) from orders" >"$D/c1.out" 2>"$D/c1.err" ||
	{
		dump "$D/c1.err"
		bad "5: the args call failed"
	}
grep -qx "$ORDERS" <(tr -d ' ' <"$D/c1.out") || {
	cat "$D/c1.out" >&2
	bad "5: expected $ORDERS orders"
}
[ ! -s "$D/c1.err" ] || {
	cat "$D/c1.err" >&2
	bad "5: a successful call wrote to stderr"
}
show "$D/c1.out"
S1="$(wait_line "$D/obs.out" "▶" "$EMAIL" "[analyst] db_query \"select count(*) from orders\"")" || {
	dump
	bad "5: no ▶ for the args call"
}
F1="$(wait_line "$D/obs.out" "■ $(call_id "$S1") exit 0 ")" || {
	dump
	bad "5: no ■ exit 0 for the args call"
}
ok "5a: args call -- the observer saw who ran what"
line "$S1"
line "$F1"
beat 2

SQL2="select customer, sum(total) from orders group by customer order by 2 desc"
run "echo '$SQL2' | wires call db_query"
printf '%s\n' "$SQL2" | WIRES_HOME="$agent" "$WIRES" call db_query >"$D/c2.out" 2>"$D/c2.err" ||
	{
		dump "$D/c2.err"
		bad "5: the stdin call failed"
	}
grep -q "umbrella" "$D/c2.out" || {
	cat "$D/c2.out" >&2
	bad "5: the stdin call returned the wrong rows"
}
show "$D/c2.out"
F2="$(wait_line "$D/obs.out" "■" "exit 0" "stdin \"select customer, sum(total) from orders")" || {
	dump
	bad "5: the stdin call's SQL is not on the channel"
}
S2="$(grep -F "▶ $(call_id "$F2") " "$D/obs.out" || true)"
printf '%s' "$S2" | grep -qF "$EMAIL (" || {
	dump
	bad "5: the stdin call's ▶ does not name $EMAIL"
}
ok "5b: stdin call -- the SQL is on the channel even though it never was an argument"
line "$S2"
line "$F2"
beat 2

SQL3="select count(distinct customer) from orders"
run "wires mcp   # JSON-RPC over pipes: initialize, tools/list, tools/call"
mkfifo "$D/mcp.in"
WIRES_HOME="$agent" "$WIRES" mcp <"$D/mcp.in" >"$D/mcp.out" 2>"$D/mcp.err" &
MCP_PID=$!
exec 3>"$D/mcp.in"
printf '%s\n' \
	'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}' \
	'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
	'{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
	"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"db_query\",\"arguments\":{\"args\":[\"$SQL3\"]}}}" >&3
wait_for "$D/mcp.out" '"id":3' 200 || {
	sed 's/^/  mcp| /' "$D/mcp.err" >&2
	bad "5: wires mcp never answered tools/call"
}
exec 3>&-
wait "$MCP_PID" 2>/dev/null || true
MCP_PID=""
grep -F '"id":2' "$D/mcp.out" | grep -qF '"db_query"' || bad "5: tools/list does not offer db_query"
RESULT="$(grep -F '"id":3' "$D/mcp.out")"
printf '%s' "$RESULT" | grep -qF '"isError":false' || {
	printf '%s\n' "$RESULT" >&2
	bad "5: the MCP tools/call was an error"
}
printf '%s' "$RESULT" | grep -qE 'distinct customer\)[^0-9]*4' || {
	printf '%s\n' "$RESULT" >&2
	bad "5: the MCP call returned the wrong answer"
}
S3="$(wait_line "$D/obs.out" "▶" "$EMAIL" "db_query \"$SQL3\"")" || {
	dump
	bad "5: no ▶ for the MCP call"
}
F3="$(wait_line "$D/obs.out" "■ $(call_id "$S3") exit 0 ")" || {
	dump
	bad "5: no ■ exit 0 for the MCP call"
}
ok "5c: MCP tools/call -- same tool, same record, same email"
line "$S3"
line "$F3"
beat 2

if [ -n "$WITH_CLAUDE" ]; then
	command -v claude >/dev/null || bad "--with-claude: \`claude\` is not on PATH"
	before="$(grep -cF "▶" "$D/obs.out")"
	MCP_CONFIG="{\"mcpServers\":{\"wires\":{\"command\":\"$WIRES\",\"args\":[\"mcp\"],\"env\":{\"WIRES_HOME\":\"$agent\"}}}}"
	run "claude -p --mcp-config '{…wires mcp…}' --allowedTools mcp__wires__db_query 'Which customer spent the most?'"
	# `--allowedTools` is variadic: the `=` form keeps it from eating the prompt.
	claude -p --mcp-config "$MCP_CONFIG" --allowedTools=mcp__wires__db_query \
		"Using the db_query tool (SQLite, table orders(customer, total, placed_at)), which customer has the highest total spend? Answer with just the customer name." \
		</dev/null >"$D/claude.out" 2>"$D/claude.err" || {
		cat "$D/claude.err" >&2
		bad "claude: claude -p failed"
	}
	show "$D/claude.out"
	grep -qi "umbrella" "$D/claude.out" || bad "claude: Claude's answer does not name umbrella"
	for _ in $(seq 1 100); do
		[ "$(grep -cF "▶" "$D/obs.out")" -gt "$before" ] && break
		sleep 0.1
	done
	[ "$(grep -cF "▶" "$D/obs.out")" -gt "$before" ] || {
		dump
		bad "claude: Claude's calls are not on the channel"
	}
	grep -F "▶" "$D/obs.out" | tail -1 | grep -qF "$EMAIL" || bad "claude: Claude's call does not name $EMAIL"
	ok "claude: Claude Code answered through wires mcp; its SQL is on the channel"
	line "$(grep -F "▶" "$D/obs.out" | tail -1)"
	beat 2
fi

# ==========================================================================
step "6  the agent tries to escape the tool -- sqlite3 -safe refuses"
# ==========================================================================
run "wires call db_query -- '.shell id'"
set +e
WIRES_HOME="$agent" "$WIRES" call db_query -- ".shell id" >"$D/c4.out" 2>"$D/c4.err"
rc=$?
set -e
[ "$rc" -ne 0 ] && [ "$rc" -ne "$EXIT_DENIED" ] || {
	dump "$D/c4.err"
	bad "6: .shell id exited $rc; expected sqlite's own nonzero exit"
}
grep -qE "^uid=" "$D/c4.out" && bad "6: .shell id RAN on the workbench"
grep -qF "cannot run .shell in safe mode" "$D/c4.err" || {
	cat "$D/c4.err" >&2
	bad "6: sqlite3 did not refuse in safe mode"
}
show "$D/c4.err"
S4="$(wait_line "$D/obs.out" "▶" "$EMAIL" "db_query \".shell id\"")" || {
	dump
	bad "6: no ▶ for .shell id"
}
F4="$(wait_line "$D/obs.out" "■ $(call_id "$S4") exit $rc ")" || {
	dump
	bad "6: no ■ exit $rc for .shell id"
}
SHELL_RC=$rc
ok "6: exit $rc from sqlite3 itself -- the attempt is on the channel with who tried it"
line "$S4"
line "$F4"
beat 3

# ==========================================================================
step "7  the human removes the agent -- one commit, nobody restarts"
# ==========================================================================
run "wires advanced roster remove --member ${AG8}...  &&  wires advanced roster commit"
WIRES_HOME="$root" "$WIRES" advanced roster remove --member "$AG_ID" >/dev/null
commit2="$(WIRES_HOME="$root" "$WIRES" advanced roster commit --ttl 3600 --out "$D/v2")"
HEAD2="$(printf '%s\n' "$commit2" | awk '/^head /{print $2}')"
[ -f "$D/v2/$AG_ID.proof" ] && bad "7: the new roster still includes the agent"
run "wires advanced import --roster-head H2 …   # on the workbench and the observer"
refresh "$wb" "$WB_ID" "$D/v2" "$HEAD2"
refresh "$obs" "$OB_ID" "$D/v2" "$HEAD2"
run "wires call db_query -- 'select count(*) from orders'"
set +e
WIRES_HOME="$agent" "$WIRES" call db_query -- "select count(*) from orders" >"$D/c5.out" 2>"$D/c5.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] || {
	dump "$D/c5.err"
	bad "7: the revoked call exited $rc, expected $EXIT_DENIED"
}
[ "$(wc -c <"$D/c5.out" | tr -d ' ')" -eq 0 ] || bad "7: the revoked call wrote $(wc -c <"$D/c5.out") bytes to stdout"
show "$D/c5.err"
DENY5="$(wait_line "$D/obs.out" "✗ ${AG_ID:0:4}… db_query denied: roster")" || {
	dump "$D/c5.err"
	bad "7: the revocation refusal never reached the observer"
}
ok "7: exit $EXIT_DENIED, 0 bytes out -- and the refusal is on the channel"
line "$DENY5"
alive "$WB_PID" || bad "7: the workbench died"
alive "$OBS_PID" || bad "7: the observer died"
ok "7: workbench is still pid $WB_PID -- never restarted, start to finish"
beat 2

# ==========================================================================
step "SUMMARY"
# ==========================================================================
printf '     reach     : by key %s... on loopback; the only thing exposed is db_query\n' "${WB_ID:0:8}" >&2
printf '     identity  : unverified caller refused (77); after login, %s verified by the observer itself\n' "$EMAIL" >&2
printf '     observable: ▶/■ naming %s + the SQL, for args, stdin and MCP calls\n' "$EMAIL" >&2
printf '     contained : .shell id refused by sqlite3 -safe, exit %s on the channel\n' "$SHELL_RC" >&2
printf '     revoke    : one roster commit -> exit 77, 0 bytes out, ✗ on the channel\n' >&2
printf '     restarts  : 0 -- workbench pid %s throughout; %ss wall clock\n' "$WB_PID" "$((SECONDS - START))" >&2
[ -z "$KEEP" ] || say "state kept in $D (observer transcript: $D/obs.out)"
