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
#   observer  -- `wires watch`: holds neither the agent's nor the
#                workbench's credentials, and sees every call anyway.
#   agent     -- `wires login` (IdP) then `wires call db_query …` and
#                `wires mcp` (JSON-RPC over pipes).
#   root      -- the admin: `wires init`, one `wires invite` per machine
#                (each joins with `wires join <token>`), and later
#                `wires remove agent` -- re-keys ride the channel, so nobody
#                imports anything.
#
# The IdP is a hermetic loopback OIDC issuer (`wires dev-mock-idp`, compiled
# only with `--features dev-mock-idp` -- never the shipped binary). `wires login
# --no-browser` prints the sign-in URL and `curl` plays the browser: the mock
# redirects straight back to the login's loopback callback with a code.
# Card 08 swaps it for real Google.
#
# Asserted: the agent finds db_query through the workbench's announcement on
# the channel, visible only once it signs in as an analyst; a signed-in
# non-analyst sees nothing and is refused by name; an unverified caller is
# refused (and the refusal is on the channel); after login, the observer sees a verified identity line and ▶/■
# for each call naming the agent's email and its SQL (args, stdin, and MCP);
# `.shell id` is refused by sqlite's -safe mode with a nonzero exit on the
# channel; the workbench pushes to the agent by key (`wires push`), which has
# no daemon: `wires inbox` fetches it (the line names the verified host), the
# observer sees ⇢ queued/fetched, and `inbox --wait` wakes on the next push
# (124 on `--timeout`); after the admin removes the agent, the workbench and the observer
# adopt the new roster off the channel with no import, the next call exits 77
# with zero stdout bytes and a ✗ line on the channel, and pushes to it are
# refused at send and at fetch (77); the responder is one
# process (same pid) throughout.
#
# Builds with Cargo (release) on first use; WIRES_BIN / WIRES_DEV_BIN override.
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
# One crate, two builds: `wires-mock-idp` adds only the hidden `dev-mock-idp`
# subcommand. Everything the demo proves runs on the shipped `wires`.
WIRES="${WIRES_BIN:-$repo/target/release/wires}"
WIRES_DEV="${WIRES_DEV_BIN:-$repo/target/release/wires-mock-idp}"
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

if [ -z "${WIRES_BIN:-}" ]; then
	say "cargo build --release (the mock-IdP build first, then the shipped one) ..."
	# Same target dir, so the second build only recompiles the wires crate; the
	# feature build is copied aside before the shipped build replaces it.
	cargo build -q --release -p wires --features dev-mock-idp
	cp -f target/release/wires "$WIRES_DEV"
	cargo build -q --release -p wires
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

# The admin starts the fabric (and is a member itself); every other machine
# makes its key and hands the admin its id. One invite token back each.
ROOT_ID="$(WIRES_HOME="$root" "$WIRES" init --channel "$TOPIC" | awk '/^fabric /{print $2}')"
WB_ID="$(WIRES_HOME="$wb" "$WIRES" id 2>/dev/null)"
AG_ID="$(WIRES_HOME="$agent" "$WIRES" id 2>/dev/null)"
OB_ID="$(WIRES_HOME="$obs" "$WIRES" id 2>/dev/null)"
[ -n "$ROOT_ID" ] && [ -n "$WB_ID" ] && [ -n "$AG_ID" ] && [ -n "$OB_ID" ] ||
	bad "setup: could not read the key ids"
AG8="${AG_ID:0:8}"
# The workbench first: it will be everyone else's bootstrap peer.
WB_TOKEN="$(WIRES_HOME="$root" "$WIRES" invite "$WB_ID" --name workbench 2>/dev/null)"
WIRES_HOME="$wb" "$WIRES" join "$WB_TOKEN" >/dev/null

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
# The workbench's ticket goes into the invites, so every joiner bootstraps
# from it; its tools come over the channel (card 15) -- nothing is decoded
# or configured by hand.
TICKET="$(grep -m1 '^share to bootstrap: ' "$D/wb.err" | sed 's/^share to bootstrap: //')"
[ -n "$TICKET" ] || bad "1: the workbench printed an empty ticket"
ok "1: workbench is pid $WB_PID, reachable by key ${WB_ID:0:8}... -- one tool, nothing else"
# Setup, continued: the agent and the observer are invited now that the
# workbench is up -- each invite is a commit, published to the workbench as a
# re-key (no import there) -- and join with their one token.
AG_TOKEN="$(WIRES_HOME="$root" "$WIRES" invite "$AG_ID" --name agent --peer "$TICKET" 2>"$D/invite.err")" || {
	cat "$D/invite.err" >&2
	bad "setup: inviting the agent failed"
}
OB_TOKEN="$(WIRES_HOME="$root" "$WIRES" invite "$OB_ID" --name observer 2>>"$D/invite.err")" || {
	cat "$D/invite.err" >&2
	bad "setup: inviting the observer failed"
}
grep -qF "re-key published on the channel" "$D/invite.err" || {
	cat "$D/invite.err" >&2
	bad "setup: the invites' re-keys never reached the workbench"
}
WIRES_HOME="$agent" "$WIRES" join "$AG_TOKEN" >/dev/null
WIRES_HOME="$obs" "$WIRES" join "$OB_TOKEN" >/dev/null
beat 2

# ==========================================================================
step "2  the observer tails the channel -- no key to the agent or the workbench"
# ==========================================================================
run "WIRES_OIDC_ISSUER=$ISSUER WIRES_OIDC_AUDIENCE=$CLIENT_ID wires watch   # the channel and peers came with the invite"
WIRES_HOME="$obs" WIRES_OIDC_ISSUER="$ISSUER" WIRES_OIDC_AUDIENCE="$CLIENT_ID" \
	"$WIRES" watch >"$D/obs.out" 2>"$D/obs.err" &
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
# Nothing is configured by hand: the workbench announces its tools on the
# channel, each one sealed to the members allowed to run it. Before login the
# agent is allowed nothing, so it sees that the workbench exists -- and no
# more.
run "wires tools"
WIRES_HOME="$agent" "$WIRES" tools >"$D/t0.out" 2>"$D/t0.err" || {
	cat "$D/t0.err" >&2
	bad "3: wires tools failed"
}
grep -qF "db_query" "$D/t0.out" && {
	cat "$D/t0.out" >&2
	bad "3: db_query is visible to the agent before it signed in"
}
grep -qF "announces nothing you may use: ${WB_ID:0:8}" "$D/t0.err" || {
	cat "$D/t0.err" >&2
	bad "3: the workbench's announcement never reached the agent"
}
show "$D/t0.err"
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
run "wires login --topic $TOPIC --issuer $ISSUER --client-id $CLIENT_ID --no-browser"
WIRES_HOME="$agent" "$WIRES" login --topic "$TOPIC" \
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
# The workbench verified the same claim, found the agent in role analyst, and
# re-announced with db_query sealed to the agent's key.
run "wires tools"
for _ in $(seq 1 10); do
	WIRES_HOME="$agent" "$WIRES" tools >"$D/t1.out" 2>"$D/t1.err" || true
	grep -qF "db_query  on ${WB_ID:0:8}" "$D/t1.out" && break
done
grep -qF "db_query  on ${WB_ID:0:8}" "$D/t1.out" || {
	cat "$D/t1.out" "$D/t1.err" >&2
	bad "4: the signed-in analyst does not see db_query"
}
show "$D/t1.out"
ok "4: signed in as an analyst, the agent now sees db_query -- no tools.json, no ticket"
beat 3

# ==========================================================================
step "4b a signed-in NON-analyst sees nothing -- and asking by name is refused"
# ==========================================================================
# The observer is a member too. It signs in as bob@other.org (the stand-in
# IdP takes a login_hint), whom host.json puts in no role.
OTHER="bob@other.org"
run "wires login --topic $TOPIC …   # as $OTHER, on the observer"
WIRES_HOME="$obs" "$WIRES" login --topic "$TOPIC" \
	--issuer "$ISSUER" --client-id "$CLIENT_ID" --client-secret not-so-secret \
	--no-browser >"$D/login2.out" 2>"$D/login2.err" &
LOGIN_PID=$!
wait_for "$D/login2.err" "sign in at" 100 || bad "4b: login printed no sign-in URL"
URL="$(grep -m1 -E '^  https?://' "$D/login2.err" | sed 's/^  //')"
curl -fsSL -o /dev/null "$URL&login_hint=$OTHER" || bad "4b: the sign-in round trip failed"
wait "$LOGIN_PID" || {
	sed 's/^/  login| /' "$D/login2.err" >&2
	bad "4b: wires login failed"
}
wait_line "$D/obs.out" "🪪 identity ${OB_ID:0:8} is $OTHER" >/dev/null || {
	dump "$D/login2.err"
	bad "4b: $OTHER's claim never reached the channel"
}
run "wires tools"
WIRES_HOME="$obs" "$WIRES" tools >"$D/t2.out" 2>"$D/t2.err" || {
	cat "$D/t2.err" >&2
	bad "4b: wires tools failed"
}
grep -qF "db_query" "$D/t2.out" && {
	cat "$D/t2.out" >&2
	bad "4b: $OTHER can see db_query"
}
grep -qF "announces nothing you may use: ${WB_ID:0:8}" "$D/t2.err" || {
	cat "$D/t2.err" >&2
	bad "4b: the observer's directory does not know the workbench"
}
show "$D/t2.err"
run "wires call db_query -- 'select 1'"
set +e
WIRES_HOME="$obs" "$WIRES" call db_query -- "select 1" >"$D/c9.out" 2>"$D/c9.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] || {
	dump "$D/c9.err"
	bad "4b: $OTHER's call exited $rc, expected $EXIT_DENIED"
}
grep -qF "identity $OTHER" "$D/c9.err" && grep -qF "is in no role allowed to run db_query" "$D/c9.err" || {
	cat "$D/c9.err" >&2
	bad "4b: refused, but not for the role"
}
show "$D/c9.err"
ok "4b: $OTHER sees no db_query, and naming it anyway gets exit $EXIT_DENIED with the reason"
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
step "6b the workbench pushes to the agent -- by key; the agent exposes nothing"
# ==========================================================================
# The agent runs no daemon here: the push is queued on the workbench, and the
# agent's next `wires inbox` fetches it. `--wait` is the same fetch, held open.
run "wires inbox --wait --timeout 1s   # nothing yet"
set +e
WIRES_HOME="$agent" "$WIRES" inbox --wait --timeout 1s >"$D/i0.out" 2>"$D/i0.err"
rc=$?
set -e
[ "$rc" -eq 124 ] || {
	cat "$D/i0.err" >&2
	bad "6b: an empty inbox --wait --timeout exited $rc, expected 124"
}
[ ! -s "$D/i0.out" ] || bad "6b: an empty inbox printed something"
run "wires push --to $AG8… --subject build-41 -- 'failed: test_orders_total'   # on the workbench"
WIRES_HOME="$wb" "$WIRES" push --to "$AG_ID" --subject build-41 -- "failed: test_orders_total" \
	>"$D/p1.out" 2>"$D/p1.err" || {
	cat "$D/p1.out" "$D/p1.err" >&2
	bad "6b: wires push failed"
}
grep -qE "^queued +$EMAIL \($AG8\)" "$D/p1.out" || {
	cat "$D/p1.out" >&2
	bad "6b: the push was not queued for $EMAIL"
}
show "$D/p1.out"
PQ="$(wait_line "$D/obs.out" "⇢" "→ $EMAIL" "[analyst] \"build-41\" queued")" || {
	dump
	bad "6b: no ⇢ queued on the channel"
}
run "wires inbox"
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i1.out" 2>"$D/i1.err" || {
	cat "$D/i1.err" >&2
	bad "6b: wires inbox failed"
}
grep -qF "from host ${WB_ID:0:8} (verified)  build-41  failed: test_orders_total" "$D/i1.out" || {
	cat "$D/i1.out" "$D/i1.err" >&2
	bad "6b: the inbox line does not name the verified host and the message"
}
show "$D/i1.out"
PF="$(wait_line "$D/obs.out" "⇢" "→ $EMAIL" "\"build-41\" fetched")" || {
	dump
	bad "6b: no ⇢ fetched on the channel"
}
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i2.out" 2>/dev/null
[ ! -s "$D/i2.out" ] || bad "6b: a read message was printed twice"
# --wait: held open until a push lands.
run "wires inbox --wait --timeout 20s &   then, on the workbench: wires push … build-42"
WIRES_HOME="$agent" "$WIRES" inbox --wait --timeout 20s >"$D/i3.out" 2>"$D/i3.err" &
WAIT_PID=$!
sleep 1
WIRES_HOME="$wb" "$WIRES" push --to "$AG_ID" --subject build-42 -- "passed" >/dev/null 2>"$D/p2.err" ||
	bad "6b: the second push failed"
wait "$WAIT_PID" || {
	cat "$D/i3.err" >&2
	bad "6b: inbox --wait did not exit 0 on the push"
}
grep -qF "build-42  passed" "$D/i3.out" || bad "6b: inbox --wait did not print build-42"
ok "6b: pushed by key, fetched with no daemon and no open port; --wait woke on the next one"
line "$(cat "$D/i1.out")"
line "$PQ"
line "$PF"
beat 3

# ==========================================================================
step "7  the human removes the agent -- one command, nobody restarts or imports"
# ==========================================================================
run "wires remove agent"
WIRES_HOME="$root" "$WIRES" remove agent >"$D/remove.out" 2>"$D/remove.err" || {
	cat "$D/remove.err" >&2
	bad "7: wires remove failed"
}
grep -qF "re-key published on the channel" "$D/remove.err" || {
	cat "$D/remove.err" >&2
	bad "7: the removal's re-key never reached the channel"
}
# No import anywhere: the workbench and the observer adopt the re-key off the
# channel. Their stored heads catching up with the admin's is the proof.
for h in "$wb" "$obs"; do
	for _ in $(seq 1 200); do
		cmp -s "$root/roster-head.json" "$h/roster-head.json" && break
		sleep 0.1
	done
	cmp -s "$root/roster-head.json" "$h/roster-head.json" ||
		bad "7: $(basename "$h") never adopted the new roster head"
done
ok "7: the workbench and the observer adopted the new roster off the channel -- no import"
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
# Removal cuts pushes the way it cuts calls: refused at send, and at fetch.
set +e
WIRES_HOME="$wb" "$WIRES" push --to "$AG_ID" --subject after-removal -- "x" >"$D/p3.out" 2>"$D/p3.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] && grep -qF "not in the channel's current roster" "$D/p3.out" || {
	cat "$D/p3.out" "$D/p3.err" >&2
	bad "7: a push to the removed agent exited $rc, expected $EXIT_DENIED"
}
set +e
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i4.out" 2>"$D/i4.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] && [ ! -s "$D/i4.out" ] || {
	cat "$D/i4.out" "$D/i4.err" >&2
	bad "7: the removed agent's inbox exited $rc, expected $EXIT_DENIED and nothing"
}
wait_line "$D/obs.out" "⇢" "\"after-removal\" denied" >/dev/null || {
	dump
	bad "7: the refused push is not on the channel"
}
ok "7: and no pushes -- refused at send and at fetch (exit $EXIT_DENIED), on the channel"
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
printf '     push      : host -> agent by key, queued then fetched by `wires inbox`; ⇢ records on the channel\n' >&2
printf '     revoke    : one `wires remove` -> exit 77, 0 bytes out, ✗ on the channel; no import anywhere\n' >&2
printf '     restarts  : 0 -- workbench pid %s throughout; %ss wall clock\n' "$WB_PID" "$((SECONDS - START))" >&2
[ -z "$KEEP" ] || say "state kept in $D (observer transcript: $D/obs.out)"
