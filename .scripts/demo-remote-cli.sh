#!/usr/bin/env bash
#
# Demo: run a CLI on another machine from your agent -- by SERVICE name, the
# machine reached by key, the caller verified by an IdP, every call in the
# host's own signed log that the people the admin names may read.
#
# Five keystores on one machine, all loopback:
#
#   workbench -- `wires serve host.json` (.scripts/fixtures/host.json:
#   spare        implements one service, orders-db, as sqlite3 over orders.db).
#                Two hosts implement it: a caller never names either.
#   agent     -- alice@example.com (role analyst): `wires login`, `wires
#                services`, `wires call orders-db …`, `wires mcp`, `wires inbox`.
#   observer  -- sec@audit.example (role security): allowed to call nothing,
#                allowed to READ orders-db's call records (`wires watch`).
#   root      -- the admin: `wires init`, `role set`, `service add`, one
#                `wires invite` per machine, and later `wires remove agent`.
#                Every change is one signed state, pushed to the hosts by key.
#
# The IdP is a hermetic loopback OIDC issuer (`wires dev-mock-idp`, compiled
# only with `--features dev-mock-idp` -- never the shipped binary). `wires login
# --no-browser` prints the sign-in URL and `curl` plays the browser.
#
# Addressing is by key. n0 discovery finds keys on a real network; here each
# host's `serve` writes its own line to run/hint and the script copies those
# into the other keystores' local, unsigned `hints` file.
#
# Asserted: before login the agent sees no service and its call is refused
# (77) with the reason; after login `wires services` lists orders-db (analyst)
# and the signed-in non-analyst sees nothing and is refused by name; the
# agent's SQL runs (args, stdin, MCP); `.shell id` is refused by sqlite3
# -safe; the security reader's `wires watch` shows every call and refusal with
# the verified email, while the agent's own watch shows only its own calls;
# the workbench pushes to the agent by key and `wires inbox` fetches it
# (--wait wakes on the next); with the workbench stopped the same call is
# answered by the spare; after `wires remove agent` its next call exits 77
# with zero stdout bytes, and pushes to it are refused at send and at fetch.
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
EMAIL="alice@example.com"
READER="sec@audit.example"
EXIT_DENIED=77
START=$SECONDS

D="$(mktemp -d)"
IDP_PID=""
WB_PID=""
SP_PID=""
MCP_PID=""
p=""
trap 'exec 3>&- 2>/dev/null || true; for p in $MCP_PID $SP_PID $WB_PID $IDP_PID; do kill "$p" 2>/dev/null || true; done; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

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
# Print a file's tail on failure.
dump() { [ -z "${1:-}" ] || sed 's/^/  '"$(basename "$1")"'| /' "$1" | tail -20 >&2; }

# Poll a file for a fixed string. $3 is the budget in tenths of a second.
wait_for() {
	local file="$1" s="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && grep -qF -- "$s" "$file"; then return 0; fi
		sleep 0.1
	done
	return 1
}
alive() { kill -0 "$1" 2>/dev/null; }
# The one line of $1 holding every remaining fixed string (or fail).
the_line() {
	local file="$1" hits
	shift
	hits="$(cat "$file")"
	for s in "$@"; do hits="$(printf '%s\n' "$hits" | grep -F -- "$s" || true)"; done
	[ -n "$hits" ] && printf '%s\n' "$hits" | tail -1
}
# The call id on a ▶/■ record line (`HH:MM:SS <service> ▶ <id> …`).
call_id() { printf '%s\n' "$1" | awk '{print $4}'; }
# Each host's own hint line, into every other keystore's local hints file.
share_hints() {
	for h in "$root" "$agent" "$obs"; do
		cat "$wb/run/hint" "$sp/run/hint" >"$h/hints"
	done
}
# Start a host: $1 keystore, $2 log prefix. Sets LAST_PID; waits for its hint.
LAST_PID=""
start_host() {
	rm -f "$1/run/hint"
	(cd "$D" && WIRES_HOME="$1" exec "$WIRES" serve "$HOST_JSON" >"$D/$2.out" 2>"$D/$2.err") &
	LAST_PID=$!
	wait_for "$1/run/hint" " " 300 || {
		sed 's/^/  '"$2"'| /' "$D/$2.err" >&2
		bad "$2 never came up"
	}
}
# Sign $1's keystore in as $2 (the stand-in IdP honours login_hint).
login_as() {
	WIRES_HOME="$1" "$WIRES" login \
		--issuer "$ISSUER" --client-id "$CLIENT_ID" --client-secret not-so-secret \
		--no-browser >"$D/login.out" 2>"$D/login.err" &
	local pid=$!
	wait_for "$D/login.err" "sign in at" 100 || bad "login printed no sign-in URL"
	local url
	url="$(grep -m1 -E '^  https?://' "$D/login.err" | sed 's/^  //')"
	curl -fsSL -o /dev/null "$url&login_hint=$2" || bad "the sign-in round trip failed"
	wait "$pid" || {
		sed 's/^/  login| /' "$D/login.err" >&2
		bad "wires login failed"
	}
	grep -qF "is $2" "$D/login.err" || bad "login did not bind $2"
}

if [ -z "${WIRES_BIN:-}" ]; then
	say "cargo build --release (the mock-IdP build first, then the shipped one) ..."
	# Same target dir, so the second build only recompiles the wires crate; the
	# feature build is copied aside before the shipped build replaces it.
	cargo build -q --release -p wires --features dev-mock-idp
	rm -f "$WIRES_DEV" && cp target/release/wires "$WIRES_DEV"
	cargo build -q --release -p wires
	# A stable signature keeps the macOS firewall from asking again each build.
	.scripts/macos-sign.sh "$WIRES" "$WIRES_DEV"
fi
command -v sqlite3 >/dev/null || bad "sqlite3 is not on PATH"
command -v curl >/dev/null || bad "curl is not on PATH"

# ==========================================================================
# Setup (off camera): five keystores, one signed state, one database, one IdP.
# ==========================================================================
root="$D/root"
wb="$D/workbench"
sp="$D/spare"
agent="$D/agent"
obs="$D/observer"
mkdir -p "$root" "$wb" "$sp" "$agent" "$obs"

# The admin starts the fabric (and is a member itself); every other machine
# makes its key and hands the admin its id. One invite token back each.
ROOT_ID="$(WIRES_HOME="$root" "$WIRES" init | awk '/^fabric /{print $2}')"
WB_ID="$(WIRES_HOME="$wb" "$WIRES" id 2>/dev/null)"
SP_ID="$(WIRES_HOME="$sp" "$WIRES" id 2>/dev/null)"
AG_ID="$(WIRES_HOME="$agent" "$WIRES" id 2>/dev/null)"
OB_ID="$(WIRES_HOME="$obs" "$WIRES" id 2>/dev/null)"
[ -n "$ROOT_ID" ] && [ -n "$WB_ID" ] && [ -n "$SP_ID" ] && [ -n "$AG_ID" ] && [ -n "$OB_ID" ] ||
	bad "setup: could not read the key ids"
AG8="${AG_ID:0:8}"
admin() { WIRES_HOME="$root" "$WIRES" "$@"; }
# Roles are who, by IdP identity. Then the hosts join; they are not running
# yet, so the admin's pushes miss them -- their tokens carry the state.
admin role set analyst '*@example.com' >/dev/null 2>&1
admin role set security "$READER" >/dev/null 2>&1
admin invite "$WB_ID" --name workbench >/dev/null 2>&1
admin invite "$SP_ID" --name spare >/dev/null 2>&1

DB="$D/orders.db"
sqlite3 "$DB" <"$repo/.scripts/fixtures/orders.sql"
ORDERS="$(sqlite3 "$DB" 'select count(*) from orders')"

"$WIRES_DEV" dev-mock-idp --email "$EMAIL" >"$D/idp.out" 2>"$D/idp.err" &
IDP_PID=$!
wait_for "$D/idp.out" "client_id " 100 || bad "setup: the mock IdP did not start; see $D/idp.err"
ISSUER="$(awk '/^issuer /{print $2}' "$D/idp.out")"
CLIENT_ID="$(awk '/^client_id /{print $2}' "$D/idp.out")"

say "five keystores on this machine stand in for five machines:"
say "  workbench  ${WB_ID:0:8}...  and spare ${SP_ID:0:8}...: both implement orders-db"
say "  agent      ${AG8}...  your agent's machine ($EMAIL)"
say "  observer   ${OB_ID:0:8}...  $READER: may read the records, may call nothing"
say "  root       the human who signs who's in and what runs where"
say "and a stand-in IdP at $ISSUER (card 08 swaps in Google)."
beat 5

# ==========================================================================
step "1  the admin registers ONE service, and who may call and read it"
# ==========================================================================
run "wires service add orders-db --description … --allow analyst --reader security --host workbench --host spare"
admin service add orders-db \
	--description "Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument." \
	--allow analyst --reader security --host workbench --host spare >"$D/svc.out" 2>"$D/svc.err" || {
	cat "$D/svc.err" >&2
	bad "1: wires service add failed"
}
show "$D/svc.out"
# The hosts were offline for that push: a fresh token catches them up (re-join
# never rolls a state back).
for pair in "$wb:$WB_ID:workbench" "$sp:$SP_ID:spare"; do
	h="${pair%%:*}"
	rest="${pair#*:}"
	tok="$(admin invite "${rest%%:*}" --name "${rest#*:}" 2>/dev/null)"
	WIRES_HOME="$h" "$WIRES" join "$tok" >/dev/null
done
HOST_JSON="$D/host.json"
sed -e "s|__ISSUER__|$ISSUER|" -e "s|__CLIENT_ID__|$CLIENT_ID|" \
	"$repo/.scripts/fixtures/host.json" >"$HOST_JSON"
run "wires serve --check host.json   # how this host implements it; who may call is the state's"
"$WIRES" serve --check "$HOST_JSON" >"$D/check.out" 2>&1 || {
	dump "$D/check.out"
	bad "1: serve --check rejected host.json"
}
grep -qF "orders-db" "$D/check.out" || bad "1: serve --check does not list orders-db"
show "$D/check.out"
run "wires serve host.json   # on the workbench, and on the spare"
start_host "$wb" workbench
WB_PID=$LAST_PID
start_host "$sp" spare
SP_PID=$LAST_PID
share_hints
ok "1: workbench (pid $WB_PID) and spare (pid $SP_PID) serve orders-db, reached by key"
# The agent and the observer are invited now; each invite is a new state,
# pushed to both hosts.
AG_TOKEN="$(admin invite "$AG_ID" --name agent 2>"$D/invite.err")" || {
	cat "$D/invite.err" >&2
	bad "setup: inviting the agent failed"
}
OB_TOKEN="$(admin invite "$OB_ID" --name observer 2>>"$D/invite.err")" || {
	cat "$D/invite.err" >&2
	bad "setup: inviting the observer failed"
}
grep -qF "pushed to 2 member(s)" "$D/invite.err" || {
	cat "$D/invite.err" >&2
	bad "setup: the invites' state never reached the two hosts"
}
WIRES_HOME="$agent" "$WIRES" join "$AG_TOKEN" >/dev/null
WIRES_HOME="$obs" "$WIRES" join "$OB_TOKEN" >/dev/null
beat 2

# ==========================================================================
step "2  the agent, before signing in: no service listed, and a call is refused"
# ==========================================================================
run "wires services"
WIRES_HOME="$agent" "$WIRES" services >"$D/s0.out" 2>"$D/s0.err" || {
	cat "$D/s0.err" >&2
	bad "2: wires services failed"
}
[ ! -s "$D/s0.out" ] || {
	cat "$D/s0.out" >&2
	bad "2: the agent lists a service before it signed in"
}
show "$D/s0.err"
run "wires call orders-db -- 'select count(*) from orders'"
set +e
WIRES_HOME="$agent" "$WIRES" call orders-db -- "select count(*) from orders" >"$D/c0.out" 2>"$D/c0.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] || {
	dump "$D/c0.err"
	bad "2: an unverified call exited $rc, expected $EXIT_DENIED"
}
grep -qF "no ID token presented" "$D/c0.err" || {
	dump "$D/c0.err"
	bad "2: refused, but not for the missing identity"
}
[ ! -s "$D/c0.out" ] || bad "2: the refused call wrote to stdout"
show "$D/c0.err"
ok "2: exit $EXIT_DENIED -- no verified identity, no sqlite3"
beat 3

# ==========================================================================
step "3  the agent signs in with its IdP -- the token is bound to its node key"
# ==========================================================================
run "wires login --issuer $ISSUER --client-id $CLIENT_ID --no-browser"
login_as "$agent" "$EMAIL"
run "wires services"
WIRES_HOME="$agent" "$WIRES" services >"$D/s1.out" 2>"$D/s1.err" || {
	cat "$D/s1.err" >&2
	bad "3: wires services failed"
}
grep -qE "^orders-db +Read-only SQL.*\(analyst\)$" "$D/s1.out" || {
	cat "$D/s1.out" "$D/s1.err" >&2
	bad "3: the signed-in analyst does not see orders-db"
}
show "$D/s1.out"
ok "3: evaluated locally against the signed state: orders-db, because analyst -- no host named"
beat 3

# ==========================================================================
step "3b a signed-in NON-analyst sees nothing -- and asking by name is refused"
# ==========================================================================
run "wires login …   # on the observer, as $READER"
login_as "$obs" "$READER"
run "wires services"
WIRES_HOME="$obs" "$WIRES" services >"$D/s2.out" 2>"$D/s2.err" || {
	cat "$D/s2.err" >&2
	bad "3b: wires services failed"
}
[ ! -s "$D/s2.out" ] || {
	cat "$D/s2.out" >&2
	bad "3b: $READER can see a service"
}
run "wires call orders-db -- 'select 1'"
set +e
WIRES_HOME="$obs" "$WIRES" call orders-db -- "select 1" >"$D/c9.out" 2>"$D/c9.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] || {
	dump "$D/c9.err"
	bad "3b: $READER's call exited $rc, expected $EXIT_DENIED"
}
grep -qF "$READER is in no role allowed to call orders-db (analyst)" "$D/c9.err" || {
	cat "$D/c9.err" >&2
	bad "3b: refused, but not for the role"
}
show "$D/c9.err"
ok "3b: $READER sees no orders-db, and naming it anyway gets exit $EXIT_DENIED with the reason"
beat 3

# ==========================================================================
step "4  the agent runs SQL by service name -- args, stdin, and MCP"
# ==========================================================================
run "wires call orders-db -- 'select count(*) from orders'"
WIRES_HOME="$agent" "$WIRES" call orders-db -- "select count(*) from orders" >"$D/c1.out" 2>"$D/c1.err" ||
	{
		dump "$D/c1.err"
		bad "4: the args call failed"
	}
grep -qx "$ORDERS" <(tr -d ' ' <"$D/c1.out") || {
	cat "$D/c1.out" >&2
	bad "4: expected $ORDERS orders"
}
[ ! -s "$D/c1.err" ] || {
	cat "$D/c1.err" >&2
	bad "4: a successful call wrote to stderr"
}
show "$D/c1.out"
ok "4a: args call"

SQL2="select customer, sum(total) from orders group by customer order by 2 desc"
run "echo '$SQL2' | wires call orders-db"
printf '%s\n' "$SQL2" | WIRES_HOME="$agent" "$WIRES" call orders-db >"$D/c2.out" 2>"$D/c2.err" ||
	{
		dump "$D/c2.err"
		bad "4: the stdin call failed"
	}
grep -q "umbrella" "$D/c2.out" || {
	cat "$D/c2.out" >&2
	bad "4: the stdin call returned the wrong rows"
}
show "$D/c2.out"
ok "4b: stdin call"

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
	"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"orders-db\",\"arguments\":{\"args\":[\"$SQL3\"]}}}" >&3
wait_for "$D/mcp.out" '"id":3' 200 || {
	sed 's/^/  mcp| /' "$D/mcp.err" >&2
	bad "4: wires mcp never answered tools/call"
}
exec 3>&-
wait "$MCP_PID" 2>/dev/null || true
MCP_PID=""
grep -F '"id":2' "$D/mcp.out" | grep -qF '"orders-db"' || bad "4: tools/list does not offer orders-db"
RESULT="$(grep -F '"id":3' "$D/mcp.out")"
printf '%s' "$RESULT" | grep -qF '"isError":false' || {
	printf '%s\n' "$RESULT" >&2
	bad "4: the MCP tools/call was an error"
}
printf '%s' "$RESULT" | grep -qE 'distinct customer\)[^0-9]*4' || {
	printf '%s\n' "$RESULT" >&2
	bad "4: the MCP call returned the wrong answer"
}
ok "4c: MCP tools/call -- the same service, as an MCP tool"
beat 2

if [ -n "$WITH_CLAUDE" ]; then
	command -v claude >/dev/null || bad "--with-claude: \`claude\` is not on PATH"
	MCP_CONFIG="{\"mcpServers\":{\"wires\":{\"command\":\"$WIRES\",\"args\":[\"mcp\"],\"env\":{\"WIRES_HOME\":\"$agent\"}}}}"
	run "claude -p --mcp-config '{…wires mcp…}' --allowedTools mcp__wires__orders-db 'Which customer spent the most?'"
	# `--allowedTools` is variadic: the `=` form keeps it from eating the prompt.
	claude -p --mcp-config "$MCP_CONFIG" --allowedTools=mcp__wires__orders-db \
		"Using the orders-db tool (SQLite, table orders(customer, total, placed_at)), which customer has the highest total spend? Answer with just the customer name." \
		</dev/null >"$D/claude.out" 2>"$D/claude.err" || {
		cat "$D/claude.err" >&2
		bad "claude: claude -p failed"
	}
	show "$D/claude.out"
	grep -qi "umbrella" "$D/claude.out" || bad "claude: Claude's answer does not name umbrella"
	ok "claude: Claude Code answered through wires mcp"
	beat 2
fi

# ==========================================================================
step "5  the agent tries to escape the service -- sqlite3 -safe refuses"
# ==========================================================================
run "wires call orders-db -- '.shell id'"
set +e
WIRES_HOME="$agent" "$WIRES" call orders-db -- ".shell id" >"$D/c4.out" 2>"$D/c4.err"
rc=$?
set -e
[ "$rc" -ne 0 ] && [ "$rc" -ne "$EXIT_DENIED" ] || {
	dump "$D/c4.err"
	bad "5: .shell id exited $rc; expected sqlite's own nonzero exit"
}
grep -qE "^uid=" "$D/c4.out" && bad "5: .shell id RAN on the workbench"
grep -qF "cannot run .shell in safe mode" "$D/c4.err" || {
	cat "$D/c4.err" >&2
	bad "5: sqlite3 did not refuse in safe mode"
}
show "$D/c4.err"
SHELL_RC=$rc
ok "5: exit $rc from sqlite3 itself"
beat 3

# ==========================================================================
step "6  the reader watches -- every call, from the hosts' own signed logs"
# ==========================================================================
run "wires watch orders-db --once   # on the observer: role security reads orders-db"
WIRES_HOME="$obs" "$WIRES" watch orders-db --once >"$D/w1.out" 2>"$D/w1.err" || {
	cat "$D/w1.err" >&2
	bad "6: the reader's wires watch failed"
}
S1="$(the_line "$D/w1.out" "orders-db ▶" "$EMAIL" "[analyst] orders-db \"select count(*) from orders\"")" || {
	cat "$D/w1.out" "$D/w1.err" >&2
	bad "6: no ▶ naming $EMAIL and the args SQL"
}
F1="$(the_line "$D/w1.out" "■ $(call_id "$S1") exit 0 ")" || {
	cat "$D/w1.out" >&2
	bad "6: no ■ exit 0 for the args call"
}
F2="$(the_line "$D/w1.out" "■" "exit 0" "stdin \"select customer, sum(total) from orders")" || {
	cat "$D/w1.out" >&2
	bad "6: the stdin call's SQL is not in the records"
}
the_line "$D/w1.out" "▶" "$EMAIL" "orders-db \"$SQL3\"" >/dev/null || {
	cat "$D/w1.out" >&2
	bad "6: no ▶ for the MCP call"
}
F4="$(the_line "$D/w1.out" "■" "exit $SHELL_RC")" || {
	cat "$D/w1.out" >&2
	bad "6: no ■ exit $SHELL_RC for .shell id"
}
D0="$(the_line "$D/w1.out" "✗ ${AG_ID:0:4}…" "no ID token presented")" || {
	cat "$D/w1.out" >&2
	bad "6: the agent's pre-login refusal is not in the records"
}
D9="$(the_line "$D/w1.out" "✗ ${OB_ID:0:4}…" "is in no role allowed to call orders-db")" || {
	cat "$D/w1.out" >&2
	bad "6: $READER's refusal is not in the records"
}
line "$S1"
line "$F1"
line "$F2"
line "$F4"
line "$D0"
line "$D9"
ok "6a: the reader sees who ran what -- and every refusal -- holding neither end's keys"
run "wires watch --once   # on the agent: not a reader, so only its own calls"
WIRES_HOME="$agent" "$WIRES" watch --once >"$D/w2.out" 2>"$D/w2.err" || {
	cat "$D/w2.err" >&2
	bad "6: the agent's wires watch failed"
}
the_line "$D/w2.out" "▶" "$EMAIL" >/dev/null || {
	cat "$D/w2.out" "$D/w2.err" >&2
	bad "6: the agent does not see its own calls"
}
grep -qF "${OB_ID:0:4}…" "$D/w2.out" && {
	cat "$D/w2.out" >&2
	bad "6: the agent sees the reader's refused call"
}
ok "6b: the agent sees its own $(grep -cF '▶' "$D/w2.out") calls and nobody else's"
beat 3

# ==========================================================================
step "7  the workbench pushes to the agent -- by key; the agent exposes nothing"
# ==========================================================================
run "wires inbox --wait --timeout 1s   # nothing yet"
set +e
WIRES_HOME="$agent" "$WIRES" inbox --wait --timeout 1s >"$D/i0.out" 2>"$D/i0.err"
rc=$?
set -e
[ "$rc" -eq 124 ] || {
	cat "$D/i0.err" >&2
	bad "7: an empty inbox --wait --timeout exited $rc, expected 124"
}
[ ! -s "$D/i0.out" ] || bad "7: an empty inbox printed something"
run "wires push --to $AG8… --subject build-41 -- 'failed: test_orders_total'   # on the workbench"
WIRES_HOME="$wb" "$WIRES" push --to "$AG_ID" --subject build-41 -- "failed: test_orders_total" \
	>"$D/p1.out" 2>"$D/p1.err" || {
	cat "$D/p1.out" "$D/p1.err" >&2
	bad "7: wires push failed"
}
grep -qE "^(queued|delivered) +$EMAIL \($AG8\)" "$D/p1.out" || {
	cat "$D/p1.out" >&2
	bad "7: the push did not reach $EMAIL"
}
show "$D/p1.out"
run "wires inbox"
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i1.out" 2>"$D/i1.err" || {
	cat "$D/i1.err" >&2
	bad "7: wires inbox failed"
}
grep -qF "from host ${WB_ID:0:8} (verified)  build-41  failed: test_orders_total" "$D/i1.out" || {
	cat "$D/i1.out" "$D/i1.err" >&2
	bad "7: the inbox line does not name the verified host and the message"
}
show "$D/i1.out"
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i2.out" 2>/dev/null
[ ! -s "$D/i2.out" ] || bad "7: a read message was printed twice"
run "wires inbox --wait --timeout 20s &   then, on the workbench: wires push … build-42"
WIRES_HOME="$agent" "$WIRES" inbox --wait --timeout 20s >"$D/i3.out" 2>"$D/i3.err" &
WAIT_PID=$!
sleep 1
WIRES_HOME="$wb" "$WIRES" push --to "$AG_ID" --subject build-42 -- "passed" >/dev/null 2>"$D/p2.err" ||
	bad "7: the second push failed"
wait "$WAIT_PID" || {
	cat "$D/i3.err" >&2
	bad "7: inbox --wait did not exit 0 on the push"
}
grep -qF "build-42  passed" "$D/i3.out" || bad "7: inbox --wait did not print build-42"
WIRES_HOME="$obs" "$WIRES" watch orders-db --once >"$D/w3.out" 2>/dev/null || true
PQ="$(the_line "$D/w3.out" "⇢" "→ $EMAIL" "\"build-41\"")" || {
	cat "$D/w3.out" >&2
	bad "7: the push is not in the workbench's records"
}
ok "7: pushed by key, fetched with no open port; --wait woke on the next one"
line "$(cat "$D/i1.out")"
line "$PQ"
beat 3

# ==========================================================================
step "8  the workbench goes down -- the same call is answered by the spare"
# ==========================================================================
kill "$WB_PID" 2>/dev/null || true
wait "$WB_PID" 2>/dev/null || true
run "wires call --verbose orders-db -- 'select count(*) from orders'"
WIRES_HOME="$agent" "$WIRES" call --verbose orders-db -- "select count(*) from orders" \
	>"$D/c6.out" 2>"$D/c6.err" || {
	dump "$D/c6.err"
	bad "8: the call failed with the workbench down"
}
grep -qx "$ORDERS" <(tr -d ' ' <"$D/c6.out") || bad "8: the failover call returned the wrong rows"
grep -qF "answered by host ${SP_ID:0:8}" "$D/c6.err" || {
	cat "$D/c6.err" >&2
	bad "8: the call was not answered by the spare"
}
show "$D/c6.err"
ok "8: same name, other host -- the agent never named either"
run "wires serve host.json   # the workbench comes back"
start_host "$wb" workbench
WB_PID=$LAST_PID
share_hints
beat 2

# ==========================================================================
step "9  the human removes the agent -- one command, no host restarts"
# ==========================================================================
run "wires remove agent"
admin remove agent >"$D/remove.out" 2>"$D/remove.err" || {
	cat "$D/remove.err" >&2
	bad "9: wires remove failed"
}
grep -qF "pushed to 2 member(s)" "$D/remove.err" || {
	cat "$D/remove.err" >&2
	bad "9: the new state never reached both hosts"
}
show "$D/remove.out"
run "wires call orders-db -- 'select count(*) from orders'"
set +e
WIRES_HOME="$agent" "$WIRES" call orders-db -- "select count(*) from orders" >"$D/c5.out" 2>"$D/c5.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] || {
	dump "$D/c5.err"
	bad "9: the removed agent's call exited $rc, expected $EXIT_DENIED"
}
[ "$(wc -c <"$D/c5.out" | tr -d ' ')" -eq 0 ] || bad "9: the refused call wrote $(wc -c <"$D/c5.out") bytes to stdout"
grep -qF "not a member of the current signed state" "$D/c5.err" || {
	cat "$D/c5.err" >&2
	bad "9: refused, but not for the removal"
}
show "$D/c5.err"
ok "9: exit $EXIT_DENIED, 0 bytes out"
# Removal cuts pushes the way it cuts calls: refused at send, and at fetch.
set +e
WIRES_HOME="$wb" "$WIRES" push --to "$AG_ID" --subject after-removal -- "x" >"$D/p3.out" 2>"$D/p3.err"
rc=$?
set -e
if ! { [ "$rc" -eq "$EXIT_DENIED" ] && grep -qF "not a member of the current signed state" "$D/p3.out"; }; then
	cat "$D/p3.out" "$D/p3.err" >&2
	bad "9: a push to the removed agent exited $rc, expected $EXIT_DENIED"
fi
set +e
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i4.out" 2>"$D/i4.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] && [ ! -s "$D/i4.out" ] || {
	cat "$D/i4.out" "$D/i4.err" >&2
	bad "9: the removed agent's inbox exited $rc, expected $EXIT_DENIED and nothing"
}
ok "9: and no pushes -- refused at send and at fetch (exit $EXIT_DENIED)"
alive "$SP_PID" || bad "9: the spare died"
ok "9: the spare is still pid $SP_PID -- the removal took effect without a restart"
beat 2

# ==========================================================================
step "SUMMARY"
# ==========================================================================
printf '     name      : orders-db, a service; its hosts were never named by the caller\n' >&2
printf '     identity  : unverified caller refused (77); %s allowed as analyst, %s refused by name\n' "$EMAIL" "$READER" >&2
printf '     records   : the security reader saw every call and refusal; the agent only its own\n' >&2
printf '     contained : .shell id refused by sqlite3 -safe, exit %s\n' "$SHELL_RC" >&2
# shellcheck disable=SC2016 # literal backticks in the summary
printf '     push      : host -> agent by key, fetched by `wires inbox`; --wait woke on the next\n' >&2
printf '     failover  : workbench down -> answered by the spare, same command\n' >&2
# shellcheck disable=SC2016 # literal backticks in the summary
printf '     revoke    : one `wires remove` -> exit 77, 0 bytes out; pushes refused; %ss wall clock\n' "$((SECONDS - START))" >&2
[ -z "$KEEP" ] || say "state kept in $D"
