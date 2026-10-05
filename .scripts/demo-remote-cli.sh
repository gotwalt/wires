#!/usr/bin/env bash
#
# Demo: run a CLI on another machine from your agent -- by SERVICE name, the
# machine reached by key, the caller verified by an IdP, every call decided
# by the host from the admin-signed policy.
#
# Six keystores on one machine, all loopback:
#
#   workbench -- `wires serve host.json` (.scripts/fixtures/host.json:
#   spare        implements one service, orders-db, as sqlite3 over orders.db,
#                and adds a stricter local rule: its caller must also be in
#                role oncall).
#                Two hosts implement it: a caller never names either. Both
#                are also the network's directories (`wires directory add`):
#                `serve` runs the directory too, which holds the signed
#                policy the admin publishes; each host follows the other's
#                (a subscription: every edit arrives within a second), and
#                callers fetch from them. Both start empty, holding no
#                policy, and take the admin's first `wires policy push`.
#                Two, because step 7 stops the workbench and step 8's
#                `wires remove` must still reach a directory.
#   agent     -- alice@example.com (roles analyst, oncall): `wires login`, `wires
#                services`, `wires call orders-db …`, `wires mcp`, `wires inbox`.
#   bob       -- bob@example.com (role analyst, not oncall): the policy lets
#                him call orders-db, and the hosts' own rule refuses him.
#   observer  -- carol@partner.example: signed in, but in no role, so allowed
#                to call nothing.
#   root      -- the admin: `wires init`, `role set`, `directory add`,
#                `service add`, `wires network` (one string, for every
#                machine), `wires policy push`, and later `wires remove
#                alice@example.com`. Every change is one signed policy,
#                published to the directories by key.
#
# The setup is card 41's first run: init, role set, directory add
# label=<id>, service add, network; the hosts `join <network>` and `serve`;
# the admin `policy push`es once; each caller's whole onboarding is `wires
# login <network>`. No step fails and none is repeated.
#
# The IdP is a hermetic loopback OIDC issuer (`wires dev-mock-idp`, compiled
# only with `--features dev-mock-idp` -- never the shipped binary). `wires login
# --no-browser` prints the sign-in URL and `curl` plays the browser.
#
# Addressing is by key. n0 discovery finds keys on a real network; here each
# host's `serve` writes its own line to run/hint and the script copies those
# into the other keystores' local, unsigned `hints` file.
#
# Asserted: before it signs in the agent is in no network, so it lists
# nothing and dials nothing (exit 1, "run `wires login <network>`"); after
# `wires login <network>` `wires services` lists orders-db (analyst);
# the signed-in non-analyst sees nothing to call, and naming it anyway stops
# on its own machine (exit 1, no host dialed); an analyst the hosts'
# `also_require` leaves out is refused by the host (exit 77, 0 bytes out); the
# agent's SQL runs (args, stdin, MCP); `.shell id` is refused by sqlite3
# -safe; the workbench pushes to the agent by key and `wires inbox` fetches it
# (--wait wakes on the next); with the workbench stopped the same call is
# answered by the spare; after `wires remove alice@example.com` her next
# call exits 77 with zero stdout bytes, and pushes to her are refused at send
# and at fetch.
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
WIRES="${WIRES_BIN:-$repo/target/release/wires}"
WIRES_DEV="${WIRES_DEV_BIN:-$repo/target/release/wires-mock-idp}"
EMAIL="alice@example.com"
OUTSIDER="carol@partner.example"
BOB="bob@example.com"
EXIT_DENIED=77
START=$SECONDS

D="$(mktemp -d)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/.scripts/lib.sh"
WB_PID=""
SP_PID=""
MCP_PID=""
p=""
trap 'exec 3>&- 2>/dev/null || true; for p in $MCP_PID $SP_PID $WB_PID $IDP_PID; do kill "$p" 2>/dev/null || true; done; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

# Each host's own hint line, into every other keystore's local hints file.
share_hints() {
	for h in "$root" "$agent" "$obs" "$bob"; do
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
build_wires
command -v sqlite3 >/dev/null || bad "sqlite3 is not on PATH"
command -v curl >/dev/null || bad "curl is not on PATH"

# ==========================================================================
# Setup (off camera): six keystores, one signed policy, one database, one IdP.
# ==========================================================================
root="$D/root"
wb="$D/workbench"
sp="$D/spare"
agent="$D/agent"
obs="$D/observer"
bob="$D/bob"
mkdir -p "$root" "$wb" "$sp" "$agent" "$obs" "$bob"

# The IdP comes first: the network's first policy trusts it, and every role
# names the issuer it trusts. (Google is the default; the stand-in replaces
# it here, so `init` names it.)
start_mock_idp "$EMAIL"
admin() { WIRES_HOME="$root" "$WIRES" "$@"; }
ROOT_ID="$(admin init --issuer "$ISSUER" --client-id "$CLIENT_ID" --public-client-secret not-so-secret |
	awk '/^network /{print $2}')"
# The hosts print their ids (`wires id`), for the admin to name them by.
WB_ID="$(WIRES_HOME="$wb" "$WIRES" id 2>/dev/null)"
SP_ID="$(WIRES_HOME="$sp" "$WIRES" id 2>/dev/null)"
[ -n "$ROOT_ID" ] && [ -n "$WB_ID" ] && [ -n "$SP_ID" ] || bad "setup: could not read the key ids"
# Roles are who, by IdP identity (the matchers trust the issuer `init`
# named). Then the hosts are named the network's directories, by key, once;
# none is running yet, so each edit notes that and succeeds.
admin role set analyst '*@example.com' >/dev/null 2>"$D/role.err" || {
	cat "$D/role.err" >&2
	bad "setup: wires role set failed"
}
# The role the hosts' host.json also requires (a stricter local rule).
admin role set oncall "$EMAIL" >/dev/null 2>&1
for named in "workbench=$WB_ID" "spare=$SP_ID"; do
	admin directory add "$named" >/dev/null 2>"$D/dir.err" || {
		cat "$D/dir.err" >&2
		bad "setup: wires directory add ${named%%=*} failed"
	}
done

DB="$D/orders.db"
sqlite3 "$DB" <"$repo/.scripts/fixtures/orders.sql"
ORDERS="$(sqlite3 "$DB" 'select count(*) from orders')"

say "six keystores on this machine stand in for six machines:"
say "  workbench  ${WB_ID:0:8}...  and spare ${SP_ID:0:8}...: both implement orders-db"
say "  agent      your agent's machine ($EMAIL)"
say "  observer   $OUTSIDER: signed in, in no role, may call nothing"
say "  bob        $BOB: an analyst, but not on call"
say "  root       the human who signs who may call what, and where it runs"
say "and a stand-in IdP at $ISSUER (card 08 swaps in Google)."
beat 5

# ==========================================================================
step "1  the admin registers ONE service, and who may call it"
# ==========================================================================
run "wires service add orders-db --description … --allow analyst --host workbench --host spare"
# The directories aren't up yet and none has taken a publish, so the edit
# notes that and succeeds (the new policy is stored; `policy push` delivers
# it once they run).
admin service add orders-db \
	--description "Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument." \
	--allow analyst --host workbench --host spare >"$D/svc.out" 2>"$D/svc.err" || {
	cat "$D/svc.err" >&2
	bad "1: wires service add failed"
}
grep -qF "no directory has taken a publish yet" "$D/svc.err" || {
	cat "$D/svc.err" >&2
	bad "1: wires service add did not say no directory has taken a publish yet"
}
show "$D/svc.out"
run "wires network   # one string for every machine: the root key, the directories, the IdP"
NETWORK="$(admin network 2>"$D/network.err")" || {
	cat "$D/network.err" >&2
	bad "1: wires network failed"
}
[ ! -s "$D/network.err" ] || {
	cat "$D/network.err" >&2
	bad "1: wires network warned"
}
line "${NETWORK:0:60}..."
run "wires join <network>   # on the workbench, and on the spare"
for h in "$wb" "$sp"; do
	WIRES_HOME="$h" "$WIRES" join "$NETWORK" >/dev/null 2>"$D/join.err" || {
		cat "$D/join.err" >&2
		bad "1: wires join failed"
	}
done
HOST_JSON="$D/host.json"
sed -e "s|__ISSUER__|$ISSUER|" -e "s|__CLIENT_ID__|$CLIENT_ID|" \
	"$repo/.scripts/fixtures/host.json" >"$HOST_JSON"
run "wires serve --check host.json   # how this host implements it; who may call is the policy's"
"$WIRES" serve --check "$HOST_JSON" >"$D/check.out" 2>&1 || {
	dump "$D/check.out"
	bad "1: serve --check rejected host.json"
}
grep -qF "orders-db" "$D/check.out" || bad "1: serve --check does not list orders-db"
show "$D/check.out"
run "wires serve host.json   # on the workbench, and on the spare: each also a directory, empty"
start_host "$wb" workbench
WB_PID=$LAST_PID
start_host "$sp" spare
SP_PID=$LAST_PID
share_hints
wait_for "$D/workbench.err" "waiting for the admin's first publish" 100 || {
	dump "$D/workbench.err"
	bad "1: the workbench did not say it waits for the first publish"
}
run "wires policy push   # on the admin: the network's one bootstrap step"
admin policy push >"$D/push0.out" 2>"$D/push0.err" || {
	cat "$D/push0.err" >&2
	bad "1: wires policy push failed"
}
grep -qF "published to 2 of 2 directory(ies)" "$D/push0.err" || {
	cat "$D/push0.err" >&2
	bad "1: the first publish did not reach both directories"
}
for h in workbench spare; do
	wait_for "$D/$h.err" "signed policy assigns every service to this host" 100 || {
		dump "$D/$h.err"
		bad "1: the $h never started serving"
	}
done
ok "1: workbench (pid $WB_PID) and spare (pid $SP_PID) serve orders-db, reached by key"
beat 2

# ==========================================================================
step "2  the agent, before it signs in: in no network, so nothing to call"
# ==========================================================================
run "wires services"
set +e
WIRES_HOME="$agent" "$WIRES" services >"$D/s0.out" 2>"$D/s0.err"
rc=$?
set -e
[ "$rc" -eq 1 ] && [ ! -s "$D/s0.out" ] || {
	cat "$D/s0.out" "$D/s0.err" >&2
	bad "2: wires services before signing in exited $rc, expected 1 and nothing listed"
}
# shellcheck disable=SC2016 # literal backticks in the message
grep -qF 'wires login <network>' "$D/s0.err" || {
	dump "$D/s0.err"
	bad "2: it did not say to run wires login <network>"
}
show "$D/s0.err"
run "wires call orders-db -- 'select count(*) from orders'"
set +e
WIRES_HOME="$agent" "$WIRES" call orders-db -- "select count(*) from orders" >"$D/c0.out" 2>"$D/c0.err"
rc=$?
set -e
[ "$rc" -eq 1 ] || {
	dump "$D/c0.err"
	bad "2: a call before signing in exited $rc, expected 1 (nothing to dial)"
}
[ ! -s "$D/c0.out" ] || bad "2: the stopped call wrote to stdout"
show "$D/c0.err"
ok "2: exit 1 -- no sign-in, nothing dialed"
beat 3

# ==========================================================================
step "3  the agent signs in with its IdP -- joining is signing in"
# ==========================================================================
run "wires login --no-browser <network>   # the string names the IdP and its client"
login_as "$agent" "$EMAIL" "$NETWORK"
AG_ID="$(WIRES_HOME="$agent" "$WIRES" id 2>/dev/null)"
AG8="${AG_ID:0:8}"
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
ok "3: its view, cut by the directory for its token: orders-db, because analyst -- no host named"
beat 3

# ==========================================================================
step "3b a signed-in NON-analyst sees nothing to call -- naming it anyway stops on its machine"
# ==========================================================================
run "wires login <network>   # on the observer, as $OUTSIDER"
login_as "$obs" "$OUTSIDER" "$NETWORK"
run "wires services"
WIRES_HOME="$obs" "$WIRES" services >"$D/s2.out" 2>"$D/s2.err" || {
	cat "$D/s2.err" >&2
	bad "3b: wires services failed"
}
[ ! -s "$D/s2.out" ] || {
	cat "$D/s2.out" >&2
	bad "3b: $OUTSIDER can see a service"
}
run "wires call orders-db -- 'select 1'"
set +e
WIRES_HOME="$obs" "$WIRES" call orders-db -- "select 1" >"$D/c9.out" 2>"$D/c9.err"
rc=$?
set -e
# Its view holds no service, and the directory it asks (`resolve`) has none
# for it either, so the call stops here: exit 1, no host dialed.
[ "$rc" -eq 1 ] || {
	dump "$D/c9.err"
	bad "3b: $OUTSIDER's call exited $rc, expected 1 (nothing to dial)"
}
# shellcheck disable=SC2016 # literal backticks in the message
grep -qF 'no service named `orders-db` that you may call' "$D/c9.err" || {
	cat "$D/c9.err" >&2
	bad "3b: stopped, but not because orders-db is not one to call"
}
[ ! -s "$D/c9.out" ] || bad "3b: the stopped call wrote to stdout"
show "$D/c9.err"
ok "3b: $OUTSIDER may not call orders-db: exit 1 on its own machine, nothing dialed"
beat 3

# ==========================================================================
step "3c an analyst the hosts' own rule leaves out -- the HOST refuses"
# ==========================================================================
run "wires login <network>   # on bob's machine, as $BOB: analyst, not oncall"
login_as "$bob" "$BOB" "$NETWORK"
run "wires call orders-db -- 'select 1'   # the policy admits analysts; host.json also requires oncall"
set +e
WIRES_HOME="$bob" "$WIRES" call orders-db -- "select 1" >"$D/c8.out" 2>"$D/c8.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] || {
	dump "$D/c8.err"
	bad "3c: $BOB's call exited $rc, expected $EXIT_DENIED"
}
[ "$(wc -c <"$D/c8.out" | tr -d ' ')" -eq 0 ] || bad "3c: the refused call wrote $(wc -c <"$D/c8.out") bytes to stdout"
grep -qF "$BOB is not admitted to orders-db by this host's own rules" "$D/c8.err" || {
	cat "$D/c8.err" >&2
	bad "3c: refused, but not by the host's own rule"
}
show "$D/c8.err"
ok "3c: the policy admits $BOB; the host's stricter rule refuses: exit $EXIT_DENIED, 0 bytes out"
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
step "6  the workbench pushes to the agent -- by key; the agent exposes nothing"
# ==========================================================================
run "wires inbox --wait --timeout 1s   # nothing yet"
set +e
WIRES_HOME="$agent" "$WIRES" inbox --wait --timeout 1s >"$D/i0.out" 2>"$D/i0.err"
rc=$?
set -e
[ "$rc" -eq 124 ] || {
	cat "$D/i0.err" >&2
	bad "6: an empty inbox --wait --timeout exited $rc, expected 124"
}
[ ! -s "$D/i0.out" ] || bad "6: an empty inbox printed something"
run "wires push --to $AG8… --subject build-41 -- 'failed: test_orders_total'   # on the workbench"
WIRES_HOME="$wb" "$WIRES" push --to "$AG_ID" --subject build-41 -- "failed: test_orders_total" \
	>"$D/p1.out" 2>"$D/p1.err" || {
	cat "$D/p1.out" "$D/p1.err" >&2
	bad "6: wires push failed"
}
grep -qE "^(queued|delivered) +$EMAIL \($AG8\)" "$D/p1.out" || {
	cat "$D/p1.out" >&2
	bad "6: the push did not reach $EMAIL"
}
show "$D/p1.out"
run "wires inbox"
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i1.out" 2>"$D/i1.err" || {
	cat "$D/i1.err" >&2
	bad "6: wires inbox failed"
}
grep -qF "from host ${WB_ID:0:8} (verified)  build-41  failed: test_orders_total" "$D/i1.out" || {
	cat "$D/i1.out" "$D/i1.err" >&2
	bad "6: the inbox line does not name the verified host and the message"
}
show "$D/i1.out"
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i2.out" 2>/dev/null
[ ! -s "$D/i2.out" ] || bad "6: a read message was printed twice"
run "wires inbox --wait --timeout 20s &   then, on the workbench: wires push … build-42"
WIRES_HOME="$agent" "$WIRES" inbox --wait --timeout 20s >"$D/i3.out" 2>"$D/i3.err" &
WAIT_PID=$!
sleep 1
WIRES_HOME="$wb" "$WIRES" push --to "$AG_ID" --subject build-42 -- "passed" >/dev/null 2>"$D/p2.err" ||
	bad "6: the second push failed"
wait "$WAIT_PID" || {
	cat "$D/i3.err" >&2
	bad "6: inbox --wait did not exit 0 on the push"
}
grep -qF "build-42  passed" "$D/i3.out" || bad "6: inbox --wait did not print build-42"
ok "6: pushed by key, fetched with no open port; --wait woke on the next one"
line "$(cat "$D/i1.out")"
beat 3

# ==========================================================================
step "7  the workbench goes down -- the same call is answered by the spare"
# ==========================================================================
kill "$WB_PID" 2>/dev/null || true
wait "$WB_PID" 2>/dev/null || true
run "wires call --verbose orders-db -- 'select count(*) from orders'"
WIRES_HOME="$agent" "$WIRES" call --verbose orders-db -- "select count(*) from orders" \
	>"$D/c6.out" 2>"$D/c6.err" || {
	dump "$D/c6.err"
	bad "7: the call failed with the workbench down"
}
grep -qx "$ORDERS" <(tr -d ' ' <"$D/c6.out") || bad "7: the failover call returned the wrong rows"
grep -qF "answered by host ${SP_ID:0:8}" "$D/c6.err" || {
	cat "$D/c6.err" >&2
	bad "7: the call was not answered by the spare"
}
show "$D/c6.err"
ok "7: same name, other host -- the agent never named either"
run "wires serve host.json   # the workbench comes back"
start_host "$wb" workbench
WB_PID=$LAST_PID
share_hints
beat 2

# ==========================================================================
step "8  the human removes $EMAIL -- one command, from every machine, no host restarts"
# ==========================================================================
run "wires remove $EMAIL"
admin remove "$EMAIL" >"$D/remove.out" 2>"$D/remove.err" || {
	cat "$D/remove.err" >&2
	bad "8: wires remove failed"
}
grep -qF "published to 2 of 2 directory(ies)" "$D/remove.err" || {
	cat "$D/remove.err" >&2
	bad "8: the new policy never reached both directories"
}
show "$D/remove.out"
run "wires call orders-db -- 'select count(*) from orders'"
set +e
WIRES_HOME="$agent" "$WIRES" call orders-db -- "select count(*) from orders" >"$D/c5.out" 2>"$D/c5.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] || {
	dump "$D/c5.err"
	bad "8: the removed agent's call exited $rc, expected $EXIT_DENIED"
}
[ "$(wc -c <"$D/c5.out" | tr -d ' ')" -eq 0 ] || bad "8: the refused call wrote $(wc -c <"$D/c5.out") bytes to stdout"
grep -qF "not admitted to this network" "$D/c5.err" || {
	cat "$D/c5.err" >&2
	bad "8: refused, but not for the removal"
}
show "$D/c5.err"
ok "8: exit $EXIT_DENIED, 0 bytes out"
# Removal cuts pushes the way it cuts calls: refused at send, and at fetch.
# The spare answered her last calls, so it knows who she is (the
# workbench restarted in step 7 and has not seen her since).
set +e
WIRES_HOME="$sp" "$WIRES" push --to "$AG_ID" --subject after-removal -- "x" >"$D/p3.out" 2>"$D/p3.err"
rc=$?
set -e
if ! { [ "$rc" -eq "$EXIT_DENIED" ] && grep -qF "removed by the current signed policy" "$D/p3.out"; }; then
	cat "$D/p3.out" "$D/p3.err" >&2
	bad "8: a push to the removed agent exited $rc, expected $EXIT_DENIED"
fi
set +e
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i4.out" 2>"$D/i4.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] && [ ! -s "$D/i4.out" ] || {
	cat "$D/i4.out" "$D/i4.err" >&2
	bad "8: the removed agent's inbox exited $rc, expected $EXIT_DENIED and nothing"
}
ok "8: and no pushes -- refused at send and at fetch (exit $EXIT_DENIED)"
alive "$SP_PID" || bad "8: the spare died"
ok "8: the spare is still pid $SP_PID -- the removal took effect without a restart"
beat 2

# ==========================================================================
step "SUMMARY"
# ==========================================================================
printf '     name      : orders-db, a service; its hosts were never named by the caller\n' >&2
printf '     identity  : joining is signing in; before it, nothing to call; %s allowed as analyst\n' "$EMAIL" >&2
printf '     narrowing : %s (no role) stopped on its machine, exit 1; %s refused by the host rule, exit 77\n' "$OUTSIDER" "$BOB" >&2
printf '     contained : .shell id refused by sqlite3 -safe, exit %s\n' "$SHELL_RC" >&2
# shellcheck disable=SC2016 # literal backticks in the summary
printf '     push      : host -> agent by key, fetched by `wires inbox`; --wait woke on the next\n' >&2
printf '     failover  : workbench down -> answered by the spare, same command\n' >&2
# shellcheck disable=SC2016 # literal backticks in the summary
printf '     revoke    : one `wires remove <email>` -> exit 77, 0 bytes out; pushes refused; %ss wall clock\n' "$((SECONDS - START))" >&2
[ -z "$KEEP" ] || say "state kept in $D"
