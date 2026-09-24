#!/usr/bin/env bash
#
# Provision a loopback network for the help-text eval (card 38):
#
#   root      -- the admin: `wires init` against a stand-in IdP, roles
#                `analyst` (*@example.com) and `hr` (hr@example.com), five
#                services, one invite per machine
#   workbench -- `wires serve host.json` (also the network's directory),
#                implementing orders-db (sqlite3), deploy-status, ci-logs,
#                tickets and payroll; payroll also requires role `hr` on this
#                host (`also_require`), so the agent's call is refused (77)
#   agent     -- alice@example.com, role analyst: joined, signed in, locked
#                (WIRES_LOCKED=1), the workbench's hint line in its `hints`
#
# The IdP is the hermetic `wires dev-mock-idp`, so $WIRES_BIN must be a
# `--features dev-mock-idp` build. State lives under $HELP_EVAL_DIR (default
# /tmp/wbh: short, since macOS caps unix-socket paths at 104 bytes). Writes
# `export` lines (WIRES_HOME, PATH, WIRES_LOCKED, the pids and the ground
# truth) to $D/env.sh.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="${HELP_EVAL_DIR:-/tmp/wbh}"
WIRES="${WIRES_BIN:?set WIRES_BIN to a wires build with --features dev-mock-idp}"
# shellcheck disable=SC2034 # lib.sh reads QUIET and WIRES_DEV
QUIET=1
EMAIL="alice@example.com"

if [ -f "$D/env.sh" ]; then
	for v in HELP_EVAL_WB_PID HELP_EVAL_IDP_PID; do
		pid="$(sed -n "s/^export $v=//p" "$D/env.sh")"
		[ -z "$pid" ] || kill "$pid" 2>/dev/null || true
	done
fi
rm -rf "$D"
mkdir -p "$D/root" "$D/workbench" "$D/agent" "$D/bin"
# shellcheck source=.scripts/lib.sh
. "$repo/.scripts/lib.sh"
# rm first: overwriting a signed binary in place gets it SIGKILLed on macOS.
rm -f "$D/bin/wires"
cp "$WIRES" "$D/bin/wires"
WIRES="$D/bin/wires"
# shellcheck disable=SC2034 # lib.sh's start_mock_idp runs it
WIRES_DEV="$WIRES"

start_mock_idp "$EMAIL"
admin() { WIRES_HOME="$D/root" "$WIRES" "$@"; }
admin init --issuer "$ISSUER" --client-id "$CLIENT_ID" --public-client-secret not-so-secret >/dev/null 2>&1
WB_ID="$(WIRES_HOME="$D/workbench" "$WIRES" id 2>/dev/null)"
AG_ID="$(WIRES_HOME="$D/agent" "$WIRES" id 2>/dev/null)"
admin role set analyst --issuer "$ISSUER" '*@example.com' >/dev/null 2>&1
admin role set hr --issuer "$ISSUER" 'hr@example.com' >/dev/null 2>&1
admin invite "$WB_ID" --name workbench >/dev/null 2>&1
# Nothing is up yet, so each edit reaches no directory and exits 1; the
# workbench's second token below carries the policy.
admin directory add workbench >/dev/null 2>&1 || true
svc() { admin service add "$1" --description "$2" --allow analyst --host workbench >/dev/null 2>&1 || true; }
svc orders-db "Read-only SQL (sqlite3) over the orders database; pass the SQL statement as the argument."
svc deploy-status "Which version of each production app is deployed, and whether it is healthy."
svc ci-logs "Build logs from CI; pass a build number."
svc tickets "Search customer support tickets; pass the search words."
svc payroll "Payroll totals by team and month; pass the team name."
WIRES_HOME="$D/workbench" "$WIRES" join "$(admin invite "$WB_ID" --name workbench 2>/dev/null)" >/dev/null

sqlite3 "$D/orders.db" <"$repo/.scripts/fixtures/orders.sql"
cat >"$D/deploy-status.sh" <<'SH'
#!/bin/sh
printf 'app       version   deployed (UTC)     health\n'
printf 'api       v2.14.1   2026-09-23 17:02   healthy\n'
printf 'web       v5.3.0    2026-09-22 09:40   degraded\n'
printf 'billing   v1.8.7    2026-09-19 12:15   healthy\n'
SH
cat >"$D/stub.sh" <<'SH'
#!/bin/sh
echo "no results for: $*"
SH
chmod +x "$D/deploy-status.sh" "$D/stub.sh"
cat >"$D/host.json" <<JSON
{
  "version": 2,
  "identity": { "issuers": [ { "issuer": "$ISSUER", "audiences": ["$CLIENT_ID"] } ] },
  "services": {
    "orders-db": { "command": ["sqlite3", "-safe", "-readonly", "-header", "-column", "$D/orders.db"] },
    "deploy-status": { "command": ["$D/deploy-status.sh"] },
    "ci-logs": { "command": ["$D/stub.sh"] },
    "tickets": { "command": ["$D/stub.sh"] },
    "payroll": { "command": ["$D/stub.sh"], "also_require": ["hr"] }
  }
}
JSON
WIRES_HOME="$D/workbench" "$WIRES" serve --check "$D/host.json" >/dev/null
(cd "$D" && WIRES_HOME="$D/workbench" exec "$WIRES" serve "$D/host.json" >"$D/wb.out" 2>"$D/wb.err" </dev/null) &
WB_PID=$!
wait_for "$D/workbench/run/hint" " " 300 || {
	cat "$D/wb.err" >&2
	bad "the workbench wrote no hint line"
}
cp "$D/workbench/run/hint" "$D/agent/hints"

WIRES_HOME="$D/agent" "$WIRES" join "$(admin invite "$AG_ID" --name agent 2>/dev/null)" >/dev/null
login_as "$D/agent" "$EMAIL"
WIRES_HOME="$D/agent" "$WIRES" services | grep -q '^orders-db ' || bad "the agent does not see orders-db"

cat >"$D/env.sh" <<ENV
export WIRES_HOME=$D/agent
export WIRES_LOCKED=1
export HELP_EVAL_BIN_DIR=$D/bin
export HELP_EVAL_WB_PID=$WB_PID
export HELP_EVAL_IDP_PID=$IDP_PID
export HELP_EVAL_ORDERS=$(sqlite3 "$D/orders.db" 'select count(*) from orders')
export HELP_EVAL_MAX_TOTAL=$(sqlite3 "$D/orders.db" 'select max(total) from orders')
ENV
cat "$D/env.sh"
