#!/usr/bin/env bash
#
# Demo (card 24): a host calls the agent back. The agent starts a build on
# the workbench, which returns at once; when the build fails, the workbench
# pushes the result to the agent by key, and the agent follows up with the
# log. Neither side exposes an endpoint: no webhook, no public URL.
#
# Four keystores on one machine, all loopback (as in demo-remote-cli.sh):
#
#   workbench -- `wires serve push-host.json`: three tools from the mock CI
#                (.scripts/fixtures/ci.sh): deploy, status, logs, for role
#                analyst = *@example.com; "push": {"allow": ["analyst"]}.
#   observer  -- `wires watch`: sees ▶ deploy → ⇢ push → ▶ logs, each line
#                stamped with the verified identity.
#   agent     -- signs in (mock IdP), then only `wires call` / `wires inbox`,
#                in locked mode (WIRES_LOCKED=1).
#   root      -- the admin: init + one invite per machine.
#
# Asserted: `deploy` returns within a few seconds while the build keeps
# running; `wires inbox --wait` (what an agent would run as a background
# command) exits 0 when the build's job runs `wires push --to
# "$WIRES_CALLER_NODE"`, and its line names the verified host; the agent's
# `logs` call returns the failing assertion; the observer shows ▶ deploy, then
# ⇢ build-41, then ▶ logs, in that order, all naming the agent's email; and a
# "sleeping" agent (no receiver running) finds the next build's push queued
# on the workbench, fetched by its next plain `wires inbox`.
#
# Run it from the repo root:
#
#   ./.scripts/demo-push.sh            narrated
#   ./.scripts/demo-push.sh --quiet    assertions only (< 30 s)
#   ./.scripts/demo-push.sh --keep     leave the state dir behind

set -euo pipefail

QUIET=""
KEEP=""
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
	*)
		printf 'usage: %s [--quiet] [--keep]\n' "$0" >&2
		exit 2
		;;
	esac
done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
WIRES="${WIRES_BIN:-$repo/target/release/wires}"
WIRES_DEV="${WIRES_DEV_BIN:-$repo/target/release/wires-mock-idp}"
TOPIC="ops"
EMAIL="alice@example.com"
JOB_SECS=3
START=$SECONDS

D="$(mktemp -d)"
IDP_PID=""
WB_PID=""
OBS_PID=""
WAIT_PID=""
p=""
trap 'for p in $WAIT_PID $OBS_PID $WB_PID $IDP_PID; do kill "$p" 2>/dev/null || true; done; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

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
# Poll for one line of $1 containing every remaining fixed string; prints
# `<line number>:<line>`. Budget: 20 s.
wait_line() {
	local file="$1"
	shift
	for _ in $(seq 1 200); do
		if [ -e "$file" ]; then
			local hits
			hits="$(grep -n '' "$file")"
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
dump() {
	sed 's/^/  observer| /' "$D/obs.out" >&2 || true
	[ -z "${1:-}" ] || sed 's/^/  '"$(basename "$1")"'| /' "$1" | tail -20 >&2
}
alive() { kill -0 "$1" 2>/dev/null; }
# The agent: locked mode, so it can steer nothing but the tool and its args.
agent_wires() { WIRES_HOME="$agent" WIRES_LOCKED=1 "$WIRES" "$@"; }

if [ -z "${WIRES_BIN:-}" ]; then
	say "cargo build --release (the mock-IdP build first, then the shipped one) ..."
	# Both builds write target/release/wires: copy the feature build aside first.
	# rm before cp: overwriting a signed binary in place gets it killed on macOS.
	(cd "$repo" && cargo build -q --release -p wires --features dev-mock-idp)
	rm -f "$WIRES_DEV" && cp "$repo/target/release/wires" "$WIRES_DEV"
	(cd "$repo" && cargo build -q --release -p wires)
fi
command -v curl >/dev/null || bad "curl is not on PATH"
command -v perl >/dev/null || bad "perl is not on PATH (the mock CI's clock)"

# ==========================================================================
# Setup (off camera): four keystores, one roster, one IdP, one mock CI.
# ==========================================================================
root="$D/root"
wb="$D/wb"
agent="$D/agent"
obs="$D/obs"
mkdir -p "$root" "$wb" "$agent" "$obs"

ROOT_ID="$(WIRES_HOME="$root" "$WIRES" init --channel "$TOPIC" | awk '/^fabric /{print $2}')"
WB_ID="$(WIRES_HOME="$wb" "$WIRES" id 2>/dev/null)"
AG_ID="$(WIRES_HOME="$agent" "$WIRES" id 2>/dev/null)"
OB_ID="$(WIRES_HOME="$obs" "$WIRES" id 2>/dev/null)"
[ -n "$ROOT_ID" ] && [ -n "$WB_ID" ] && [ -n "$AG_ID" ] && [ -n "$OB_ID" ] ||
	bad "setup: could not read the key ids"
AG8="${AG_ID:0:8}"
WB8="${WB_ID:0:8}"
WB_TOKEN="$(WIRES_HOME="$root" "$WIRES" invite "$WB_ID" --name workbench 2>/dev/null)"
WIRES_HOME="$wb" "$WIRES" join "$WB_TOKEN" >/dev/null

"$WIRES_DEV" dev-mock-idp --email "$EMAIL" >"$D/idp.out" 2>"$D/idp.err" &
IDP_PID=$!
wait_for "$D/idp.out" "client_id " 100 || bad "setup: the mock IdP did not start; see $D/idp.err"
ISSUER="$(awk '/^issuer /{print $2}' "$D/idp.out")"
CLIENT_ID="$(awk '/^client_id /{print $2}' "$D/idp.out")"

HOST_JSON="$D/host.json"
sed -e "s|__ISSUER__|$ISSUER|" -e "s|__CLIENT_ID__|$CLIENT_ID|" \
	-e "s|__CI__|$repo/.scripts/fixtures/ci.sh|" \
	"$repo/.scripts/fixtures/push-host.json" >"$HOST_JSON"
"$WIRES" serve --check "$HOST_JSON" >"$D/check.out" 2>&1 || {
	cat "$D/check.out" >&2
	bad "setup: serve --check rejected push-host.json"
}
JOBS="$D/jobs"
mkdir -p "$JOBS"
(cd "$D" && WIRES_HOME="$wb" CI_JOBS="$JOBS" CI_JOB_SECS="$JOB_SECS" CI_WIRES="$WIRES" \
	exec "$WIRES" serve "$HOST_JSON" >"$D/wb.out" 2>"$D/wb.err") &
WB_PID=$!
wait_for "$D/wb.err" "share to bootstrap: " 300 || {
	sed 's/^/  workbench| /' "$D/wb.err" >&2
	bad "setup: the workbench never printed its ticket"
}
TICKET="$(grep -m1 '^share to bootstrap: ' "$D/wb.err" | sed 's/^share to bootstrap: //')"
AG_TOKEN="$(WIRES_HOME="$root" "$WIRES" invite "$AG_ID" --name agent --peer "$TICKET" 2>"$D/invite.err")" || {
	cat "$D/invite.err" >&2
	bad "setup: inviting the agent failed"
}
OB_TOKEN="$(WIRES_HOME="$root" "$WIRES" invite "$OB_ID" --name observer 2>>"$D/invite.err")" || {
	cat "$D/invite.err" >&2
	bad "setup: inviting the observer failed"
}
WIRES_HOME="$agent" "$WIRES" join "$AG_TOKEN" >/dev/null
WIRES_HOME="$obs" "$WIRES" join "$OB_TOKEN" >/dev/null

WIRES_HOME="$obs" WIRES_OIDC_ISSUER="$ISSUER" WIRES_OIDC_AUDIENCE="$CLIENT_ID" \
	"$WIRES" watch >"$D/obs.out" 2>"$D/obs.err" &
OBS_PID=$!
wait_for "$D/obs.err" "neighbor up" 300 || {
	sed 's/^/  observer| /' "$D/obs.err" >&2
	bad "setup: the observer never joined the workbench's mesh"
}

WIRES_HOME="$agent" "$WIRES" login --topic "$TOPIC" \
	--issuer "$ISSUER" --client-id "$CLIENT_ID" --client-secret not-so-secret \
	--no-browser >"$D/login.out" 2>"$D/login.err" &
LOGIN_PID=$!
wait_for "$D/login.err" "sign in at" 100 || bad "setup: login printed no sign-in URL"
URL="$(grep -m1 -E '^  https?://' "$D/login.err" | sed 's/^  //')"
curl -fsSL -o /dev/null "$URL" || bad "setup: the sign-in round trip failed"
wait "$LOGIN_PID" || {
	sed 's/^/  login| /' "$D/login.err" >&2
	bad "setup: wires login failed"
}
wait_line "$D/obs.out" "🪪 identity $AG8 is $EMAIL" >/dev/null || {
	dump "$D/login.err"
	bad "setup: the observer never verified the agent's identity"
}
# The workbench re-announces with the tools sealed to the signed-in analyst.
for _ in $(seq 1 20); do
	agent_wires tools >"$D/tools.out" 2>/dev/null || true
	grep -qF "deploy  on $WB8" "$D/tools.out" && break
	sleep 0.2
done
grep -qF "deploy  on $WB8" "$D/tools.out" || {
	cat "$D/tools.out" >&2
	bad "setup: the signed-in agent does not see deploy"
}

say "workbench ${WB8}...  runs a mock CI: deploy / status / logs; may push to analysts"
say "agent     ${AG8}...  signed in as $EMAIL; runs only \`wires call\` and \`wires inbox\` (locked)"
say "observer  ${OB_ID:0:8}...  watches the channel; holds neither end's keys"
show "$D/tools.out"
beat 4

# ==========================================================================
step "1  the agent starts a build -- the tool returns at once"
# ==========================================================================
run "wires call deploy -- build 41"
t0=$SECONDS
agent_wires call deploy -- build 41 >"$D/d1.out" 2>"$D/d1.err" || {
	dump "$D/d1.err"
	bad "1: wires call deploy failed"
}
[ $((SECONDS - t0)) -le 3 ] || bad "1: deploy took $((SECONDS - t0)) s; it should return at once"
grep -qF "started build-41" "$D/d1.out" || {
	cat "$D/d1.out" "$D/d1.err" >&2
	bad "1: deploy did not start build-41"
}
grep -qx running "$JOBS/build-41/state" || bad "1: build-41 is not running on the workbench"
show "$D/d1.out"
ok "1: deploy returned in $((SECONDS - t0)) s; build-41 runs on the workbench (${JOB_SECS} s here, minutes in life)"
beat 2

# ==========================================================================
step "2  the agent waits -- \`wires inbox --wait\`, a background command in Claude Code"
# ==========================================================================
# In Claude Code this is a background Bash command: the agent goes quiet and
# is woken when it exits. It opens no port: it dials the workbench by key and
# holds a fetch open.
run "wires inbox --wait --timeout 30s &"
agent_wires inbox --wait --timeout 30s >"$D/i1.out" 2>"$D/i1.err" &
WAIT_PID=$!
beat 1
alive "$WAIT_PID" || {
	cat "$D/i1.err" >&2
	bad "2: inbox --wait exited before anything was pushed"
}
ok "2: waiting (pid $WAIT_PID), no listener, no webhook URL"

# ==========================================================================
step "3  the build fails on the workbench; its job pushes to \$WIRES_CALLER_NODE"
# ==========================================================================
set +e
wait "$WAIT_PID"
rc=$?
WOKE_MS="$(perl -MTime::HiRes=time -e 'printf "%d", time*1000')"
set -e
WAIT_PID=""
[ "$rc" -eq 0 ] || {
	cat "$D/i1.err" "$JOBS/build-41/push.out" "$JOBS/build-41/push.err" >&2 || true
	bad "3: inbox --wait exited $rc, expected 0 (a message)"
}
[ -f "$JOBS/build-41/done_ms" ] || bad "3: inbox --wait woke before the build finished"
# The fetch can hand the message over before `wires push` itself returns.
for _ in $(seq 1 100); do
	[ -f "$JOBS/build-41/pushed_ms" ] && break
	sleep 0.1
done
grep -qE "^(delivered|queued) +$EMAIL \($AG8\)" "$JOBS/build-41/push.out" || {
	cat "$JOBS/build-41/push.out" "$JOBS/build-41/push.err" >&2
	bad "3: the job's wires push did not name $EMAIL"
}
run "# the job ran:  wires push --to \"\$WIRES_CALLER_NODE\" --subject build-41 -- 'failed: …'"
show "$JOBS/build-41/push.out"
grep -qF "from host $WB8 (verified)  build-41  failed: test_orders_total" "$D/i1.out" || {
	cat "$D/i1.out" "$D/i1.err" >&2
	bad "3: the inbox line does not name the verified host and build-41"
}
LAT=$((WOKE_MS - $(cat "$JOBS/build-41/done_ms")))
show "$D/i1.out"
ok "3: inbox --wait woke with the push; the sender is the host key the agent dialed, verified"
beat 3

# ==========================================================================
step "4  woken, the agent follows up -- the log, from the same host"
# ==========================================================================
run "wires call logs -- build 41 --tail 50"
agent_wires call logs -- build 41 --tail 50 >"$D/l1.out" 2>"$D/l1.err" || {
	dump "$D/l1.err"
	bad "4: wires call logs failed"
}
GOT="$(awk '/^  left: /{print $2}' "$D/l1.out")"
[ "$(wc -l <"$D/l1.out" | tr -d ' ')" -eq 50 ] || bad "4: logs --tail 50 returned $(wc -l <"$D/l1.out") lines"
grep -qF "panicked at orders/total.rs" "$D/l1.out" && [ -n "$GOT" ] || {
	cat "$D/l1.out" >&2
	bad "4: the log tail does not hold the failing assertion"
}
[ -n "$QUIET" ] || grep -A3 -F "panicked at" "$D/l1.out" | sed 's/^/     /' >&2
ok "4: test_orders_total: left $GOT, right 1234.50"
beat 3

# ==========================================================================
step "5  the observer saw the whole chain, each line stamped with who"
# ==========================================================================
SD="$(wait_line "$D/obs.out" "▶" "$EMAIL" "[analyst] deploy build 41")" || {
	dump
	bad "5: no ▶ deploy naming $EMAIL"
}
# `delivered` if the host's direct dial reached a resident receiver, else
# `fetched` by the agent's waiting inbox.
SP="$(wait_line "$D/obs.out" "⇢" "→ $EMAIL" "[analyst] \"build-41\" ")" || {
	dump
	bad "5: no ⇢ build-41 delivered/fetched on the channel"
}
SL="$(wait_line "$D/obs.out" "▶" "$EMAIL" "[analyst] logs build 41 --tail 50")" || {
	dump
	bad "5: no ▶ logs naming $EMAIL"
}
nD="${SD%%:*}"
nP="${SP%%:*}"
nL="${SL%%:*}"
[ "$nD" -lt "$nP" ] && [ "$nP" -lt "$nL" ] || {
	dump
	bad "5: the chain is out of order (deploy line $nD, push $nP, logs $nL)"
}
ok "5: ▶ deploy → ⇢ push → ▶ logs, in order"
line "${SD#*:}"
line "${SP#*:}"
line "${SL#*:}"
beat 3

# ==========================================================================
step "6  a sleeping agent: nothing running -- the push waits on the workbench"
# ==========================================================================
run "wires call deploy -- build 42   # and then the agent stops; no inbox running"
agent_wires call deploy -- build 42 >"$D/d2.out" 2>"$D/d2.err" || {
	dump "$D/d2.err"
	bad "6: wires call deploy (42) failed"
}
for _ in $(seq 1 $((JOB_SECS * 10 + 100))); do
	[ -f "$JOBS/build-42/pushed_ms" ] && break
	sleep 0.1
done
[ -f "$JOBS/build-42/pushed_ms" ] || bad "6: build-42's job never pushed"
grep -qE "^queued +$EMAIL \($AG8\)" "$JOBS/build-42/push.out" || {
	cat "$JOBS/build-42/push.out" "$JOBS/build-42/push.err" >&2
	bad "6: with no receiver, build-42's push was not queued"
}
QQ="$(wait_line "$D/obs.out" "⇢" "→ $EMAIL" "\"build-42\" queued")" || {
	dump
	bad "6: no ⇢ build-42 queued on the channel"
}
ok "6: build-42 failed while the agent slept; the push is queued on the workbench"
line "${QQ#*:}"
run "wires inbox   # the agent's next turn, whenever that is"
agent_wires inbox >"$D/i2.out" 2>"$D/i2.err" || {
	cat "$D/i2.err" >&2
	bad "6: wires inbox failed"
}
grep -qF "from host $WB8 (verified)  build-42  failed: test_orders_total" "$D/i2.out" || {
	cat "$D/i2.out" "$D/i2.err" >&2
	bad "6: the next wires inbox did not fetch build-42"
}
show "$D/i2.out"
QF="$(wait_line "$D/obs.out" "⇢" "→ $EMAIL" "\"build-42\" fetched")" || {
	dump
	bad "6: no ⇢ build-42 fetched on the channel"
}
agent_wires inbox >"$D/i3.out" 2>/dev/null
[ ! -s "$D/i3.out" ] || bad "6: a read message was printed twice"
ok "6: fetched on the next \`wires inbox\` -- once"
line "${QF#*:}"
alive "$WB_PID" || bad "6: the workbench died"

# ==========================================================================
step "SUMMARY"
# ==========================================================================
printf '     callback  : build-41 result pushed host -> agent by key; inbox --wait woke %s ms after the build finished\n' "$LAT" >&2
printf '     follow-up : logs -- build 41 --tail 50 -> test_orders_total left %s\n' "$GOT" >&2
printf '     observable: ▶ deploy → ⇢ build-41 → ▶ logs, naming %s\n' "$EMAIL" >&2
printf '     asleep    : build-42 queued on the workbench, fetched by the next `wires inbox`\n' >&2
printf '     exposed   : nothing on the agent -- no port, no webhook URL; %ss wall clock\n' "$((SECONDS - START))" >&2
[ -z "$KEEP" ] || say "state kept in $D (observer transcript: $D/obs.out)"
