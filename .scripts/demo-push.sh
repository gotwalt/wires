#!/usr/bin/env bash
#
# Demo (card 24): a host calls the agent back. The agent starts a build on
# the workbench, which returns at once; when the build fails, the workbench
# pushes the result to the agent by key, and the agent follows up with the
# log. Neither side exposes an endpoint: no webhook, no public URL.
#
# Three keystores on one machine, all loopback (as in demo-remote-cli.sh):
#
#   workbench -- `wires serve push-host.json`: implements three services from
#                the mock CI (.scripts/fixtures/ci.sh): deploy, status, logs;
#                "push": {"allow": ["analyst"]}.
#   agent     -- signs in (mock IdP) as an analyst, then only `wires call` /
#                `wires inbox` / `wires watch`, in locked mode (WIRES_LOCKED=1).
#   root      -- the admin: init, the analyst role, the three services on the
#                workbench, one invite per machine.
#
# Asserted: `deploy` returns within a few seconds while the build keeps
# running; `wires inbox --wait` (what an agent would run as a background
# command) exits 0 when the build's job runs `wires push --to
# "$WIRES_CALLER_NODE"`, and its line names the verified host; the agent's
# `logs` call returns the failing assertion; the agent's own `wires watch`
# shows ▶ deploy, then ⇢ build-41, then ▶ logs, in that order, from the
# workbench's signed log; and a "sleeping" agent (nothing running) finds the
# next build's push queued on the workbench, fetched by its next plain
# `wires inbox`.
#
# Run it from the repo root:
#
#   ./.scripts/demo-push.sh            narrated
#   ./.scripts/demo-push.sh --quiet    assertions only
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
EMAIL="alice@example.com"
# Narrated mode pauses ~4.5 s before `inbox --wait` starts; the build must outlast that.
JOB_SECS=3
[ -n "$QUIET" ] || JOB_SECS=8
START=$SECONDS

D="$(mktemp -d)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/.scripts/lib.sh"
WB_PID=""
WAIT_PID=""
p=""
trap 'for p in $WAIT_PID $WB_PID $IDP_PID; do kill "$p" 2>/dev/null || true; done; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

# The last line of $1 holding every remaining fixed string, as
# `<line number>:<line>` (or fail), so steps can be checked for order.
numbered_line() {
	local file="$1" hits
	shift
	hits="$(grep -n '' "$file")"
	for s in "$@"; do hits="$(printf '%s\n' "$hits" | grep -F -- "$s" || true)"; done
	[ -n "$hits" ] && printf '%s\n' "$hits" | tail -1
}
admin() { WIRES_HOME="$root" "$WIRES" "$@"; }
# The agent: locked mode, so it can steer nothing but the service and its args.
agent_wires() { WIRES_HOME="$agent" WIRES_LOCKED=1 "$WIRES" "$@"; }

build_wires
command -v curl >/dev/null || bad "curl is not on PATH"
command -v perl >/dev/null || bad "perl is not on PATH (the mock CI's clock)"

# ==========================================================================
# Setup (off camera): three keystores, one signed policy, one IdP, one mock CI.
# ==========================================================================
root="$D/root"
wb="$D/wb"
agent="$D/agent"
mkdir -p "$root" "$wb" "$agent"

# The IdP comes first: the network's first policy trusts it, and every role
# names the issuer it trusts.
start_mock_idp "$EMAIL"
ROOT_ID="$(admin init --issuer "$ISSUER" --client-id "$CLIENT_ID" --public-client-secret not-so-secret | awk '/^network /{print $2}')"
WB_ID="$(WIRES_HOME="$wb" "$WIRES" id 2>/dev/null)"
AG_ID="$(WIRES_HOME="$agent" "$WIRES" id 2>/dev/null)"
[ -n "$ROOT_ID" ] && [ -n "$WB_ID" ] && [ -n "$AG_ID" ] || bad "setup: could not read the key ids"
AG8="${AG_ID:0:8}"
WB8="${WB_ID:0:8}"
admin role set analyst --issuer "$ISSUER" '*@example.com' >/dev/null 2>&1
admin invite "$WB_ID" --name workbench >/dev/null 2>&1
# The workbench is also the network's one directory (card 37: callers ask
# one for their view). It isn't up yet, so each edit is stored here and
# notes that no directory is running yet; the workbench's token carries the
# policy.
admin directory add workbench >/dev/null 2>"$D/dir.err" || {
	cat "$D/dir.err" >&2
	bad "setup: wires directory add workbench failed"
}
for svc in deploy status logs; do
	admin service add "$svc" --allow analyst --host workbench \
		--description "$svc a CI build: \`$svc -- build <n>\`" >/dev/null 2>"$D/svc.err" || {
		cat "$D/svc.err" >&2
		bad "setup: wires service add $svc failed"
	}
done
WB_TOKEN="$(admin invite "$WB_ID" --name workbench 2>/dev/null)" || true
WIRES_HOME="$wb" "$WIRES" join "$WB_TOKEN" >/dev/null

HOST_JSON="$D/host.json"
JOBS="$D/jobs"
mkdir -p "$JOBS"
# A service runs in a minimal environment (PATH, the locale, host.json's
# `env`, the WIRES_* values): the mock CI's settings go in host.json.
sed -e "s|__ISSUER__|$ISSUER|" -e "s|__CLIENT_ID__|$CLIENT_ID|" \
	-e "s|__CI__|$repo/.scripts/fixtures/ci.sh|" \
	-e "s|__JOBS__|$JOBS|" -e "s|__JOB_SECS__|$JOB_SECS|" -e "s|__WIRES__|$WIRES|" \
	"$repo/.scripts/fixtures/push-host.json" >"$HOST_JSON"
"$WIRES" serve --check "$HOST_JSON" >"$D/check.out" 2>&1 || {
	cat "$D/check.out" >&2
	bad "setup: serve --check rejected push-host.json"
}
(cd "$D" && WIRES_HOME="$wb" exec "$WIRES" serve "$HOST_JSON" >"$D/wb.out" 2>"$D/wb.err") &
WB_PID=$!
wait_for "$wb/run/hint" " " 300 || {
	sed 's/^/  workbench| /' "$D/wb.err" >&2
	bad "setup: the workbench never came up"
}
# Addressing is by key; on loopback, the workbench's own hint line stands in
# for n0 discovery.
cp "$wb/run/hint" "$root/hints"
cp "$wb/run/hint" "$agent/hints"
AG_TOKEN="$(admin invite "$AG_ID" --name agent 2>"$D/invite.err")" || {
	cat "$D/invite.err" >&2
	bad "setup: inviting the agent failed"
}
WIRES_HOME="$agent" "$WIRES" join "$AG_TOKEN" >/dev/null

login_as "$agent" "$EMAIL"
agent_wires services >"$D/services.out" 2>/dev/null || true
grep -qE "^deploy .*\(analyst\)$" "$D/services.out" || {
	cat "$D/services.out" >&2
	bad "setup: the signed-in agent does not see deploy"
}

say "workbench ${WB8}...  runs a mock CI: deploy / status / logs; may push to analysts"
say "agent     ${AG8}...  signed in as $EMAIL; runs only \`wires call\` and \`wires inbox\` (locked)"
show "$D/services.out"
beat 4

# ==========================================================================
step "1  the agent starts a build -- the service returns at once"
# ==========================================================================
run "wires call deploy -- build 41"
t0=$SECONDS
agent_wires call deploy -- build 41 >"$D/d1.out" 2>"$D/d1.err" || {
	cat "$D/d1.err" >&2
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
# is woken when it exits. It dials the workbench by key and holds a fetch
# open; while it runs, a push dialed to it by key lands too.
run "wires inbox --wait --timeout 30s &"
agent_wires inbox --wait --timeout 30s >"$D/i1.out" 2>"$D/i1.err" &
WAIT_PID=$!
beat 1
alive "$WAIT_PID" || {
	cat "$D/i1.err" >&2
	bad "2: inbox --wait exited before anything was pushed"
}
ok "2: waiting (pid $WAIT_PID), no webhook URL"

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
ok "3: inbox --wait woke with the push; the sender is the host key, verified"
beat 3

# ==========================================================================
step "4  woken, the agent follows up -- the log, from the same host"
# ==========================================================================
run "wires call logs -- build 41 --tail 50"
agent_wires call logs -- build 41 --tail 50 >"$D/l1.out" 2>"$D/l1.err" || {
	cat "$D/l1.err" >&2
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
step "5  the workbench's own log holds the whole chain -- the agent reads its part"
# ==========================================================================
run "wires watch --once   # the agent's own calls, and the pushes to it"
agent_wires watch --once >"$D/w1.out" 2>"$D/w1.err" || {
	cat "$D/w1.err" >&2
	bad "5: wires watch failed"
}
SD="$(numbered_line "$D/w1.out" "▶" "$EMAIL" "[analyst] deploy build 41")" || {
	cat "$D/w1.out" >&2
	bad "5: no ▶ deploy naming $EMAIL"
}
# `delivered` if the host's direct dial reached the waiting inbox, else
# `fetched` by its long poll.
SP="$(numbered_line "$D/w1.out" "⇢" "→ $EMAIL" "[analyst] \"build-41\" ")" || {
	cat "$D/w1.out" >&2
	bad "5: no ⇢ build-41 in the records"
}
SL="$(numbered_line "$D/w1.out" "▶" "$EMAIL" "[analyst] logs build 41 --tail 50")" || {
	cat "$D/w1.out" >&2
	bad "5: no ▶ logs naming $EMAIL"
}
nD="${SD%%:*}"
nP="${SP%%:*}"
nL="${SL%%:*}"
[ "$nD" -lt "$nP" ] && [ "$nP" -lt "$nL" ] || {
	cat "$D/w1.out" >&2
	bad "5: the chain is out of order (deploy line $nD, push $nP, logs $nL)"
}
ok "5: ▶ deploy → ⇢ push → ▶ logs, in order, verified against the host's signed log"
line "${SD#*:}"
line "${SP#*:}"
line "${SL#*:}"
beat 3

# ==========================================================================
step "6  a sleeping agent: nothing running -- the push waits on the workbench"
# ==========================================================================
run "wires call deploy -- build 42   # and then the agent stops; no inbox running"
agent_wires call deploy -- build 42 >"$D/d2.out" 2>"$D/d2.err" || {
	cat "$D/d2.err" >&2
	bad "6: wires call deploy (42) failed"
}
for _ in $(seq 1 $((JOB_SECS * 10 + 100))); do
	[ -f "$JOBS/build-42/pushed_ms" ] && break
	sleep 0.1
done
[ -f "$JOBS/build-42/pushed_ms" ] || bad "6: build-42's job never pushed"
grep -qE "^queued +$EMAIL \($AG8\)" "$JOBS/build-42/push.out" || {
	cat "$JOBS/build-42/push.out" "$JOBS/build-42/push.err" >&2
	bad "6: with nothing running, build-42's push was not queued"
}
ok "6: build-42 failed while the agent slept; the push is queued on the workbench"
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
agent_wires inbox >"$D/i3.out" 2>/dev/null
[ ! -s "$D/i3.out" ] || bad "6: a read message was printed twice"
agent_wires watch --once >"$D/w2.out" 2>/dev/null || true
QF="$(numbered_line "$D/w2.out" "⇢" "→ $EMAIL" "\"build-42\" fetched")" || {
	cat "$D/w2.out" >&2
	bad "6: no ⇢ build-42 fetched in the records"
}
ok "6: fetched on the next \`wires inbox\` -- once"
line "${QF#*:}"
alive "$WB_PID" || bad "6: the workbench died"

# ==========================================================================
step "SUMMARY"
# ==========================================================================
printf '     callback  : build-41 result pushed host -> agent by key; inbox --wait woke %s ms after the build finished\n' "$LAT" >&2
printf '     follow-up : logs -- build 41 --tail 50 -> test_orders_total left %s\n' "$GOT" >&2
printf '     recorded  : ▶ deploy → ⇢ build-41 → ▶ logs in the host'"'"'s signed log, naming %s\n' "$EMAIL" >&2
# shellcheck disable=SC2016 # literal backticks in the summary
printf '     asleep    : build-42 queued on the workbench, fetched by the next `wires inbox`\n' >&2
printf '     exposed   : nothing on the agent -- no webhook URL; %ss wall clock\n' "$((SECONDS - START))" >&2
[ -z "$KEEP" ] || say "state kept in $D"
