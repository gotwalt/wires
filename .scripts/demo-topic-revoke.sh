#!/usr/bin/env bash
#
# Demo: taking one agent out of a live conversation, without restarting anyone.
#
# `.scripts/demo-revoke.sh` shows revocation on a one-to-one session. This is
# the multiway version, and it is the harder claim: A, B and C are all in one
# topic, A's tail is the resident node, and the operator removes B *while the
# conversation is running*. The script asserts each of the four latencies
# spec §2.4 promises:
#
#   1. confidentiality  -- immediate. The commit that removed B minted a new
#                          fabric key sealed only to A and C.
#   2. ingest integrity -- immediate. B cannot mint anything the survivors will
#                          accept under the new key.
#   3. mesh eviction    -- within one watchdog interval (30s by default) of A
#                          holding the new head. Asserted against A's own log.
#   4. re-admission     -- refused outright: B's next cold publish exits 77.
#
# And the thing the whole demo exists for: A's tail is the SAME PROCESS at the
# end as at the start. Nothing was restarted, re-keyed by hand, or reconfigured.
#
# Because it waits out a real watchdog interval, a run takes about a minute.
#
# Run it directly from the repo root -- NOT via `bazel run //.scripts:...`.
#
#   ./.scripts/demo-topic-revoke.sh          narrated, paced for watching
#   ./.scripts/demo-topic-revoke.sh --quiet  assertions only
#   ./.scripts/demo-topic-revoke.sh --keep   leave the state dir behind

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
WIRES="${WIRES_BIN:-$repo/bazel-bin/wires/wires}"
TOPIC="ops"
EXIT_DENIED=77
# `ADMIT_RECHECK` is 30s (wires/admission.rs). Allow one full interval plus
# slack for the pass itself; anything past this is a real regression.
EVICT_BUDGET=45

D="$(mktemp -d)"
A_PID=""
B_PID=""
C_PID=""
trap 'for p in $A_PID $B_PID $C_PID; do kill "$p" 2>/dev/null || true; done; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

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

# Poll a file for a regex. $3 is the budget in tenths of a second.
wait_for() {
	local file="$1" re="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && grep -qE "$re" "$file"; then return 0; fi
		sleep 0.1
	done
	return 1
}
wait_lines() {
	local file="$1" want="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && [ "$(wc -l <"$file" | tr -d ' ')" -ge "$want" ]; then return 0; fi
		sleep 0.1
	done
	return 1
}
# Poll for a single line matching both patterns. The logs are ANSI-decorated
# even when redirected, so a `field=value` pattern would never match; pinning
# the message text and the bare node id separately does.
wait_pair() {
	local file="$1" re1="$2" re2="$3" n="${4:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && grep "$re1" "$file" | grep -q "$re2"; then return 0; fi
		sleep 0.1
	done
	return 1
}
count() { wc -l <"$1" | tr -d ' '; }

if [ ! -x "$WIRES" ]; then
	say "building //wires (first run) ..."
	bazel build //wires >/dev/null 2>&1
fi

# ==========================================================================
# Setup (off camera): root + A, B, C, all on roster v1.
# ==========================================================================
op="$D/operator"
a="$D/agent-a"
b="$D/agent-b"
c="$D/agent-c"
mkdir -p "$op" "$a" "$b" "$c"

WIRES_HOME="$op" "$WIRES" keygen --save-root >/dev/null
for h in "$a" "$b" "$c"; do WIRES_HOME="$h" "$WIRES" keygen --save-node >/dev/null; done

node_id() { "$WIRES" keygen --node-seed "$(tr -d '\n' <"$1/node.seed")" | awk '/^node_id/{print $2}'; }
ROOT_ID="$("$WIRES" keygen --root-seed "$(tr -d '\n' <"$op/root.seed")" | awk '/^root_id/{print $2}')"
A_ID="$(node_id "$a")"
B_ID="$(node_id "$b")"
C_ID="$(node_id "$c")"
A8="${A_ID:0:8}"
B8="${B_ID:0:8}"
C8="${C_ID:0:8}"

for id in "$A_ID" "$B_ID" "$C_ID"; do
	WIRES_HOME="$op" "$WIRES" roster add --member "$id" >/dev/null
	WIRES_HOME="$op" "$WIRES" member --subject "$id" --ttl 3600 >"$D/$id.member"
done
commit1="$(WIRES_HOME="$op" "$WIRES" roster commit --ttl 3600 --out "$D/v1")"
HEAD1="$(printf '%s\n' "$commit1" | awk '/^head /{print $2}')"

# Install (or refresh) one member's credentials from a commit directory.
refresh() { # $1 = home, $2 = node id, $3 = proof dir, $4 = head token
	WIRES_HOME="$1" "$WIRES" import \
		--membership-file "$D/$2.member" \
		--inclusion-proof-file "$3/$2.proof" \
		--roster-head "$4" \
		--fabric-key-file "$3/$2.key" >/dev/null
}
refresh "$a" "$A_ID" "$D/v1" "$HEAD1"
refresh "$b" "$B_ID" "$D/v1" "$HEAD1"
refresh "$c" "$C_ID" "$D/v1" "$HEAD1"

say "Three AI agents -- A, B and C -- share one topic. There is no server:"
say "A's process happens to hold the log, but every one of them checks every"
say "other one against the same signed list from the human."
beat 5
[ -n "$QUIET" ] || printf '\n' >&2
say "A = ${A8}...   B = ${B8}...   C = ${C8}..."
say "list version 1: all three are on it."
beat 3

# ==========================================================================
step "ACT 1  the conversation, with everyone still on the list"
# ==========================================================================
run "wires tail $TOPIC        # A, the resident node -- watch this pid"
WIRES_HOME="$a" "$WIRES" tail "$TOPIC" >"$D/a.out" 2>"$D/a.err" &
A_PID=$!
wait_for "$D/a.err" '^share to bootstrap: ' 300 ||
	bad "act 1: A's tail never printed a bootstrap ticket; see $D/a.err"
TICKET_A="$(grep -m1 '^share to bootstrap: ' "$D/a.err" | sed 's/^share to bootstrap: //')"
ok "act 1: A's tail is pid $A_PID"

run "wires tail $TOPIC --peer \$TICKET_A   # B joins A's mesh and stays"
WIRES_HOME="$b" "$WIRES" tail "$TOPIC" --peer "$TICKET_A" >"$D/b.out" 2>"$D/b.err" &
B_PID=$!
wait_for "$D/a.err" 'neighbor up' 300 || {
	sed 's/^/  A| /' "$D/a.err" >&2
	bad "act 1: A never saw B as a neighbor"
}
ok "act 1: B is a live neighbor of A -- a real mesh, not a request/response"
beat 2

run "wires publish $TOPIC -m 'B: rolling the canary'   # through B's own tail"
WIRES_HOME="$b" "$WIRES" publish "$TOPIC" -m "B: rolling the canary" 2>"$D/b-pub.err" ||
	bad "act 1: B's publish failed"
wait_lines "$D/a.out" 1 300 || {
	sed 's/^/  A| /' "$D/a.err" >&2
	bad "act 1: B's message never reached A"
}
first="$(sed -n 1p "$D/a.out")"
printf '%s\n' "$first" | grep -qE "^[0-9]{2}:[0-9]{2}:[0-9]{2} $B8 B: rolling the canary$" ||
	bad "act 1: A's first line was not B's message: [$first]"
ok "act 1: A read B's message"
line "$first"
beat 3

# ==========================================================================
step "ACT 2  the human removes B -- two commands, nobody restarts"
# ==========================================================================
say "the human does not log into A, does not touch B's machine, does not"
say "rotate a password. They edit their signed list and sign it again."
beat 4
run "wires roster remove --member ${B8}...  &&  wires roster commit"
WIRES_HOME="$op" "$WIRES" roster remove --member "$B_ID" >/dev/null
commit2="$(WIRES_HOME="$op" "$WIRES" roster commit --ttl 3600 --out "$D/v2")"
HEAD2="$(printf '%s\n' "$commit2" | awk '/^head /{print $2}')"
[ -f "$D/v2/$B_ID.key" ] && bad "act 2: the new fabric key was sealed to B, who is off the list"
ok "act 2: version 2 minted a new lockbox key -- sealed to A and C, not to B"
beat 2
say "that is claim #1, and it is instant: B was not a recipient of the new"
say "key, so nothing said from here on is even readable by it."
beat 4

run "wires import --inclusion-proof-file P2 --roster-head H2 --fabric-key-file K2"
refresh "$a" "$A_ID" "$D/v2" "$HEAD2"
refresh "$c" "$C_ID" "$D/v2" "$HEAD2"
ok "act 2: A and C picked up version 2 (B has nothing new to pick up)"
[ "$(kill -0 "$A_PID" 2>/dev/null && echo live)" = "live" ] ||
	bad "act 2: A's tail died; the point of this demo is that it does not"
say "A's tail is still pid $A_PID. It re-reads the list per handshake and"
say "per watchdog pass -- there is no config to reload and no socket to bounce."
beat 4

# ==========================================================================
step "ACT 3  A drops B from the mesh, on its own, within the watchdog window"
# ==========================================================================
say "B is still connected and still thinks it is a member. A's watchdog runs"
say "every 30 seconds: it re-checks every peer it has admitted against the"
say "list as it stands NOW, and B no longer passes."
beat 4
before_evict="$(count "$D/a.out")"
run "# (nothing typed here -- A does this by itself)"
wait_for "$D/a.err" "admission no longer holds; evicting" $((EVICT_BUDGET * 10)) || {
	sed 's/^/  A| /' "$D/a.err" | tail -20 >&2
	bad "act 3: A did not evict B within ${EVICT_BUDGET}s"
}
# The log is ANSI-decorated even when redirected, so match the bare node id on
# the eviction line rather than the `peer=` field.
grep "admission no longer holds" "$D/a.err" | grep -q "$B_ID" ||
	bad "act 3: A evicted somebody, but not B"
ok "act 3: A evicted B within ${EVICT_BUDGET}s -- claim #3, no restart"
[ -n "$QUIET" ] || grep -m1 "admission no longer holds" "$D/a.err" |
	sed 's/^/     /' >&2
beat 3

say "now B talks anyway. Its process is still up, it still holds the old key,"
say "and it does not know it has been dropped."
beat 3
run "wires publish $TOPIC -m 'B: still here?'    # from B's still-running tail"
WIRES_HOME="$b" "$WIRES" publish "$TOPIC" -m "B: still here?" 2>"$D/b-pub2.err" || true
sleep 5
after_evict="$(count "$D/a.out")"
[ "$after_evict" -eq "$before_evict" ] ||
	bad "act 3: A's transcript grew from $before_evict to $after_evict lines after the eviction"
grep -q "B: still here?" "$D/a.out" &&
	bad "act 3: B's post-revocation message is in A's transcript"
ok "act 3: A's transcript is unchanged at $after_evict lines -- B shouted into a closed room"
beat 3

# ==========================================================================
step "ACT 4  B tries to come back in from scratch"
# ==========================================================================
say "maybe B just needs to reconnect? It restarts, holding the same ticket,"
say "the same key, and the same proof it was admitted with an hour ago."
beat 4
kill "$B_PID" 2>/dev/null || true
wait "$B_PID" 2>/dev/null || true
B_PID=""
run "wires publish $TOPIC -m 'B: let me back in' --peer \$TICKET_A"
set +e
WIRES_HOME="$b" "$WIRES" publish "$TOPIC" -m "B: let me back in" \
	--peer "$TICKET_A" >"$D/b-cold.out" 2>"$D/b-cold.err"
rc_b=$?
set -e
[ "$rc_b" -eq "$EXIT_DENIED" ] || {
	sed 's/^/  B| /' "$D/b-cold.err" >&2
	bad "act 4: B's cold publish exited $rc_b, expected $EXIT_DENIED"
}
ok "act 4: exit $EXIT_DENIED -- claim #4, re-admission refused at the door"
REASON="$(grep -m1 'denied by responder' "$D/b-cold.err" || true)"
[ -n "$REASON" ] || bad "act 4: B was refused without being told why"
[ -n "$QUIET" ] || printf '\033[31m     %s\033[0m\n' "$REASON" >&2
beat 3
say "translation: \"your proof is against list version 1; the list is now"
say "version 2.\" B's credentials were never confiscated. They just stopped"
say "matching anything."
beat 4

# ==========================================================================
step "ACT 5  and C, who is still on the list, carries on"
# ==========================================================================
say "the test of a revocation is not that it stops somebody. It is that it"
say "stops exactly one somebody."
beat 3
run "wires tail $TOPIC --peer \$TICKET_A     # C joins, using A's original ticket"
WIRES_HOME="$c" "$WIRES" tail "$TOPIC" --peer "$TICKET_A" >"$D/c.out" 2>"$D/c.err" &
C_PID=$!
# A's log already names B on older `neighbor up` lines, so match C's id on one.
wait_pair "$D/a.err" 'neighbor up' "$C_ID" 600 || {
	sed 's/^/  A| /' "$D/a.err" | tail -20 >&2
	sed 's/^/  C| /' "$D/c.err" | tail -20 >&2
	bad "act 5: C could not join A's mesh -- the revocation caught a bystander"
}
ok "act 5: C was admitted against roster v2 -- A's proof is current too"
beat 2

run "wires publish $TOPIC -m 'C: canary is green'"
WIRES_HOME="$c" "$WIRES" publish "$TOPIC" -m "C: canary is green" 2>"$D/c-pub.err" || {
	sed 's/^/  C| /' "$D/c-pub.err" >&2
	bad "act 5: C's publish failed"
}
wait_lines "$D/a.out" $((before_evict + 1)) 600 || {
	sed 's/^/  A| /' "$D/a.err" | tail -20 >&2
	sed 's/^/  C| /' "$D/c-pub.err" >&2
	bad "act 5: C's message never reached A -- the revocation caught a bystander"
}
last="$(tail -1 "$D/a.out")"
printf '%s\n' "$last" | grep -qE "^[0-9]{2}:[0-9]{2}:[0-9]{2} $C8 C: canary is green$" ||
	bad "act 5: A's last line was not C's message: [$last]"
ok "act 5: A read C's message, sealed under the NEW key -- the mesh is alive"
line "$last"
beat 2

grep -q "B: still here?" "$D/a.out" && bad "act 5: B's message surfaced late"
[ "$(kill -0 "$A_PID" 2>/dev/null && echo "$A_PID")" = "$A_PID" ] ||
	bad "act 5: A's tail is not the process it was in act 1"
ok "act 5: A's tail is still pid $A_PID -- never restarted, start to finish"
beat 2

# ==========================================================================
step "SUMMARY"
# ==========================================================================
printf '     confidentiality : immediate -- v2 key never sealed to %s\n' "$B8" >&2
printf '     mesh eviction   : < %ss  -- A evicted %s on its own watchdog\n' "$EVICT_BUDGET" "$B8" >&2
printf '     re-admission    : exit %s -- B refused against roster v2\n' "$EXIT_DENIED" >&2
printf '     bystanders      : 0     -- %s published and was read after the removal\n' "$C8" >&2
printf '     restarts        : 0     -- A is pid %s throughout\n' "$A_PID" >&2
say "one human, one signed list, one line of change. No key rotation ritual,"
say "no service window, no auth server to ask."
beat 5
