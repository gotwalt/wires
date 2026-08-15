#!/usr/bin/env bash
#
# Soak: a topic under the two failures that actually happen -- a node that
# freezes, and a node that dies.
#
# This is the week-gate rehearsal, compressed to about two minutes. Three
# resident nodes share one topic: P publishes a numbered stream, T1 and T2 read
# it. Mid-stream:
#
#   * T2 is SIGSTOPped for longer than the QUIC idle timeout (iroh's direct
#     path gives up at 15s, a relayed one at 30s), then SIGCONTed. Every
#     connection it had is gone by the time it wakes up.
#   * T1 is `kill -9`ed -- no graceful shutdown, no flush -- and restarted
#     against nothing but its own persisted state.
#
# Then the audit: BOTH readers' transcripts must contain messages 1..N exactly
# once each, in order. Gaps are healed by replay; the absence of duplicates is
# structural, because a line is only printed when the append reported
# `Inserted` (spec §7). A missing message is a lost write; a repeated one is a
# broken dedupe; either fails the run.
#
# Run it directly from the repo root -- NOT via `bazel run //.scripts:...`.
#
#   ./.scripts/soak-topic.sh            30 messages, narrated progress
#   ./.scripts/soak-topic.sh --quiet    result lines only
#   ./.scripts/soak-topic.sh --keep     leave the state dir behind
#   SOAK_N=60 ./.scripts/soak-topic.sh  longer run

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
TOPIC="soak"

# How many messages, how fast, and how long the freeze lasts. The freeze must
# outlast iroh's relayed-path idle timeout (30s) for the test to mean anything.
N="${SOAK_N:-30}"
INTERVAL="${SOAK_INTERVAL:-2}"
FREEZE="${SOAK_FREEZE:-35}"
# When to interfere, in messages published.
STOP_AT=6
KILL_AT=12
# How long to wait, after the last publish, for both readers to settle.
SETTLE=120

D="$(mktemp -d)"
P_PID=""
T1_PID=""
T2_PID=""
PUB_PID=""
# Inline rather than a `cleanup` function, and with the loop variable declared
# up front: shellcheck does not model the EXIT trap of a script that ends in an
# explicit `exit` (SC2329), nor a `for` variable first seen inside a trap string
# (SC2154). SIGCONT comes first because a stopped process cannot act on a TERM.
p=""
trap 'for p in $T2_PID $T1_PID $P_PID $PUB_PID; do kill -CONT "$p" 2>/dev/null || true; done; for p in $PUB_PID $T1_PID $T2_PID $P_PID; do kill "$p" 2>/dev/null || true; done; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

say() { [ -n "$QUIET" ] || printf '\033[36m[soak]\033[0m %s\n' "$*" >&2; }
ok() { printf '\033[32m[ok]\033[0m   %s\n' "$*" >&2; }
FAILED=0
no() {
	printf '\033[31m[FAIL]\033[0m %s\n' "$*" >&2
	FAILED=1
}
bad() {
	printf '\033[31m[FAIL]\033[0m %s\n' "$*" >&2
	printf 'RESULT: FAIL (%s)\n' "$*"
	exit 1
}

wait_for() { # file regex tenths-of-a-second
	local file="$1" re="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && grep -qE "$re" "$file"; then return 0; fi
		sleep 0.1
	done
	return 1
}
wait_lines() { # file want tenths-of-a-second
	local file="$1" want="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && [ "$(count "$file")" -ge "$want" ]; then return 0; fi
		sleep 0.1
	done
	return 1
}
count() { [ -e "$1" ] && wc -l <"$1" | tr -d ' ' || echo 0; }
ticket_of() { grep -m1 '^share to bootstrap: ' "$1" | sed 's/^share to bootstrap: //'; }

if [ ! -x "$WIRES" ]; then
	say "building //wires (first run) ..."
	bazel build //wires >/dev/null 2>&1
fi

# ==========================================================================
# Setup: root + three members, one roster, one topic.
# ==========================================================================
op="$D/operator"
p="$D/publisher"
t1="$D/reader-1"
t2="$D/reader-2"
mkdir -p "$op" "$p" "$t1" "$t2"

WIRES_HOME="$op" "$WIRES" keygen --save-root >/dev/null
for h in "$p" "$t1" "$t2"; do WIRES_HOME="$h" "$WIRES" keygen --save-node >/dev/null; done

node_id() { "$WIRES" keygen --node-seed "$(tr -d '\n' <"$1/node.seed")" | awk '/^node_id/{print $2}'; }
P_ID="$(node_id "$p")"
T1_ID="$(node_id "$t1")"
T2_ID="$(node_id "$t2")"
P8="${P_ID:0:8}"

for id in "$P_ID" "$T1_ID" "$T2_ID"; do
	WIRES_HOME="$op" "$WIRES" roster add --member "$id" >/dev/null
	WIRES_HOME="$op" "$WIRES" member --subject "$id" --ttl 7200 >"$D/$id.member"
done
commit="$(WIRES_HOME="$op" "$WIRES" roster commit --ttl 7200 --out "$D/v1")"
HEAD="$(printf '%s\n' "$commit" | awk '/^head /{print $2}')"
for pair in "$p:$P_ID" "$t1:$T1_ID" "$t2:$T2_ID"; do
	home="${pair%%:*}"
	id="${pair##*:}"
	WIRES_HOME="$home" "$WIRES" import \
		--membership-file "$D/$id.member" \
		--inclusion-proof-file "$D/v1/$id.proof" \
		--roster-head "$HEAD" \
		--fabric-key-file "$D/v1/$id.key" >/dev/null
done
say "roster v1: publisher $P8 plus two readers; $N messages every ${INTERVAL}s"

# ==========================================================================
# Stand the mesh up: P first (it owns the ticket everyone bootstraps from).
# ==========================================================================
WIRES_HOME="$p" "$WIRES" tail "$TOPIC" >"$D/p.out" 2>"$D/p.err" &
P_PID=$!
wait_for "$D/p.err" '^share to bootstrap: ' 300 || bad "P never printed a ticket"
TICKET_P="$(ticket_of "$D/p.err")"

WIRES_HOME="$t1" "$WIRES" tail "$TOPIC" --peer "$TICKET_P" >"$D/t1a.out" 2>"$D/t1a.err" &
T1_PID=$!
WIRES_HOME="$t2" "$WIRES" tail "$TOPIC" --peer "$TICKET_P" >"$D/t2.out" 2>"$D/t2.err" &
T2_PID=$!
wait_for "$D/t1a.err" 'neighbor up' 600 || bad "T1 never joined the mesh"
wait_for "$D/t2.err" 'neighbor up' 600 || bad "T2 never joined the mesh"
say "mesh up: P=$P_PID T1=$T1_PID T2=$T2_PID"

# ==========================================================================
# The stream. Runs in the background so the failures can be injected against
# message counts rather than against a guessed clock.
# ==========================================================================
publisher() {
	local i
	for i in $(seq 1 "$N"); do
		WIRES_HOME="$p" "$WIRES" publish "$TOPIC" \
			-m "$(printf 'soak %03d' "$i")" 2>>"$D/pub.err" ||
			printf 'publish %d FAILED\n' "$i" >>"$D/pub.err"
		printf '%d\n' "$i" >>"$D/progress"
		sleep "$INTERVAL"
	done
}
: >"$D/progress"
publisher &
PUB_PID=$!

# ---- failure 1: freeze a reader past the QUIC idle timeout ----------------
wait_lines "$D/progress" "$STOP_AT" 1200 || bad "the publisher stalled before message $STOP_AT"
kill -STOP "$T2_PID"
froze_at="$(date +%s)"
say "T2 ($T2_PID) SIGSTOPped at message $STOP_AT -- frozen for ${FREEZE}s"

# ---- failure 2: kill the other reader outright and restart it -------------
wait_lines "$D/progress" "$KILL_AT" 1200 || bad "the publisher stalled before message $KILL_AT"
kill -9 "$T1_PID" 2>/dev/null || true
wait "$T1_PID" 2>/dev/null || true
say "T1 ($T1_PID) killed -9 at message $KILL_AT -- restarting from its own state"
# No `--peer`: the restart must find its way back from `topics/<id>.peers.json`
# alone, which is the whole point of persisting it (spec §7).
WIRES_HOME="$t1" "$WIRES" tail "$TOPIC" >"$D/t1b.out" 2>"$D/t1b.err" &
T1_PID=$!
wait_for "$D/t1b.err" '^share to bootstrap: ' 600 || bad "T1 did not come back up"

# ---- thaw ------------------------------------------------------------------
now="$(date +%s)"
left=$((FREEZE - (now - froze_at)))
[ "$left" -gt 0 ] && sleep "$left"
kill -CONT "$T2_PID"
say "T2 SIGCONTed after ${FREEZE}s -- every connection it had is long gone"

# ---- let the stream finish -------------------------------------------------
wait "$PUB_PID" 2>/dev/null || true
PUB_PID=""
published="$(count "$D/progress")"
[ "$published" -eq "$N" ] || bad "the publisher only got through $published of $N messages"
say "all $N published; waiting up to ${SETTLE}s for both readers to settle"

wait_lines "$D/t1b.out" "$N" $((SETTLE * 10)) || say "T1 stopped short at $(count "$D/t1b.out")"
wait_lines "$D/t2.out" "$N" $((SETTLE * 10)) || say "T2 stopped short at $(count "$D/t2.out")"
# A moment past the last expected line, so a duplicate has a chance to show up
# and be caught rather than to arrive after the audit.
sleep 5

# ==========================================================================
# Audit
# ==========================================================================
seq 1 "$N" | while read -r i; do printf 'soak %03d\n' "$i"; done >"$D/expected"

audit() { # $1 = label, $2 = transcript
	local label="$1" file="$2" got="$D/$1.got" senders
	if [ ! -s "$file" ]; then
		no "$label: transcript is empty"
		return
	fi
	# Everything after `HH:MM:SS <sender8> ` is the message text.
	cut -d' ' -f3- "$file" >"$got"
	senders="$(awk '{print $2}' "$file" | sort -u | tr '\n' ' ')"
	[ "$senders" = "$P8 " ] || no "$label: unexpected senders [$senders], want [$P8]"
	if diff -u "$D/expected" "$got" >"$D/$label.diff" 2>&1; then
		ok "$label: all $N messages, exactly once each, in order"
	else
		local missing dupes
		missing="$(comm -23 <(sort -u "$D/expected") <(sort -u "$got") | tr '\n' ' ')"
		dupes="$(sort "$got" | uniq -d | tr '\n' ' ')"
		no "$label: $(count "$got") lines; missing: [${missing:-none}]; duplicated: [${dupes:-none}]"
		[ -n "$QUIET" ] || head -20 "$D/$label.diff" | sed 's/^/     /' >&2
	fi
}

audit "T1-after-kill9" "$D/t1b.out"
audit "T2-after-freeze" "$D/t2.out"
audit "P-publisher" "$D/p.out"

# The pre-kill transcript is not audited for completeness -- it was cut off
# mid-stream on purpose -- but it must be a clean prefix, with no duplicates
# and nothing the restarted process disagrees with.
if [ -s "$D/t1a.out" ]; then
	cut -d' ' -f3- "$D/t1a.out" >"$D/t1a.got"
	if [ "$(sort "$D/t1a.got" | uniq -d | wc -l | tr -d ' ')" -eq 0 ] &&
		[ "$(head -n "$(count "$D/t1a.got")" "$D/expected")" = "$(cat "$D/t1a.got")" ]; then
		ok "T1-before-kill9: $(count "$D/t1a.got") lines, a clean in-order prefix"
	else
		no "T1-before-kill9: not a clean prefix of the stream"
	fi
fi

for name in "P:$P_PID" "T1:$T1_PID" "T2:$T2_PID"; do
	kill -0 "${name##*:}" 2>/dev/null || no "${name%%:*} is not running at the end of the soak"
done

if [ "$FAILED" -eq 0 ]; then
	printf 'RESULT: PASS (%s messages, 1 freeze of %ss, 1 kill -9, 0 gaps, 0 duplicates)\n' \
		"$N" "$FREEZE"
	exit 0
fi
printf 'RESULT: FAIL (state kept in %s)\n' "$D"
KEEP=1
exit 1
