#!/usr/bin/env bash
#
# Demo: two agents, one topic, nobody in the middle.
#
# `wires tail` is the resident node: it owns the topic log, the mesh, the
# admission gate, the replay server, and a unix control socket. `wires publish`
# is either a client of that socket (when a tail is resident) or a one-shot node
# of its own (when it is not). This script exercises both halves.
#
# Act 1 stands up agent A's tail and reads the bootstrap ticket off its stderr
# banner. Act 2 has agent B publish one message from a cold start, with nothing
# but that ticket -- no server, no broker, no account. Act 3 publishes from A
# itself, through the socket, while the tail keeps running. At the end A's
# stdout is asserted byte-for-byte: exactly two lines, in order, each stamped
# with the right sender.
#
# Everything is loopback: the ticket carries the tail's bound sockets, so no
# relay and no discovery service is involved in the dial.
#
# Run it directly from the repo root -- NOT via `bazel run //.scripts:...`.
#
#   ./.scripts/demo-topic.sh          narrated, paced for watching
#   ./.scripts/demo-topic.sh --quiet  assertions only
#   ./.scripts/demo-topic.sh --keep   leave the state dir behind

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

D="$(mktemp -d)"
TAIL_PID=""
trap 'if [ -n "$TAIL_PID" ]; then kill "$TAIL_PID" 2>/dev/null || true; fi; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

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
# Echo a transcript line the way the viewer sees it on the tail's terminal.
line() { [ -n "$QUIET" ] || printf '\033[1m     %s\033[0m\n' "$*" >&2; }

# Poll a file for a regex instead of sleeping a guessed interval. $3 is the
# budget in tenths of a second (default 30s).
wait_for() {
	local file="$1" re="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && grep -qE "$re" "$file"; then return 0; fi
		sleep 0.1
	done
	return 1
}

# Wait until a file has at least $2 lines.
wait_lines() {
	local file="$1" want="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && [ "$(wc -l <"$file" | tr -d ' ')" -ge "$want" ]; then return 0; fi
		sleep 0.1
	done
	return 1
}

if [ ! -x "$WIRES" ]; then
	say "building //wires (first run) ..."
	bazel build //wires >/dev/null 2>&1
fi

# ==========================================================================
# Setup (off camera): a root key, two member keys, one signed roster.
# ==========================================================================
op="$D/operator"
a="$D/agent-a"
b="$D/agent-b"
mkdir -p "$op" "$a" "$b"

WIRES_HOME="$op" "$WIRES" keygen --save-root >/dev/null
WIRES_HOME="$a" "$WIRES" keygen --save-node >/dev/null
WIRES_HOME="$b" "$WIRES" keygen --save-node >/dev/null

node_id() { "$WIRES" keygen --node-seed "$(tr -d '\n' <"$1/node.seed")" | awk '/^node_id/{print $2}'; }
ROOT_ID="$("$WIRES" keygen --root-seed "$(tr -d '\n' <"$op/root.seed")" | awk '/^root_id/{print $2}')"
A_ID="$(node_id "$a")"
B_ID="$(node_id "$b")"
A8="${A_ID:0:8}"
B8="${B_ID:0:8}"

WIRES_HOME="$op" "$WIRES" roster add --member "$A_ID" >/dev/null
WIRES_HOME="$op" "$WIRES" roster add --member "$B_ID" >/dev/null
commit="$(WIRES_HOME="$op" "$WIRES" roster commit --ttl 3600 --out "$D/proofs")"
HEAD="$(printf '%s\n' "$commit" | awk '/^head /{print $2}')"

# One `wires import` per member installs all four credentials at once.
install() { # $1 = home, $2 = node id, $3 = proof dir, $4 = head token
	WIRES_HOME="$op" "$WIRES" member --subject "$2" --ttl 3600 >"$D/$2.member"
	WIRES_HOME="$1" "$WIRES" import \
		--membership-file "$D/$2.member" \
		--inclusion-proof-file "$3/$2.proof" \
		--roster-head "$4" \
		--fabric-key-file "$3/$2.key" >/dev/null
}
install "$a" "$A_ID" "$D/proofs" "$HEAD"
install "$b" "$B_ID" "$D/proofs" "$HEAD"

say "The cast: a HUMAN with a master key, and two AI AGENTS -- A and B --"
say "who need to talk to each other about a shared job."
beat 4
[ -n "$QUIET" ] || printf '\n' >&2
say "The human never runs a server. They signed a one-line list -- \"A and B"
say "are in my network\" -- and handed each agent three small files: a pass,"
say "a proof they are on the list, and the network's shared lockbox key."
beat 5
[ -n "$QUIET" ] || printf '\n' >&2
say "agent A : ${A8}..."
say "agent B : ${B8}..."
say "topic   : \"$TOPIC\" -- not created anywhere; both sides compute the same"
say "          name from the fabric they belong to."
beat 4

# ==========================================================================
step "ACT 1  agent A opens the topic and gets an address to share"
# ==========================================================================
run "wires tail $TOPIC     # A's resident node: log + mesh + gate + socket"
WIRES_HOME="$a" "$WIRES" tail "$TOPIC" >"$D/a.out" 2>"$D/a.err" &
TAIL_PID=$!

wait_for "$D/a.err" '^share to bootstrap: ' 300 ||
	bad "act 1: A's tail never printed a bootstrap ticket; see $D/a.err"
TICKET_A="$(grep -m1 '^share to bootstrap: ' "$D/a.err" | sed 's/^share to bootstrap: //')"
[ -n "$TICKET_A" ] || bad "act 1: the bootstrap ticket was empty"
ok "act 1: A's tail is up as pid $TAIL_PID and published a ticket"
beat 1.5

[ -n "$QUIET" ] || {
	# The banner only -- the tracing lines beside it are noise on camera.
	grep '^wires tail: ' "$D/a.err" | sed 's/^/     /' >&2
	printf '\033[2m     share to bootstrap: %s...\033[0m\n' "${TICKET_A:0:56}" >&2
}
beat 2
say "that last blob is the whole bootstrap story: it is A's address plus the"
say "topic name. It is NOT a credential -- it is unsigned, and handing it to"
say "a stranger gets them a failed handshake, not a seat at the table."
beat 5

# ==========================================================================
step "ACT 2  agent B publishes, cold, holding only that ticket"
# ==========================================================================
say "B has never spoken to A. No account was created, no invite accepted,"
say "no port opened. B dials the ticket, both sides check each other against"
say "the human's signed list, and only then does the message move."
beat 4
run "wires publish $TOPIC -m 'deploying build 41' --peer \$TICKET_A"
WIRES_HOME="$b" "$WIRES" publish "$TOPIC" -m "deploying build 41" \
	--peer "$TICKET_A" 2>"$D/b.err" || {
	sed 's/^/     /' "$D/b.err" >&2
	bad "act 2: B's publish failed"
}

wait_lines "$D/a.out" 1 300 || {
	sed 's/^/  A| /' "$D/a.err" >&2
	sed 's/^/  B| /' "$D/b.err" >&2
	bad "act 2: A's tail printed nothing within 30s"
}
first="$(sed -n 1p "$D/a.out")"
printf '%s\n' "$first" | grep -qE "^[0-9]{2}:[0-9]{2}:[0-9]{2} $B8 deploying build 41$" ||
	bad "act 2: A's first line was not B's message, byte for byte: [$first]"
ok "act 2: A printed B's message, stamped $B8 -- the sender, not a claim"
line "$first"
beat 3
say "A did not take B's word for who B is. The identity in that line is the"
say "key that signed the message; there is no display name to spoof."
beat 4

# ==========================================================================
step "ACT 3  A answers -- same running tail, no restart"
# ==========================================================================
say "A's tail already owns the log, so a second publish from A does not"
say "start a second node: it hands the text to the running one over a unix"
say "socket. One writer per node is what keeps the message numbering sane."
beat 4
run "wires publish $TOPIC -m 'ack, watching the canary' # same machine as the tail"
WIRES_HOME="$a" "$WIRES" publish "$TOPIC" -m "ack, watching the canary" \
	2>"$D/a-pub.err" || {
	sed 's/^/     /' "$D/a-pub.err" >&2
	bad "act 3: A's publish failed"
}
wait_lines "$D/a.out" 2 300 || {
	sed 's/^/     /' "$D/a.err" >&2
	bad "act 3: A's own message never reached A's transcript"
}
second="$(sed -n 2p "$D/a.out")"
printf '%s\n' "$second" | grep -qE "^[0-9]{2}:[0-9]{2}:[0-9]{2} $A8 ack, watching the canary$" ||
	bad "act 3: A's second line was wrong, byte for byte: [$second]"
ok "act 3: A's own message is in the same transcript, stamped $A8"
line "$second"
beat 2

lines="$(wc -l <"$D/a.out" | tr -d ' ')"
[ "$lines" -eq 2 ] || bad "act 3: expected exactly 2 lines on A's stdout, got $lines"
ok "act 3: exactly 2 lines on stdout -- no duplicates, no debug noise"
beat 1.5

[ "$(kill -0 "$TAIL_PID" 2>/dev/null && echo live)" = "live" ] ||
	bad "act 3: A's tail died somewhere in the demo"
ok "act 3: A's tail is still pid $TAIL_PID -- one process for the whole run"
beat 1.5

# ==========================================================================
step "SUMMARY"
# ==========================================================================
printf '     topic  : %s\n' "$TOPIC" >&2
printf '     members: %s (A) and %s (B), on one signed list\n' "$A8" "$B8" >&2
printf '     traffic: 2 messages, 0 servers, 0 accounts, 0 open ports\n' >&2
printf '     root   : %s -- signed the list, cannot read the traffic\n' "${ROOT_ID:0:8}..." >&2
say "the human's key decides WHO is in. The lockbox key decides what can be"
say "READ -- and the human never kept a copy of it."
beat 5
