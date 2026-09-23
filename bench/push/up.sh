#!/usr/bin/env bash
#
# Provision the push-vs-poll benchmark (card 24): one loopback workbench
# running the mock CI (.scripts/fixtures/ci.sh: deploy / status / logs) and
# one agent keystore per arm, so parallel lanes never share a mailbox.
#
#   root      -- `wires init --channel ops`, one invite per machine
#   workbench -- `wires serve host.json`: the three CI tools and push, for the
#                built-in role `member` (any roster member; no IdP -- the
#                benchmark measures waiting, not sign-in)
#   agent-<arm> -- joined with its invite; the bench runs Claude Code with
#                WIRES_HOME=<that keystore> and WIRES_LOCKED=1
#
# State lives under $BENCH_PUSH_DIR (default /tmp/wb24): short, because macOS
# caps unix-socket paths at 104 bytes. Writes $D/env.sh (export lines).
#
#   bench/push/up.sh poll loop-inbox wait

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="${BENCH_PUSH_DIR:-/tmp/wb24}"
WIRES="${WIRES_BIN:-$D/bin/wires}"
[ -x "$WIRES" ] || {
	echo "up: no wires binary at $WIRES (cargo build --release -p wires; copy target/release/wires there)" >&2
	exit 1
}
[ $# -ge 1 ] || {
	echo "usage: $0 <arm>..." >&2
	exit 2
}

if [ -f "$D/wb.pid" ] && kill -0 "$(cat "$D/wb.pid")" 2>/dev/null; then
	kill "$(cat "$D/wb.pid")" || true
	sleep 1
fi
rm -rf "$D/root" "$D/wb" "$D/jobs" "$D"/agent-*
mkdir -p "$D/root" "$D/wb" "$D/jobs"

WIRES_HOME="$D/root" "$WIRES" init --channel ops >/dev/null
WB_ID="$(WIRES_HOME="$D/wb" "$WIRES" id 2>/dev/null)"
tok="$(WIRES_HOME="$D/root" "$WIRES" invite "$WB_ID" --name workbench 2>/dev/null)"
WIRES_HOME="$D/wb" "$WIRES" join "$tok" >/dev/null

cat >"$D/host.json" <<JSON
{
  "version": 1,
  "channel": "ops",
  "tools": {
    "deploy": {
      "description": "Start a CI build in the background: deploy -- build <n>. Returns at once; the result is pushed to your wires inbox when the build finishes.",
      "command": ["$repo/.scripts/fixtures/ci.sh", "deploy"],
      "allow": ["member"]
    },
    "status": {
      "description": "A build's state: status -- build <n> (running / failed).",
      "command": ["$repo/.scripts/fixtures/ci.sh", "status"],
      "allow": ["member"]
    },
    "logs": {
      "description": "A build's log: logs -- build <n> [--tail N] (default: last 50 lines).",
      "command": ["$repo/.scripts/fixtures/ci.sh", "logs"],
      "allow": ["member"]
    }
  },
  "push": { "allow": ["member"] }
}
JSON
"$WIRES" serve --check "$D/host.json" >/dev/null
(cd "$D" && WIRES_HOME="$D/wb" CI_JOBS="$D/jobs" CI_WIRES="$WIRES" \
	exec nohup "$WIRES" serve "$D/host.json" >"$D/wb.out" 2>"$D/wb.err" </dev/null) &
echo $! >"$D/wb.pid"
for _ in $(seq 1 300); do
	grep -q '^share to bootstrap: ' "$D/wb.err" 2>/dev/null && break
	sleep 0.1
done
TICKET="$(grep -m1 '^share to bootstrap: ' "$D/wb.err" | sed 's/^share to bootstrap: //')"
[ -n "$TICKET" ] || {
	cat "$D/wb.err" >&2
	echo "up: the workbench never printed its ticket" >&2
	exit 1
}

for arm in "$@"; do
	h="$D/agent-$arm"
	mkdir -p "$h"
	id="$(WIRES_HOME="$h" "$WIRES" id 2>/dev/null)"
	tok="$(WIRES_HOME="$D/root" "$WIRES" invite "$id" --name "agent-$arm" --peer "$TICKET" 2>/dev/null)"
	WIRES_HOME="$h" "$WIRES" join "$tok" >/dev/null
	# Warm the directory: the workbench's announcement names the CI tools.
	for _ in $(seq 1 50); do
		WIRES_HOME="$h" "$WIRES" tools 2>/dev/null | grep -q '^deploy ' && break
		sleep 0.2
	done
	WIRES_HOME="$h" "$WIRES" tools 2>/dev/null | grep -q '^deploy ' || {
		echo "up: agent-$arm does not see the CI tools" >&2
		exit 1
	}
done

{
	printf 'export BENCH_PUSH_DIR=%q\n' "$D"
	printf 'export BENCH_PUSH_WB_PID=%q\n' "$(cat "$D/wb.pid")"
	printf 'export BENCH_PUSH_BIN_DIR=%q\n' "$(dirname "$WIRES")"
} | tee "$D/env.sh"
