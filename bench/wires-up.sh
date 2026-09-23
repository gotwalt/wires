#!/usr/bin/env bash
#
# Provision a loopback wires pair for the benchmark's `wires` arm:
#
#   responder -- `wires serve host.json`, implementing one service `gh` (the
#                local `gh`, with its own auth), registered for role `member`
#                (any member; no IdP)
#   agent     -- the responder's hint line in its local `hints` file (loopback
#                address by key), so the agent runs `wires call gh -- …`
#
# State lives under $BENCH_WIRES_DIR (default /tmp/wb16): short on purpose,
# since macOS caps unix-socket paths at 104 bytes. Prints `export` lines for
# WIRES_HOME / PATH / responder pid to $D/env.sh (and stdout), for `source`.

set -euo pipefail

D="${BENCH_WIRES_DIR:-/tmp/wb16}"
WIRES="${WIRES_BIN:-$D/bin/wires}"
[ -x "$WIRES" ] || {
	echo "wires-up: no wires binary at $WIRES (cargo build --release -p wires; copy target/release/wires there)" >&2
	exit 1
}

wb="$D/wb"
agent="$D/agent"
if [ -f "$D/wb.pid" ] && kill -0 "$(cat "$D/wb.pid")" 2>/dev/null; then
	kill "$(cat "$D/wb.pid")" || true
fi
rm -rf "$wb" "$agent"
mkdir -p "$wb" "$agent"

# The responder is also the admin (so every state lands in its own keystore
# with no round-trip); the agent makes its key and joins with the one token
# `wires invite` prints for it.
WIRES_HOME="$wb" "$WIRES" init >/dev/null 2>&1
WB_ID="$(WIRES_HOME="$wb" "$WIRES" id 2>/dev/null)"
WIRES_HOME="$wb" "$WIRES" service add gh --allow member --host "$WB_ID" \
	--description "The GitHub CLI (gh), run on a remote machine that is already authenticated. Pass gh's arguments after --." >/dev/null 2>&1
AG_ID="$(WIRES_HOME="$agent" "$WIRES" id 2>/dev/null)"
token="$(WIRES_HOME="$wb" "$WIRES" invite "$AG_ID" --name agent 2>/dev/null)"
WIRES_HOME="$agent" "$WIRES" join "$token" >/dev/null

cat >"$D/host.json" <<'JSON'
{
  "version": 2,
  "services": { "gh": { "command": ["gh"] } }
}
JSON
WIRES_HOME="$wb" "$WIRES" serve --check "$D/host.json" >/dev/null
WIRES_HOME="$wb" nohup "$WIRES" serve "$D/host.json" >"$D/wb.out" 2>"$D/wb.err" </dev/null &
echo $! >"$D/wb.pid"
sleep 2
kill -0 "$(cat "$D/wb.pid")" || {
	cat "$D/wb.err" >&2
	exit 1
}
# Addressing is by key: the responder's own hint line (its loopback
# address) goes into the agent's local hints file, so no discovery or relay is
# involved.
for _ in $(seq 1 50); do
	[ -s "$wb/run/hint" ] && break
	sleep 0.1
done
cp "$wb/run/hint" "$agent/hints" || {
	cat "$D/wb.err" >&2
	echo "wires-up: the responder wrote no hint line" >&2
	exit 1
}

{
	printf 'export WIRES_HOME=%q\n' "$agent"
	# shellcheck disable=SC2016 # $PATH expands in the sourcing shell
	printf 'export PATH=%q:"$PATH"\n' "$(dirname "$WIRES")"
	printf 'export BENCH_WIRES_PID=%q\n' "$(cat "$D/wb.pid")"
} | tee "$D/env.sh"
