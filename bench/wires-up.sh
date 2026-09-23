#!/usr/bin/env bash
#
# Provision a loopback wires pair for the benchmark's `wires` arm:
#
#   responder -- `wires serve host.json`, host.json exposing one tool `gh`
#                (the local `gh`, with its own auth) to any roster member;
#                no channel, so no audit and no IdP (card 13's member-only host)
#   agent     -- `tools.json` entry `gh` pointing at the responder by node id
#                + loopback address, so the agent runs `wires call gh -- …`
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

# The responder is also the admin (so every commit lands in its own keystore
# with no channel round-trip); the agent makes its key and joins with the one
# token `wires invite` prints for it.
WIRES_HOME="$wb" "$WIRES" init --channel bench >/dev/null 2>&1
AG_ID="$(WIRES_HOME="$agent" "$WIRES" id 2>/dev/null)"
token="$(WIRES_HOME="$wb" "$WIRES" invite "$AG_ID" --name agent 2>/dev/null)"
WIRES_HOME="$agent" "$WIRES" join "$token" >/dev/null
WB_ID="$(WIRES_HOME="$wb" "$WIRES" id 2>/dev/null)"

cat >"$D/host.json" <<'JSON'
{
  "version": 1,
  "tools": {
    "gh": {
      "description": "The GitHub CLI (gh), run on this host with its own auth",
      "command": ["gh"],
      "allow": ["member"]
    }
  }
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
# serve logs its bound sockets (`sockets=[0.0.0.0:PORT, [::]:PORT]`); the agent
# dials the IPv4 one on loopback, so no discovery or relay is involved.
PORT="$(sed 's/\x1b\[[0-9;]*m//g' "$D/wb.err" | grep -oE 'sockets=\[0\.0\.0\.0:[0-9]+' | head -1 | sed 's/.*://')"
[ -n "$PORT" ] || {
	cat "$D/wb.err" >&2
	echo "wires-up: could not read the responder's port" >&2
	exit 1
}

WIRES_HOME="$agent" "$WIRES" tools add gh --node "$WB_ID" --addr "127.0.0.1:$PORT" \
	--description "The GitHub CLI (gh), run on a remote machine that is already authenticated. Pass gh's arguments after --." >/dev/null

{
	printf 'export WIRES_HOME=%q\n' "$agent"
	printf 'export PATH=%q:"$PATH"\n' "$(dirname "$WIRES")"
	printf 'export BENCH_WIRES_PID=%q\n' "$(cat "$D/wb.pid")"
} | tee "$D/env.sh"
