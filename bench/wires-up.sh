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

root="$D/root"
wb="$D/wb"
agent="$D/agent"
if [ -f "$D/wb.pid" ] && kill -0 "$(cat "$D/wb.pid")" 2>/dev/null; then
	kill "$(cat "$D/wb.pid")" || true
fi
rm -rf "$root" "$wb" "$agent" "$D/v1" "$D"/*.member
mkdir -p "$root" "$wb" "$agent"

WIRES_HOME="$root" "$WIRES" advanced keygen --save-root >/dev/null
for h in "$wb" "$agent"; do WIRES_HOME="$h" "$WIRES" advanced keygen --save-node >/dev/null; done
node_id() { "$WIRES" advanced keygen --node-seed "$(tr -d '\n' <"$1/node.seed")" | awk '/^node_id/{print $2}'; }
WB_ID="$(node_id "$wb")"
AG_ID="$(node_id "$agent")"

for id in "$WB_ID" "$AG_ID"; do
	WIRES_HOME="$root" "$WIRES" advanced roster add --member "$id" >/dev/null
	WIRES_HOME="$root" "$WIRES" advanced member --subject "$id" --ttl 86400 >"$D/$id.member"
done
HEAD1="$(WIRES_HOME="$root" "$WIRES" advanced roster commit --ttl 86400 --out "$D/v1" | awk '/^head /{print $2}')"
for pair in "$wb:$WB_ID" "$agent:$AG_ID"; do
	h="${pair%%:*}"
	id="${pair#*:}"
	WIRES_HOME="$h" "$WIRES" advanced import \
		--membership-file "$D/$id.member" \
		--inclusion-proof-file "$D/v1/$id.proof" \
		--roster-head "$HEAD1" \
		--fabric-key-file "$D/v1/$id.key" >/dev/null
done

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
