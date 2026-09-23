#!/usr/bin/env bash
#
# Provision a loopback wires pair for the benchmark's `wires` arm:
#
#   responder -- `wires serve --expose 'gh=gh'` (the local `gh`, with its own
#                auth; nothing else exposed)
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
	echo "wires-up: no wires binary at $WIRES (bazel build //wires; copy bazel-bin/wires/wires there)" >&2
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

WIRES_HOME="$root" "$WIRES" keygen --save-root >/dev/null
for h in "$wb" "$agent"; do WIRES_HOME="$h" "$WIRES" keygen --save-node >/dev/null; done
ROOT_ID="$(WIRES_HOME="$root" "$WIRES" keygen --root-seed "$(tr -d '\n' <"$root/root.seed")" | awk '/^root_id/{print $2}')"
node_id() { "$WIRES" keygen --node-seed "$(tr -d '\n' <"$1/node.seed")" | awk '/^node_id/{print $2}'; }
WB_ID="$(node_id "$wb")"
AG_ID="$(node_id "$agent")"

for id in "$WB_ID" "$AG_ID"; do
	WIRES_HOME="$root" "$WIRES" roster add --member "$id" >/dev/null
	WIRES_HOME="$root" "$WIRES" member --subject "$id" --ttl 86400 >"$D/$id.member"
done
HEAD1="$(WIRES_HOME="$root" "$WIRES" roster commit --ttl 86400 --out "$D/v1" | awk '/^head /{print $2}')"
for pair in "$wb:$WB_ID" "$agent:$AG_ID"; do
	h="${pair%%:*}"
	id="${pair#*:}"
	WIRES_HOME="$h" "$WIRES" import \
		--membership-file "$D/$id.member" \
		--inclusion-proof-file "$D/v1/$id.proof" \
		--roster-head "$HEAD1" \
		--fabric-key-file "$D/v1/$id.key" >/dev/null
done

WIRES_HOME="$wb" nohup "$WIRES" serve --trust-root "$ROOT_ID" --allow-any-member \
	--expose 'gh=gh' >"$D/wb.out" 2>"$D/wb.err" </dev/null &
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
