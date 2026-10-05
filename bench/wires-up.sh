#!/usr/bin/env bash
#
# Provision a loopback wires network for the benchmark's `wires` arm, the
# way card 41's first run does:
#
#   admin     -- `wires init` (trusting $BENCH_OIDC_ISSUER), role `bench`
#                ($BENCH_EMAIL: every role needs a verified identity), the
#                workbench named by key as the directory and as the host of
#                one service `gh`, `wires network`, then `wires policy push`
#   workbench -- `wires join <network>`, `wires serve host.json`: the local
#                `gh`, with its own auth; also the directory, which starts
#                empty and takes the admin's first publish
#   agent     -- `wires login <network>` (a browser opens once), with the
#                workbench's hint line in its local `hints` file (loopback
#                address by key), so the agent runs `wires call gh -- …`
#
# Needs BENCH_EMAIL (who may call) and BENCH_OIDC_CLIENT_ID (an OAuth client
# of that IdP; Google "Desktop app"); BENCH_OIDC_CLIENT_SECRET if it has one
# (a public one); BENCH_OIDC_ISSUER defaults to https://accounts.google.com.
#
# State lives under $BENCH_WIRES_DIR (default /tmp/wb16): short on purpose,
# since macOS caps unix-socket paths at 104 bytes. Prints `export` lines for
# WIRES_HOME / PATH / the workbench pid to $D/env.sh (and stdout), for `source`.

set -euo pipefail

D="${BENCH_WIRES_DIR:-/tmp/wb16}"
WIRES="${WIRES_BIN:-$D/bin/wires}"
[ -x "$WIRES" ] || {
	echo "wires-up: no wires binary at $WIRES (cargo build --release -p wires; copy target/release/wires there)" >&2
	exit 1
}

EMAIL="${BENCH_EMAIL:?set BENCH_EMAIL to the address that may call (e.g. you@example.com)}"
CLIENT_ID="${BENCH_OIDC_CLIENT_ID:?set BENCH_OIDC_CLIENT_ID to the IdP OAuth client id}"
ISSUER="${BENCH_OIDC_ISSUER:-https://accounts.google.com}"

admin_ks="$D/admin"
wb="$D/wb"
agent="$D/agent"
if [ -f "$D/wb.pid" ] && kill -0 "$(cat "$D/wb.pid")" 2>/dev/null; then
	kill "$(cat "$D/wb.pid")" || true
fi
rm -rf "$admin_ks" "$wb" "$agent"
mkdir -p "$admin_ks" "$wb" "$agent"
admin() { WIRES_HOME="$admin_ks" "$WIRES" "$@"; }

# The admin starts the network; the workbench prints its id for the admin
# to name it by. No step fails: the edits before the directory runs are
# stored, and `policy push` delivers them.
admin init --issuer "$ISSUER" --client-id "$CLIENT_ID" \
	${BENCH_OIDC_CLIENT_SECRET:+--public-client-secret "$BENCH_OIDC_CLIENT_SECRET"} >/dev/null
WB_ID="$(WIRES_HOME="$wb" "$WIRES" id 2>/dev/null)"
admin role set bench "$EMAIL" >/dev/null 2>&1
admin directory add "workbench=$WB_ID" >/dev/null 2>&1
admin service add gh --allow bench --host workbench \
	--description "The GitHub CLI (gh), run on a remote machine that is already authenticated. Pass gh's arguments after --." >/dev/null 2>&1
NETWORK="$(admin network)"
WIRES_HOME="$wb" "$WIRES" join "$NETWORK" >/dev/null

cat >"$D/host.json" <<JSON
{
  "version": 2,
  "identity": { "issuers": [ { "issuer": "$ISSUER", "audiences": ["$CLIENT_ID"] } ] },
  "services": { "gh": { "command": ["gh"] } }
}
JSON
WIRES_HOME="$wb" "$WIRES" serve --check "$D/host.json" >/dev/null
WIRES_HOME="$wb" nohup "$WIRES" serve "$D/host.json" >"$D/wb.out" 2>"$D/wb.err" </dev/null &
echo $! >"$D/wb.pid"
# Addressing is by key: the workbench's own hint line (its loopback
# address) goes into the others' local hints files, so no discovery or relay
# is involved.
for _ in $(seq 1 50); do
	[ -s "$wb/run/hint" ] && break
	sleep 0.1
done
kill -0 "$(cat "$D/wb.pid")" || {
	cat "$D/wb.err" >&2
	exit 1
}
[ -s "$wb/run/hint" ] || {
	cat "$D/wb.err" >&2
	echo "wires-up: the workbench wrote no hint line" >&2
	exit 1
}
cp "$wb/run/hint" "$admin_ks/hints"
cp "$wb/run/hint" "$agent/hints"
# The workbench's directory started empty: the first publish fills it.
admin policy push >&2

# The agent joins and signs in, in one command: its ID token is bound to its
# node key.
WIRES_HOME="$agent" "$WIRES" login "$NETWORK" >&2

{
	printf 'export WIRES_HOME=%q\n' "$agent"
	# shellcheck disable=SC2016 # $PATH expands in the sourcing shell
	printf 'export PATH=%q:"$PATH"\n' "$(dirname "$WIRES")"
	printf 'export BENCH_WIRES_PID=%q\n' "$(cat "$D/wb.pid")"
} | tee "$D/env.sh"
