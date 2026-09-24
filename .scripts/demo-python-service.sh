#!/usr/bin/env bash
#
# Acceptance for card 33 phase 2: a wires-native service written in PYTHON
# (bindings/python/examples/kv.py, through the wires-ffi bindings) is served
# on a real, loopback fabric and called with the shipped `wires` binary.
# To a caller it is a CLI like any other.
#
# Four keystores on one machine:
#
#   host   -- `python3 kv.py`: the embedded host, implementing kv in Python.
#   agent  -- alice@example.com (role analyst): calls kv.
#   other  -- bob@other.example: signed in, but in no role that may call kv.
#   root   -- the admin: init, role set, invite, service add.
#
# The IdP is the hermetic loopback issuer (`wires dev-mock-idp`, only in the
# `--features dev-mock-idp` build). Addressing is by key; the host writes its
# run/hint as `wires serve` does, and the script copies it into the others'
# hints files.
#
# Asserted: alice's `set` (value on stdin), `get` and `keys` round-trip
# through the Python handler, state kept between calls; the handler's exit
# code and stderr are the caller's; bob is refused (77) by name, before the
# handler runs; the handler's push_to_caller reaches alice's `wires inbox`,
# from the host's verified key; and the host's signed log, read by alice's
# own `wires watch`, shows her calls with her verified email.
#
# Python comes from uv (a uv-managed CPython, $WIRES_PYTHON, default 3.13;
# uv downloads it on first use). The host binds loopback only (`--loopback`),
# so the macOS firewall never asks to approve the interpreter.
#
#   ./.scripts/demo-python-service.sh          (builds on first use)
#   ./.scripts/demo-python-service.sh --keep   leave the state dir behind

set -euo pipefail

KEEP=""
[ "${1:-}" = "--keep" ] && KEEP=1

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
WIRES="${WIRES_BIN:-$repo/target/release/wires}"
WIRES_DEV="${WIRES_DEV_BIN:-$repo/target/release/wires-mock-idp}"
EXIT_DENIED=77
EMAIL="alice@example.com"
OTHER="bob@other.example"

D="$(mktemp -d)"
IDP_PID=""
HOST_PID=""
p=""
trap 'for p in $HOST_PID $IDP_PID; do kill "$p" 2>/dev/null || true; done; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

ok() { printf '\033[32m[ok]\033[0m   %s\n' "$*" >&2; }
bad() {
	printf '\033[31m[FAIL]\033[0m %s\n' "$*" >&2
	exit 1
}
dump() { [ -z "${1:-}" ] || sed 's/^/  '"$(basename "$1")"'| /' "$1" | tail -20 >&2; }
wait_for() {
	local file="$1" s="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && grep -qF -- "$s" "$file"; then return 0; fi
		sleep 0.1
	done
	return 1
}
login_as() {
	WIRES_HOME="$1" "$WIRES" login \
		--issuer "$ISSUER" --client-id "$CLIENT_ID" --client-secret not-so-secret \
		--no-browser >"$D/login.out" 2>"$D/login.err" &
	local pid=$!
	wait_for "$D/login.err" "sign in at" 100 || bad "login printed no sign-in URL"
	local url
	url="$(grep -m1 -E '^  https?://' "$D/login.err" | sed 's/^  //')"
	curl -fsSL -o /dev/null "$url&login_hint=$2" || bad "the sign-in round trip failed"
	wait "$pid" || {
		dump "$D/login.err"
		bad "wires login failed"
	}
}

if [ -z "${WIRES_BIN:-}" ]; then
	cargo build -q --release -p wires --features dev-mock-idp
	rm -f "$WIRES_DEV" && cp target/release/wires "$WIRES_DEV"
	cargo build -q --release -p wires
	.scripts/macos-sign.sh "$WIRES" "$WIRES_DEV"
fi
PY="$(.scripts/build-python.sh "$D/python")"
command -v curl >/dev/null || bad "curl is not on PATH"
command -v uv >/dev/null || bad "uv is not on PATH (https://docs.astral.sh/uv/)"
PYTHON_VERSION="${WIRES_PYTHON:-3.13}"

# --------------------------------------------------------------------------
# The fabric: the admin, the Python host, two callers, one IdP.
# --------------------------------------------------------------------------
root="$D/root"
host="$D/host"
agent="$D/agent"
other="$D/other"
mkdir -p "$root" "$host" "$agent" "$other"
WIRES_HOME="$root" "$WIRES" init >/dev/null
HOST_ID="$(WIRES_HOME="$host" "$WIRES" id 2>/dev/null)"
AG_ID="$(WIRES_HOME="$agent" "$WIRES" id 2>/dev/null)"
OT_ID="$(WIRES_HOME="$other" "$WIRES" id 2>/dev/null)"
admin() { WIRES_HOME="$root" "$WIRES" "$@"; }

"$WIRES_DEV" dev-mock-idp --email "$EMAIL" >"$D/idp.out" 2>"$D/idp.err" &
IDP_PID=$!
wait_for "$D/idp.out" "client_id " 100 || bad "the mock IdP did not start"
ISSUER="$(awk '/^issuer /{print $2}' "$D/idp.out")"
CLIENT_ID="$(awk '/^client_id /{print $2}' "$D/idp.out")"

admin role set analyst --issuer "$ISSUER" '*@example.com' >/dev/null 2>&1
admin invite "$HOST_ID" --name pyhost >/dev/null 2>&1
# The host isn't up yet: the edit is stored, and a fresh token carries it.
admin service add kv --description "A key-value store, one namespace per person (Python)." \
	--allow analyst --host pyhost >"$D/svc.out" 2>"$D/svc.err" ||
	grep -qF "reached none of its 1 host(s)" "$D/svc.err" || {
	dump "$D/svc.err"
	bad "wires service add failed"
}
WIRES_HOME="$host" "$WIRES" join "$(admin invite "$HOST_ID" --name pyhost 2>/dev/null)" >/dev/null

# --------------------------------------------------------------------------
# The Python host.
# --------------------------------------------------------------------------
PYTHONPATH="$PY" uv run -q --no-project --managed-python --python "$PYTHON_VERSION" -- \
	python "$repo/bindings/python/examples/kv.py" \
	"$host" "$ISSUER" "$CLIENT_ID" --push-to analyst --loopback >"$D/host.out" 2>"$D/host.err" &
HOST_PID=$!
wait_for "$host/run/hint" " " 300 || {
	dump "$D/host.err"
	bad "the Python host never came up"
}
grep -qF "kv: serving as $HOST_ID" "$D/host.err" || bad "the Python host is not serving as its node key"
for h in "$root" "$agent" "$other"; do cp "$host/run/hint" "$h/hints"; done
ok "the Python host serves kv as ${HOST_ID:0:8}... (pid $HOST_PID)"

# The callers join; each invite is a new state, pushed to the Python host.
AG_TOKEN="$(admin invite "$AG_ID" --name agent 2>"$D/invite.err")"
OT_TOKEN="$(admin invite "$OT_ID" --name other 2>>"$D/invite.err")"
grep -qF "pushed to 1 of 1 host(s)" "$D/invite.err" || {
	dump "$D/invite.err"
	bad "the invites' state never reached the Python host"
}
WIRES_HOME="$agent" "$WIRES" join "$AG_TOKEN" >/dev/null
WIRES_HOME="$other" "$WIRES" join "$OT_TOKEN" >/dev/null
login_as "$agent" "$EMAIL"
login_as "$other" "$OTHER"
ok "the Python host took the admin's pushed state; alice and bob signed in"

# --------------------------------------------------------------------------
# Calls.
# --------------------------------------------------------------------------
call() { WIRES_HOME="$1" "$WIRES" call kv -- "${@:2}"; }

printf 'hello' | call "$agent" set greeting >"$D/c1.out" 2>"$D/c1.err" || {
	dump "$D/c1.err"
	bad "alice's set failed"
}
[ "$(call "$agent" get greeting 2>"$D/c2.err")" = "hello" ] || {
	dump "$D/c2.err"
	bad "alice's get did not return what she set"
}
[ "$(call "$agent" keys 2>/dev/null)" = "greeting" ] || bad "alice's keys is not [greeting]"
ok "set (stdin) / get / keys round-trip through the Python handler, state kept"

set +e
call "$agent" get nope >"$D/c3.out" 2>"$D/c3.err"
rc=$?
set -e
[ "$rc" -eq 1 ] || bad "a missing key exited $rc, expected the handler's 1"
grep -qF "kv: no such key" "$D/c3.err" || bad "the handler's stderr did not reach the caller"
ok "the handler's exit code (1) and stderr are the caller's"

set +e
call "$other" keys >"$D/c4.out" 2>"$D/c4.err"
rc=$?
set -e
[ "$rc" -eq "$EXIT_DENIED" ] || {
	dump "$D/c4.err"
	bad "bob's call exited $rc, expected $EXIT_DENIED"
}
grep -qF "$OTHER is in no role allowed to call kv (analyst)" "$D/c4.err" || {
	dump "$D/c4.err"
	bad "bob was refused, but not by name"
}
[ ! -s "$D/c4.out" ] || bad "bob's refused call wrote to stdout"
ok "bob is refused ($EXIT_DENIED) by name, before the handler runs"

# --------------------------------------------------------------------------
# The handler's push, and the host's own record.
# --------------------------------------------------------------------------
WIRES_HOME="$agent" "$WIRES" inbox >"$D/i1.out" 2>"$D/i1.err" || {
	dump "$D/i1.err"
	bad "wires inbox failed"
}
grep -qF "from host ${HOST_ID:0:8} (verified)  kv: greeting set" "$D/i1.out" || {
	dump "$D/i1.out"
	dump "$D/i1.err"
	bad "the handler's push_to_caller did not reach alice's inbox"
}
ok "push_to_caller from Python reached alice's wires inbox, from the host's verified key"

WIRES_HOME="$agent" "$WIRES" watch --mine --once kv >"$D/w.out" 2>"$D/w.err" || {
	dump "$D/w.err"
	bad "wires watch failed"
}
grep -qE "kv +▶ [0-9a-f]+ $EMAIL .*\[analyst\] kv set greeting" "$D/w.out" || {
	dump "$D/w.out"
	bad "alice's watch does not show her set, with her verified email and role"
}
grep -qE "kv +■ [0-9a-f]+ exit 0 .*stdin \"hello\"" "$D/w.out" || {
	dump "$D/w.out"
	bad "alice's watch does not show the set's exit and its stdin"
}
ok "the host's signed log shows alice's calls to the Python service, with her verified email"

kill "$HOST_PID" 2>/dev/null || true
printf '\n\033[1mpython-service demo: all assertions passed\033[0m\n' >&2
