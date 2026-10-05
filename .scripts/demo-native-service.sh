#!/usr/bin/env bash
#
# A wires-native service written in Python (bindings/python/examples/kv.py,
# through wires-ffi / UniFFI) or TypeScript (bindings/node/examples/kv.mts,
# through wires-node / napi-rs), served on a real loopback network and
# called with the shipped `wires` binary. To a caller it is a CLI like any
# other. Self-asserting; exits non-zero on the first failed check.
#
# Four keystores on one machine:
#
#   host   -- `kv.py` or `kv.mts`: the embedded host, implementing kv.
#   agent  -- alice@example.com (role analyst): calls kv.
#   other  -- bob@other.example: signs in at the IdP, but no role matches him,
#             so he is not in the network.
#   root   -- the admin: init, role set, directory add, service add, network,
#             and the first policy push (card 41's first run).
#
# The IdP is the hermetic loopback issuer (`wires dev-mock-idp`, only in the
# `--features dev-mock-idp` build). Addressing is by key; the host writes its
# run/hint as `wires serve` does, and the script copies it into the others'
# hints files.
#
# Asserted: (TypeScript) the example typechecks against the index.d.ts
# generated from the Rust; alice's set (value on stdin), get and keys
# round-trip through the handler, state kept between calls; the handler's
# exit code and stderr are the caller's, and an exception it raises is exit
# 1 with its message; the handler's call.id_token() is the ID token alice
# presented; bob, whose view holds no kv, dials nothing (exit 1);
# push_to_caller reaches alice's `wires inbox` from the host's verified key;
# and SIGTERM makes the example call `stop()`, so
# `serve()` returns and the process exits 0 on its own.
#
# Python comes from uv (a uv-managed CPython, $WIRES_PYTHON, default 3.13;
# uv downloads it on first use); TypeScript runs on Node >= 22.18, which
# strips types itself. The host binds loopback only (`--loopback`), so the
# macOS firewall never asks to approve the interpreter.
#
#   ./.scripts/demo-native-service.sh --lang python   (builds on first use)
#   ./.scripts/demo-native-service.sh --lang node
#   ... --keep                                        leave the state dir behind

set -euo pipefail

KEEP=""
LANG_=""
while [ $# -gt 0 ]; do
	case "$1" in
	--keep)
		KEEP=1
		shift
		;;
	--lang)
		LANG_="${2:-}"
		shift 2
		;;
	*)
		printf 'usage: %s --lang python|node [--keep]\n' "$0" >&2
		exit 2
		;;
	esac
done
case "$LANG_" in
python | node) ;;
*)
	printf 'usage: %s --lang python|node [--keep]\n' "$0" >&2
	exit 2
	;;
esac

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
WIRES="${WIRES_BIN:-$repo/target/release/wires}"
WIRES_DEV="${WIRES_DEV_BIN:-$repo/target/release/wires-mock-idp}"
EMAIL="alice@example.com"
OTHER="bob@other.example"

D="$(mktemp -d)"
IDP_PID=""
HOST_PID=""
cleanup() {
	local pid
	for pid in $HOST_PID $IDP_PID; do kill "$pid" 2>/dev/null || true; done
	[ -n "$KEEP" ] || rm -rf "$D"
}
trap cleanup EXIT INT TERM

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
# Sign keystore $1 in as $2, joining the network string $3 first.
login_as() {
	WIRES_HOME="$1" "$WIRES" login --no-browser "$3" >"$D/login.out" 2>"$D/login.err" &
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
command -v curl >/dev/null || bad "curl is not on PATH"
if [ "$LANG_" = python ]; then
	command -v uv >/dev/null || bad "uv is not on PATH (https://docs.astral.sh/uv/)"
	PYTHON_VERSION="${WIRES_PYTHON:-3.13}"
	PY="$(.scripts/build-python.sh "$D/python")"
	LANG_NAME=Python
else
	command -v node >/dev/null || bad "node is not on PATH"
	# The package, installed as `wires` beside a copy of the example.
	app="$D/app"
	mkdir -p "$app/node_modules"
	.scripts/build-node.sh "$app/node_modules/wires" >/dev/null
	cp "$repo/bindings/node/examples/kv.mts" "$repo/bindings/node/examples/tsconfig.json" "$app/"
	(cd "$app" && "$repo/bindings/node/node_modules/.bin/tsc" -p tsconfig.json \
		--typeRoots "$repo/bindings/node/node_modules/@types") >"$D/tsc.out" 2>&1 || {
		dump "$D/tsc.out"
		bad "kv.mts does not typecheck against the generated index.d.ts"
	}
	LANG_NAME=TypeScript
	ok "kv.mts typechecks against the index.d.ts generated from bindings/node/lib.rs"
fi

# --------------------------------------------------------------------------
# The network: the admin, the $LANG_NAME host, two callers, one IdP.
# --------------------------------------------------------------------------
root="$D/root"
host="$D/host"
agent="$D/agent"
other="$D/other"
mkdir -p "$root" "$host" "$agent" "$other"
"$WIRES_DEV" dev-mock-idp --email "$EMAIL" >"$D/idp.out" 2>"$D/idp.err" &
IDP_PID=$!
wait_for "$D/idp.out" "client_id " 100 || bad "the mock IdP did not start"
ISSUER="$(awk '/^issuer /{print $2}' "$D/idp.out")"
CLIENT_ID="$(awk '/^client_id /{print $2}' "$D/idp.out")"

# The network's first policy trusts the IdP.
WIRES_HOME="$root" "$WIRES" init --issuer "$ISSUER" --client-id "$CLIENT_ID" --public-client-secret not-so-secret >/dev/null
HOST_ID="$(WIRES_HOME="$host" "$WIRES" id 2>/dev/null)"
admin() { WIRES_HOME="$root" "$WIRES" "$@"; }

admin role set analyst '*@example.com' >/dev/null 2>&1
# The host is also the network's directory (card 37: callers ask one for
# their view). It isn't up yet, so the edits reach no directory: it starts
# empty and takes the admin's first publish.
admin directory add "nativehost=$HOST_ID" >/dev/null 2>"$D/dir.err" || {
	dump "$D/dir.err"
	bad "wires directory add failed"
}
admin service add kv --description "A key-value store, one namespace per person ($LANG_NAME)." \
	--allow analyst --host nativehost >"$D/svc.out" 2>"$D/svc.err" || {
	dump "$D/svc.err"
	bad "wires service add failed"
}
NETWORK="$(admin network)"
WIRES_HOME="$host" "$WIRES" join "$NETWORK" >/dev/null

# --------------------------------------------------------------------------
# The $LANG_NAME host.
# --------------------------------------------------------------------------
if [ "$LANG_" = python ]; then
	PYTHONPATH="$PY" uv run -q --no-project --managed-python --python "$PYTHON_VERSION" -- \
		python "$repo/bindings/python/examples/kv.py" \
		"$host" "$ISSUER" "$CLIENT_ID" --push-to analyst --loopback >"$D/host.out" 2>"$D/host.err" &
else
	(cd "$app" && exec node kv.mts "$host" "$ISSUER" "$CLIENT_ID" --push-to analyst --loopback) \
		>"$D/host.out" 2>"$D/host.err" &
fi
HOST_PID=$!
wait_for "$host/run/hint" " " 300 || {
	dump "$D/host.err"
	bad "the $LANG_NAME host never came up"
}
grep -qF "kv: serving as $HOST_ID" "$D/host.err" || bad "the $LANG_NAME host is not serving as its node key"
for h in "$root" "$agent" "$other"; do cp "$host/run/hint" "$h/hints"; done
# Its directory started empty: the admin's first publish gives it (and the
# host) the policy that assigns it kv.
admin policy push >/dev/null 2>"$D/push0.err" || {
	dump "$D/push0.err"
	bad "wires policy push failed"
}
grep -qF "published to 1 of 1" "$D/push0.err" || {
	dump "$D/push0.err"
	bad "the first publish did not reach the host's directory"
}
ok "the $LANG_NAME host serves kv as ${HOST_ID:0:8}... (pid $HOST_PID)"

# Each caller's whole onboarding: `wires login <network>`.
login_as "$agent" "$EMAIL" "$NETWORK"
login_as "$other" "$OTHER" "$NETWORK"
ok "the $LANG_NAME host serves the admin's signed policy; alice and bob signed in"

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
ok "set (stdin) / get / keys round-trip through the $LANG_NAME handler, state kept"

set +e
call "$agent" get nope >"$D/c3.out" 2>"$D/c3.err"
rc=$?
set -e
[ "$rc" -eq 1 ] || bad "a missing key exited $rc, expected the handler's 1"
grep -qF "kv: no such key" "$D/c3.err" || bad "the handler's stderr did not reach the caller"
ok "the handler's exit code (1) and stderr are the caller's"

# The handler holds alice's ID token (`call.id_token()`), the one her
# `wires call` presented; `whoami` echoes it without its signature.
call "$agent" whoami >"$D/c6.out" 2>"$D/c6.err" || {
	dump "$D/c6.err"
	bad "alice's whoami failed"
}
TOKEN="$(cat "$agent/idp-token.jwt")"
[ "$(sed -n 1p "$D/c6.out")" = "$EMAIL" ] || bad "whoami did not name alice"
[ "$(sed -n 2p "$D/c6.out")" = "${TOKEN%.*}" ] || {
	dump "$D/c6.out"
	bad "the handler's call.id_token() is not the token alice presented"
}
ok "the $LANG_NAME handler holds alice's ID token (call.id_token()) and her verified email"

set +e
call "$agent" throw >"$D/c5.out" 2>"$D/c5.err"
rc=$?
set -e
[ "$rc" -eq 1 ] || bad "a raising handler exited $rc, expected 1"
grep -qF "kv: thrown on request" "$D/c5.err" || {
	dump "$D/c5.err"
	bad "the exception's message did not reach the caller's stderr"
}
ok "an exception in the $LANG_NAME handler is exit 1 with its message on stderr"

set +e
call "$other" keys >"$D/c4.out" 2>"$D/c4.err"
rc=$?
set -e
# Card 47: no role matches bob, so no directory admits him and he holds no
# view: nothing is dialed, and the handler never runs.
[ "$rc" -eq 1 ] || {
	dump "$D/c4.err"
	bad "bob's call exited $rc, expected 1 (not in the network)"
}
grep -qF "no role in this network matches bob@other.example" "$D/c4.err" || {
	dump "$D/c4.err"
	bad "bob's call stopped, but not because the network doesn't admit him"
}
[ ! -s "$D/c4.out" ] || bad "bob's call wrote to stdout"
ok "bob is not in the network: nothing dialed, the handler never runs"

# --------------------------------------------------------------------------
# The handler's push.
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
ok "push_to_caller from $LANG_NAME reached alice's wires inbox, from the host's verified key"

# --------------------------------------------------------------------------
# Stop: SIGTERM makes the example call host.stop(); serve() returns and the
# process exits 0 by itself (nothing of the host keeps it alive).
# --------------------------------------------------------------------------
kill -TERM "$HOST_PID"
for _ in $(seq 1 100); do
	kill -0 "$HOST_PID" 2>/dev/null || break
	sleep 0.1
done
if kill -0 "$HOST_PID" 2>/dev/null; then
	dump "$D/host.err"
	bad "the $LANG_NAME host was still running 10s after stop()"
fi
set +e
wait "$HOST_PID"
rc=$?
set -e
HOST_PID=""
[ "$rc" -eq 0 ] || {
	dump "$D/host.err"
	bad "the $LANG_NAME host exited $rc after stop(), expected 0"
}
grep -qF "kv: stopped" "$D/host.err" || bad "the $LANG_NAME host did not return from serve()"
ok "stop() ended serve(), and the $LANG_NAME process exited 0 on its own"

printf '\n\033[1mnative-service demo (%s): all assertions passed\033[0m\n' "$LANG_NAME" >&2
