# shellcheck shell=bash
# shellcheck disable=SC2034,SC2154 # the demos set and read these globals
#
# Shared by the self-asserting demos (demo-remote-cli.sh, demo-push.sh):
# narration helpers, polling, the two release builds, the stand-in IdP and
# the scripted sign-in. Source it after setting:
#
#   QUIET      non-empty: assertions only (no narration, no pauses)
#   repo       the repo root
#   D          the demo's scratch dir
#   WIRES      the shipped binary; WIRES_DEV the `dev-mock-idp` build

# Narration: silent under --quiet. `ok` and `bad` always print.
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
line() { [ -n "$QUIET" ] || printf '\033[1m     %s\033[0m\n' "$*" >&2; }
show() { [ -n "$QUIET" ] || sed 's/^/     /' "$1" >&2; }
# Print a file's tail on failure.
dump() { [ -z "${1:-}" ] || sed 's/^/  '"$(basename "$1")"'| /' "$1" | tail -20 >&2; }

# Poll a file for a fixed string. $3 is the budget in tenths of a second.
wait_for() {
	local file="$1" s="$2" n="${3:-300}"
	for _ in $(seq 1 "$n"); do
		if [ -e "$file" ] && grep -qF -- "$s" "$file"; then return 0; fi
		sleep 0.1
	done
	return 1
}
alive() { kill -0 "$1" 2>/dev/null; }

# Build both binaries unless WIRES_BIN is set. One crate, two builds:
# `wires-mock-idp` adds only the hidden `dev-mock-idp` subcommand; everything
# the demos prove runs on the shipped `wires`.
build_wires() {
	[ -z "${WIRES_BIN:-}" ] || return 0
	say "cargo build --release (the mock-IdP build first, then the shipped one) ..."
	# Same target dir, so the second build only recompiles the wires crate; the
	# feature build is copied aside before the shipped build replaces it.
	# rm before cp: overwriting a signed binary in place gets it killed on macOS.
	(cd "$repo" && cargo build -q --release -p wires --features dev-mock-idp)
	rm -f "$WIRES_DEV" && cp "$repo/target/release/wires" "$WIRES_DEV"
	(cd "$repo" && cargo build -q --release -p wires)
	# A stable signature keeps the macOS firewall from asking again each build.
	"$repo/.scripts/macos-sign.sh" "$WIRES" "$WIRES_DEV"
}

# Start the stand-in IdP (a hermetic loopback OIDC issuer) signing in $1 by
# default. Sets IDP_PID, ISSUER and CLIENT_ID.
IDP_PID=""
start_mock_idp() {
	"$WIRES_DEV" dev-mock-idp --email "$1" >"$D/idp.out" 2>"$D/idp.err" &
	IDP_PID=$!
	wait_for "$D/idp.out" "client_id " 100 || bad "setup: the mock IdP did not start; see $D/idp.err"
	ISSUER="$(awk '/^issuer /{print $2}' "$D/idp.out")"
	CLIENT_ID="$(awk '/^client_id /{print $2}' "$D/idp.out")"
}

# Sign keystore $1 in as $2 (the stand-in IdP honours login_hint): `wires
# login --no-browser` prints the sign-in URL, and curl plays the browser.
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
		sed 's/^/  login| /' "$D/login.err" >&2
		bad "wires login failed"
	}
	grep -qF "is $2" "$D/login.err" || bad "login did not bind $2"
}
