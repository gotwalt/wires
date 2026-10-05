# shellcheck shell=sh
# shellcheck disable=SC2034 # the wrappers read what these functions set
#
# Shared by the example wrappers (examples/services/*/wrapper.sh). Each
# wrapper is a `host.json` service's whole command: it runs once per call,
# in the environment `wires serve` builds from nothing (PATH, the locale,
# the service's `env` from host.json, then the WIRES_* values of the
# verified call), and ends by exec'ing the vendor's CLI, so the CLI is the
# process the host kills if the caller goes away.
#
# What every wrapper reads from host.json's `env`:
#
#   ROLE_MAP        a file of `<wires role> <value>` lines (`#` comments):
#                   the cloud role, service account, namespace or credential
#                   file the caller's role (WIRES_ROLE) maps to. A role with
#                   no line is refused.
#   ALLOW_COMMANDS  optional: the subcommands an agent may run, separated by
#                   spaces; `word` allows a first argument, `word:sub` a first
#                   and second. Each wrapper has its own default.
#   STATE_DIR       pattern A only: where each call's token file lives (0700,
#                   owned by serve's user).
#
# A refusal exits 77 (EX_NOPERM); `wires call` reports a service's 77 as 1
# with a note on stderr, so a caller can tell it from the host's own refusal.

# Print a message to stderr and exit with $1.
die() {
	code="$1"
	shift
	printf 'wires-example %s: %s\n' "${WIRES_SERVICE:-service}" "$*" >&2
	exit "$code"
}

# Refuse to run outside a wires call: the role and the verified email come
# from the host, never from the caller.
need_call() {
	[ -n "${WIRES_ROLE:-}" ] && [ -n "${WIRES_CALLER_EMAIL:-}" ] ||
		die 1 "WIRES_ROLE and WIRES_CALLER_EMAIL are unset: run me as a service of wires serve"
}

# Refuse a subcommand that ALLOW (set by the wrapper) doesn't list. The
# allowlist is about the first words only: what an allowed subcommand may
# do is the credential's scope.
allow_command() {
	[ $# -gt 0 ] || die 2 "usage: wires call $WIRES_SERVICE -- <subcommand> ...; allowed: $ALLOW"
	case " $ALLOW " in
	*" $1 "* | *" $1:${2:-} "*) ;;
	*) die 77 "\`$1${2:+ $2}\` is not allowed on this host; allowed: $ALLOW" ;;
	esac
}

# Set MAPPED to what ROLE_MAP gives the caller's role, or refuse.
map_role() {
	[ -n "${ROLE_MAP:-}" ] && [ -r "$ROLE_MAP" ] || die 1 "ROLE_MAP is unset or unreadable"
	MAPPED="$(awk -v r="$WIRES_ROLE" '$1 == r { $1 = ""; sub(/^ +/, ""); print; exit }' "$ROLE_MAP")"
	[ -n "$MAPPED" ] || die 77 "role $WIRES_ROLE has no mapping for $WIRES_SERVICE on this host"
}

# Set SECRET to the first line of file $1. Never printed.
read_secret() {
	[ -r "$1" ] || die 1 "the credential file for role $WIRES_ROLE is missing or unreadable"
	SECRET=""
	IFS= read -r SECRET <"$1" || true
	[ -n "$SECRET" ] || die 1 "the credential file for role $WIRES_ROLE is empty"
}

# Pattern A: make this call's private directory under STATE_DIR and write
# the caller's ID token into it (TOKEN_FILE), for the cloud's own token
# exchange to read. The wrapper execs the CLI, so nothing is left to delete
# the directory when the call ends: each call first sweeps directories over
# an hour old, whose tokens have expired (a Google ID token lasts an hour).
token_file() {
	[ -n "${STATE_DIR:-}" ] || die 1 "STATE_DIR is unset"
	umask 077
	mkdir -p "$STATE_DIR" || die 1 "cannot create STATE_DIR"
	find "$STATE_DIR" -mindepth 1 -maxdepth 1 -name 'call.*' -mmin +60 -exec rm -rf {} + 2>/dev/null || true
	CALL_DIR="$(mktemp -d "$STATE_DIR/call.XXXXXX")" || die 1 "cannot create a call directory"
	TOKEN_FILE="$CALL_DIR/id-token"
	printf '%s' "$WIRES_ID_TOKEN" >"$TOKEN_FILE"
}

# Set SESSION to the caller's verified email, cut to what a session name
# may hold (AWS: 2-64 characters of [A-Za-z0-9_+=,.@-]).
session_name() {
	SESSION="$(printf '%s' "$WIRES_CALLER_EMAIL" | tr -c 'A-Za-z0-9_+=,.@-' '-' | cut -c1-64)"
}

# Drop the call's own credentials before the vendor's CLI starts: the
# caller's ID token (pattern A hands it over as TOKEN_FILE) and the push
# capability. The CLI needs neither.
scrub() {
	unset WIRES_ID_TOKEN WIRES_PUSH_TOKEN WIRES_PUSH_SOCKET
}
