#!/usr/bin/env bash
# Sign local macOS builds with a stable identity so the firewall and Local
# Network approvals survive rebuilds.
#
#   .scripts/macos-sign.sh BIN...          sign each binary
#   .scripts/macos-sign.sh --run BIN ARGS  sign BIN and its sibling `wires`, then exec
#                                          (the cargo runner, see .cargo/config.toml)
#
# The linker's ad-hoc signature is a hash of the binary, so macOS sees every
# build as a new app and asks again. A certificate signature with a fixed
# identifier gives a designated requirement that holds across builds.
# Identity: $WIRES_SIGN_ID, else the first Developer ID Application, else the
# first Apple Development certificate. With none, binaries stay ad hoc and
# still run. WIRES_SIGN_ID=- skips signing.
set -euo pipefail

[[ "$(uname -s)" == Darwin ]] || {
	[[ "${1:-}" == --run ]] && shift && exec "$@"
	exit 0
}

identity() {
	if [[ -n "${WIRES_SIGN_ID:-}" ]]; then
		printf '%s\n' "$WIRES_SIGN_ID"
		return
	fi
	local ids
	ids="$(security find-identity -v -p codesigning 2>/dev/null || true)"
	local kind
	for kind in 'Developer ID Application' 'Apple Development'; do
		# shellcheck disable=SC2001 # the name is between the first pair of quotes
		grep -F "\"$kind:" <<<"$ids" | head -1 | sed 's/^[^"]*"\([^"]*\)".*/\1/' && return
	done
}

ID="$(identity)"

sign() {
	local bin="$1" name
	[[ -n "$ID" && "$ID" != - && -f "$bin" ]] || return 0
	# Already ours (cargo replaces the file with a fresh ad-hoc one on rebuild).
	codesign -dv "$bin" 2>&1 | grep -qF "Authority=$ID" && return 0
	# Test binaries are `name-<16 hex>`; drop the hash so the identifier is stable.
	name="$(basename "$bin" | sed -E 's/-[0-9a-f]{16}$//')"
	codesign -f -s "$ID" --identifier "dev.wires.$name" "$bin" 2>/dev/null ||
		echo "macos-sign: could not sign $bin with \"$ID\" (running it ad hoc)" >&2
}

if [[ "${1:-}" == --run ]]; then
	shift
	sign "$1"
	# e2e tests spawn target/<profile>/wires directly, not through the runner.
	sign "$(dirname "$1")/../wires"
	sign "$(dirname "$1")/wires"
	exec "$@"
fi

for bin in "$@"; do sign "$bin"; done
