#!/usr/bin/env bash
# Cargo runner wrapper for macOS that ad-hoc codesigns test binaries with a
# stable identifier before exec'ing them. The macOS Application Firewall keys
# allow/deny decisions on code signature, so a stable identifier means you
# approve the firewall prompt once and never see it again for this workspace.
set -euo pipefail

bin="$1"
shift

if [[ "$(uname -s)" == "Darwin" ]]; then
  codesign --force --sign - --identifier wires-tests "$bin" >/dev/null 2>&1 || true
fi

exec "$bin" "$@"
