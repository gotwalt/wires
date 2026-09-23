#!/usr/bin/env bash
#
# Push vs poll benchmark (board card 24). Reproduce with:
#
#   bazel build //wires && ./bench/push/run.sh              # full: 3 arms x {60 s, 300 s} x 5 reps
#   ./bench/push/run.sh --reps 1 --secs 20                  # smoke test
#   ./bench/push/run.sh --arms poll,wait --secs 60          # a slice
#
# Needs: `claude` (logged in), perl (the mock CI's clock), python3.
# Raw stream-json transcripts go to $BENCH_RAW (default: a temp dir), NOT the
# repo. Extra args go to bench.py (--reps, --arms, --secs, --budget).

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="${BENCH_PUSH_DIR:-/tmp/wb24}" # short: macOS 104-byte unix-socket paths
mkdir -p "$D/bin"
if [ -z "${WIRES_BIN:-}" ]; then
	[ -x "$repo/bazel-bin/wires/wires" ] || (cd "$repo" && bazel build //wires)
	# rm first: overwriting a signed binary in place gets it SIGKILLed on macOS
	rm -f "$D/bin/wires"
	cp "$repo/bazel-bin/wires/wires" "$D/bin/wires"
	chmod u+w "$D/bin/wires"
fi

BENCH_PUSH_DIR="$D" "$repo/bench/push/up.sh" poll poll-loop loop-inbox wait >/dev/null
# shellcheck source=/dev/null
. "$D/env.sh"
trap 'kill "$BENCH_PUSH_WB_PID" 2>/dev/null || true' EXIT

date="$(date -u +%Y-%m-%d)"
out="${BENCH_OUT:-$repo/bench/push/results/$date.jsonl}"
raw="${BENCH_RAW:-$(mktemp -d)/raw}"
echo "results: $out" >&2
echo "raw transcripts: $raw" >&2
python3 "$repo/bench/push/bench.py" --out "$out" --raw "$raw" "$@"
