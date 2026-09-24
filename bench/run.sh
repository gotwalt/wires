#!/usr/bin/env bash
#
# MCP vs CLI token benchmark (board card 16). Reproduce with:
#
#   ./bench/run.sh                                        # full: 5 arms x 5 tasks x 5 reps
#   ./bench/run.sh --reps 1                               # smoke test
#   ./bench/run.sh --arms mcp,gh --tasks t1-release       # a slice
#
# Needs: `claude` (logged in), `gh` (logged in), docker, python3.
# The GitHub token is read with `gh auth token` at runtime by bench.py and
# handed to the MCP container through the environment; it is never written
# to disk. Raw stream-json transcripts go to $BENCH_RAW (default: a temp dir),
# NOT the repo -- they can contain whatever the model printed.
#
# Extra args are passed to bench.py (--reps, --arms, --tasks, --budget).

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
D="${BENCH_WIRES_DIR:-/tmp/wb16}" # short: macOS 104-byte unix-socket paths
mkdir -p "$D/bin"
if [ -z "${WIRES_BIN:-}" ]; then
	(cd "$repo" && cargo build -q --release -p wires)
	# rm first: overwriting a signed binary in place gets it SIGKILLed on macOS
	rm -f "$D/bin/wires"
	cp "$repo/target/release/wires" "$D/bin/wires"
	chmod u+w "$D/bin/wires"
fi

docker pull -q "${GH_MCP_IMAGE:-ghcr.io/github/github-mcp-server}" >/dev/null

BENCH_WIRES_DIR="$D" "$repo/bench/wires-up.sh" >/dev/null
# shellcheck source=/dev/null
. "$D/env.sh"
export BENCH_WIRES_BIN_DIR="$D/bin"
trap 'kill "$BENCH_WIRES_PID" 2>/dev/null || true' EXIT

date="$(date -u +%Y-%m-%d)"
out="${BENCH_OUT:-$repo/bench/results/$date.jsonl}"
raw="${BENCH_RAW:-$(mktemp -d)/raw}"
echo "results: $out" >&2
echo "raw transcripts: $raw" >&2
python3 "$repo/bench/bench.py" --out "$out" --raw "$raw" "$@"
