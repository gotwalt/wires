#!/usr/bin/env bash
#
# Help-text eval (board card 38). Reproduce with:
#
#   ./bench/help/run.sh --label after                   # 4 tasks x 2 reps, this checkout
#   WIRES_BIN=/path/to/old/wires ./bench/help/run.sh --label before
#   ./bench/help/run.sh --label after --reps 1 --tasks premise
#
# WIRES_BIN must be a `--features dev-mock-idp` build (the stand-in IdP);
# without it this builds one from the checkout. Needs `claude` (logged in),
# sqlite3, curl, python3. Raw stream-json transcripts go to $HELP_EVAL_RAW
# (default: a temp dir), not the repo. Extra args go to eval.py (--label,
# --reps, --tasks, --budget).

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
D="${HELP_EVAL_DIR:-/tmp/wbh}"
if [ -z "${WIRES_BIN:-}" ]; then
	(cd "$repo" && cargo build -q --release -p wires --features dev-mock-idp)
	mkdir -p "$D.build"
	rm -f "$D.build/wires"
	cp "$repo/target/release/wires" "$D.build/wires"
	WIRES_BIN="$D.build/wires"
fi

HELP_EVAL_DIR="$D" WIRES_BIN="$WIRES_BIN" "$repo/bench/help/up.sh" >/dev/null
# shellcheck source=/dev/null
. "$D/env.sh"
trap 'kill "$HELP_EVAL_WB_PID" "$HELP_EVAL_IDP_PID" 2>/dev/null || true' EXIT

out="${HELP_EVAL_OUT:-$repo/bench/help/results/$(date -u +%Y-%m-%d).jsonl}"
raw="${HELP_EVAL_RAW:-$(mktemp -d)/raw}"
mkdir -p "$(dirname "$out")"
echo "results: $out" >&2
echo "raw transcripts: $raw" >&2
python3 "$repo/bench/help/eval.py" --out "$out" --raw "$raw" "$@"
