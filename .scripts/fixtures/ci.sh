#!/usr/bin/env bash
#
# A mock CI host for the push demo (card 24): three tools in one script,
# exposed by .scripts/fixtures/push-host.json.
#
#   ci.sh deploy build <n>             start build <n> in the background; return at once
#   ci.sh status build <n>             running / failed (the poll path)
#   ci.sh logs   build <n> [--tail N]  the build log (default: last 50 lines)
#
# `wires serve` runs it, so the caller's arguments come after the fixed
# subcommand, and the verified caller's node id is in $WIRES_CALLER_NODE.
# When a build finishes, its background job pushes the result to that caller:
#
#   wires push --to "$WIRES_CALLER_NODE" --subject build-<n> -- "failed: …"
#
# which reaches the running `wires serve` over its control socket: serve sets
# $WIRES_HOME to the host's keystore for every service it runs.
#
# Environment (set on `wires serve`, inherited):
#   CI_JOBS      state directory (default ./ci-jobs, relative to serve's cwd)
#   CI_JOB_SECS  how long a build runs (default 5); $CI_JOBS/job-secs, if
#                present, overrides it at deploy time (the benchmark sets it)
#   CI_WIRES     the wires binary for `wires push` (default: `wires` on PATH)
#
# Every tool call is appended to $CI_JOBS/calls.log as
# `<epoch ms> <tool> <caller8> <args>`, and a finished build writes
# $CI_JOBS/build-<n>/done_ms: the benchmark measures reaction latency from them.

set -euo pipefail

JOBS="${CI_JOBS:-ci-jobs}"
WIRES_PUSH="${CI_WIRES:-wires}"
mkdir -p "$JOBS"

now_ms() { perl -MTime::HiRes=time -e 'printf "%d\n", time*1000'; }
die() {
	printf '%s\n' "$*" >&2
	exit 2
}

tool="${1:-}"
shift || true
printf '%s %s %s %s\n' "$(now_ms)" "$tool" "${WIRES_CALLER_NODE:0:8}" "$*" >>"$JOBS/calls.log"

# `build <n>` (or `build-<n>`), then tool-specific flags.
[ $# -ge 1 ] || die "usage: $tool build <n>"
if [ "$1" = build ]; then
	[ $# -ge 2 ] || die "usage: $tool build <n>"
	n="$2"
	shift 2
else
	n="${1#build-}"
	shift
fi
case "$n" in '' | *[!0-9]*) die "$tool: build number must be digits, got '$n'" ;; esac
[ "${#n}" -le 9 ] || die "$tool: build number too long"
job="$JOBS/build-$n"

# The build's one failing assertion. The value depends on the build number,
# so a correct answer has to come from this build's log.
got() { printf '%d.%02d' $((1234 + n % 97)) $((n % 100)); }

write_log() {
	local i
	{
		printf '[ci] build %s: cargo test --workspace\n' "$n"
		for i in $(seq 1 160); do
			printf 'test orders::tests::case_%03d ... ok\n' "$i"
		done
		printf 'test orders::tests::test_orders_total ... FAILED\n'
		for i in $(seq 161 213); do
			printf 'test orders::tests::case_%03d ... ok\n' "$i"
		done
		printf '\nfailures:\n\n---- orders::tests::test_orders_total stdout ----\n'
		printf "thread 'orders::tests::test_orders_total' panicked at orders/total.rs:88:9:\n"
		# shellcheck disable=SC2016 # a Rust assertion message, not an expansion
		printf 'assertion `left == right` failed: sum(total) over the fixture orders\n'
		printf '  left: %s\n right: 1234.50\n' "$(got)"
		printf '\nfailures:\n    orders::tests::test_orders_total\n\n'
		printf 'test result: FAILED. 213 passed; 1 failed; 0 ignored; finished in %ss\n' "$1"
	} >"$job/log"
}

case "$tool" in
deploy)
	[ $# -eq 0 ] || die "usage: deploy build <n>"
	[ ! -e "$job" ] || die "deploy: build-$n already exists"
	[ -n "${WIRES_CALLER_NODE:-}" ] || die "deploy: no WIRES_CALLER_NODE (run me under wires serve)"
	secs="${CI_JOB_SECS:-5}"
	[ ! -f "$JOBS/job-secs" ] || secs="$(cat "$JOBS/job-secs")"
	mkdir -p "$job"
	now_ms >"$job/started_ms"
	echo running >"$job/state"
	printf '[ci] build %s: queued\n' "$n" >"$job/log"
	caller="$WIRES_CALLER_NODE"
	# Detach fully (fresh stdio, nothing holding the call's pipes) so this
	# call returns now and the job outlives it.
	(
		sleep "$secs"
		write_log "$secs"
		echo failed >"$job/state"
		now_ms >"$job/done_ms"
		"$WIRES_PUSH" push --to "$caller" --subject "build-$n" --ttl 1h -- \
			"failed: test_orders_total (1 of 214 tests). Logs: wires call logs -- build $n --tail 50" \
			>"$job/push.out" 2>"$job/push.err" || true
		now_ms >"$job/pushed_ms"
	) </dev/null >/dev/null 2>&1 &
	disown
	# No ETA on purpose: a caller that knows exactly when to look needs
	# neither polling nor push (the benchmark's smoke test showed one
	# well-timed `sleep` doing the job). Nor a hint how to wait: that is the
	# variable the benchmark's prompts set.
	printf 'started build-%s for %s\n' "$n" "${caller:0:8}"
	;;
status)
	[ $# -eq 0 ] || die "usage: status build <n>"
	[ -d "$job" ] || die "status: no such build: build-$n"
	state="$(cat "$job/state")"
	case "$state" in
	running) printf 'build-%s running (%ss elapsed)\n' "$n" $((($(now_ms) - $(cat "$job/started_ms")) / 1000)) ;;
	failed) printf 'build-%s failed: test_orders_total (1 of 214 tests). Logs: wires call logs -- build %s --tail 50\n' "$n" "$n" ;;
	*) printf 'build-%s %s\n' "$n" "$state" ;;
	esac
	;;
logs)
	tail=50
	while [ $# -gt 0 ]; do
		case "$1" in
		--tail)
			[ $# -ge 2 ] || die "logs: --tail needs a number"
			tail="$2"
			shift 2
			;;
		--tail=*)
			tail="${1#--tail=}"
			shift
			;;
		*) die "usage: logs build <n> [--tail N]" ;;
		esac
	done
	case "$tail" in '' | *[!0-9]*) die "logs: --tail must be a number" ;; esac
	[ -d "$job" ] || die "logs: no such build: build-$n"
	tail -n "$tail" "$job/log"
	;;
*)
	die "ci.sh: unknown tool '$tool' (deploy, status, logs)"
	;;
esac
