#!/usr/bin/env bash
#
# Container smoke test for the example services (opt-in: needs Docker;
# `make demo-examples-docker`). Builds two examples from
# examples/services/Dockerfile through their own compose.yml, with
# .scripts/fixtures/stub-cli.sh standing in for the vendor's CLI (the `stub`
# target), and checks what the compose files promise:
#
#   github (pattern B): the role's credential arrives as a Compose secret
#     under /run/secrets, readable by the unprivileged user with no chown;
#   aws (pattern A): no secret; each call's token file lands in a tmpfs
#     owned by that user;
#   all eight: compose.yml validates;
#   both: `wires serve --check` accepts the mounted host.json; the process
#     runs as uid 10001 on a read-only root; the keystore volume at /data is
#     writable by it and keeps the node id between runs; the wrapper refuses
#     an unallowed subcommand with exit 77 and the CLI never run.
#
# It doesn't start `wires serve` against a network: make demo-examples covers
# the wrappers over a live loopback host.
#
# Everything it creates is named wires-example-test-* and removed on exit:
# the compose projects (containers, networks, volumes), their images, and
# the wires image it builds from the repo's Dockerfile (set WIRES_IMAGE to
# use an existing one instead; it is then left alone).
#
#   ./.scripts/demo-example-services-docker.sh            narrated
#   ./.scripts/demo-example-services-docker.sh --quiet    assertions only

set -euo pipefail

QUIET=""
case "${1:-}" in
--quiet) QUIET=1 ;;
"") ;;
*)
	printf 'usage: %s [--quiet]\n' "$0" >&2
	exit 2
	;;
esac

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/.scripts/lib.sh"
command -v docker >/dev/null || bad "docker is not on PATH"
docker compose version >/dev/null 2>&1 || bad "docker compose is not available"
command -v jq >/dev/null || bad "jq is not on PATH"

PREFIX=wires-example-test
UID_WIRES=10001
START=$SECONDS
D="$(mktemp -d)"
OWN_IMAGE=""
PROJECTS=()
cleanup() {
	local svc
	for svc in "${PROJECTS[@]}"; do
		dc "$svc" down -v --rmi all --remove-orphans >/dev/null 2>&1 || true
	done
	[ -z "$OWN_IMAGE" ] || docker image rm "$OWN_IMAGE" >/dev/null 2>&1 || true
	rm -rf "$D"
}
trap cleanup EXIT INT TERM

if [ -z "${WIRES_IMAGE:-}" ]; then
	WIRES_IMAGE="$PREFIX-wires"
	OWN_IMAGE="$WIRES_IMAGE"
	run "docker build -t $WIRES_IMAGE .   # the repo's image; the examples copy wires from it"
	docker build -q -t "$WIRES_IMAGE" "$repo" >/dev/null 2>"$D/wires-build.err" || {
		dump "$D/wires-build.err"
		bad "setup: the repo's wires image did not build"
	}
fi
export WIRES_IMAGE

# Run compose for example $1 (its own compose.yml plus the stub override).
dc() {
	local svc="$1"
	shift
	docker compose -p "$PREFIX-$svc" -f "$repo/examples/services/$svc/compose.yml" -f "$D/$PREFIX-$svc.yml" "$@"
}

# Build example $1 with stub CLI $2 standing in. Any further lines on stdin
# are appended to the override (top-level keys such as `secrets:`).
build_stub() {
	local svc="$1" cli="$2"
	PROJECTS+=("$svc")
	{
		cat <<EOF
services:
  $svc:
    image: $PREFIX-$svc
    build:
      target: stub
      args:
        SERVICE: $svc
        CLI: $cli
      additional_contexts:
        fixtures: $repo/.scripts/fixtures
EOF
		cat
	} >"$D/$PREFIX-$svc.yml"
	run "docker compose build   # examples/services/$svc, with a stub $cli"
	dc "$svc" build -q >/dev/null 2>"$D/$svc-build.err" || {
		dump "$D/$svc-build.err"
		bad "$svc: the image did not build"
	}
}

# `-e NAME=VALUE` for each of example $1's host.json env, as serve sets it.
host_env() {
	jq -r --arg s "$1" '.services[$s].env | to_entries[] | "-e\n\(.key)=\(.value)"' \
		"$repo/examples/services/$1/host.json"
}

# Run the wrapper of example $1 in its container, as one call of role
# analyst would be run (host.json's env plus the WIRES_* values; extra `-e`
# pairs in the array CALL_ENV), with argv "${@:2}". Writes $D/$1.<tag>.out
# and .err, where tag is $TAG; sets RC. The stub records to /tmp/stub, which
# the output then lists.
CALL_ENV=()
call_wrapper() {
	local svc="$1"
	shift
	local env_args=()
	mapfile -t env_args < <(host_env "$svc")
	set +e
	# shellcheck disable=SC2016 # expands in the container's shell
	dc "$svc" run --rm -T --entrypoint /bin/sh "${env_args[@]}" "${CALL_ENV[@]}" \
		-e WIRES_SERVICE="$svc" -e WIRES_ROLE=analyst -e WIRES_CALLER_EMAIL=alice@example.com \
		-e STUB_LOG=/tmp/stub "$svc" -c \
		'mkdir /tmp/stub && echo "uid $(id -u)" && "$0" "$@" && cat /tmp/stub/*' \
		"/opt/wires-examples/services/$svc/wrapper.sh" "$@" \
		</dev/null >"$D/$svc.$TAG.out" 2>"$D/$svc.$TAG.err"
	RC=$?
	set -e
}
has() { grep -qxF -- "$2" "$1" || {
	sed 's/^/  out| /' "$1" >&2
	bad "$3"
}; }

# Checks both examples share: serve --check, the keystore volume, the user.
common_checks() {
	local svc="$1"
	run "docker compose run --rm $svc serve --check /etc/wires-examples/host.json"
	dc "$svc" run --rm -T "$svc" serve --check /etc/wires-examples/host.json </dev/null \
		>"$D/$svc.check.out" 2>"$D/$svc.check.err" || {
		dump "$D/$svc.check.err"
		bad "$svc: serve --check rejected the mounted host.json"
	}
	grep -qF "$svc" "$D/$svc.check.out" || {
		dump "$D/$svc.check.out"
		bad "$svc: serve --check did not list $svc"
	}
	show "$D/$svc.check.out"
	ok "$svc: serve --check accepts /etc/wires-examples/host.json (a Compose config)"

	run "docker compose run --rm $svc id   # twice: the keystore volume keeps the node key"
	local id1 id2
	id1="$(dc "$svc" run --rm -T "$svc" id </dev/null 2>"$D/$svc.id.err")" || {
		dump "$D/$svc.id.err"
		bad "$svc: wires id failed (is /data writable by uid $UID_WIRES?)"
	}
	id2="$(dc "$svc" run --rm -T "$svc" id </dev/null 2>/dev/null)"
	[ -n "$id1" ] && [ "$id1" = "$id2" ] || bad "$svc: the node id did not persist ($id1 / $id2)"
	ok "$svc: node ${id1:0:8}... in the keystore volume, the same on the next run"

	local who
	# The uid, and the root mount's first option (ro or rw).
	# shellcheck disable=SC2016 # awk's own $2, $4
	who="$(dc "$svc" run --rm -T --entrypoint /bin/sh "$svc" -c \
		'id -u; awk '\''$2 == "/" { split($4, o, ","); print o[1] }'\'' /proc/mounts' </dev/null 2>/dev/null | tr '\n' ' ')"
	[ "$who" = "$UID_WIRES ro " ] || bad "$svc: expected uid $UID_WIRES on a read-only root, got: $who"
	ok "$svc: runs as uid $UID_WIRES; the root filesystem is read-only"
}

# ==========================================================================
step "0  every example's compose.yml is valid Compose"
# ==========================================================================
for svc in aws gcp k8s github cloudflare vercel supabase stripe; do
	docker compose -f "$repo/examples/services/$svc/compose.yml" config -q 2>"$D/config.err" || {
		dump "$D/config.err"
		bad "$svc: compose.yml does not validate"
	}
done
ok "0: eight compose.yml files validate (docker compose config)"

# ==========================================================================
step "1  github (pattern B): the role's token as a Compose secret, no chown"
# ==========================================================================
# As the README has the operator do it: a 0700 directory, a file Docker can
# bind-mount for the container's user.
GH_SECRET="demo-gh-analyst-$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
install -d -m 700 "$D/github-secrets"
(umask 022 && printf '%s\n' "$GH_SECRET" >"$D/github-secrets/analyst.token")
build_stub github gh <<EOF
secrets:
  analyst:
    file: $D/github-secrets/analyst.token
EOF
common_checks github

TAG=call
CALL_ENV=()
run "the wrapper, as a call by alice (analyst): pr list"
call_wrapper github pr list
[ "$RC" -eq 0 ] || {
	dump "$D/github.call.err"
	bad "github: the wrapper exited $RC"
}
has "$D/github.call.out" "uid $UID_WIRES" "github: the call did not run as uid $UID_WIRES"
has "$D/github.call.out" "argv pr list" "github: gh did not run the agent's command"
has "$D/github.call.out" "env GH_TOKEN=$GH_SECRET" "github: gh did not get the token from /run/secrets/analyst"
has "$D/github.call.out" "env HOME=/var/lib/wires-examples/github" "github: gh's HOME is not the tmpfs"
ok "github: GH_TOKEN read from /run/secrets/analyst by uid $UID_WIRES"

TAG=refused
run "the wrapper: auth token   # would print the token"
call_wrapper github auth token
[ "$RC" -eq 77 ] || bad "github: auth token exited $RC, expected 77"
grep -qF 'is not allowed on this host' "$D/github.refused.err" || bad "github: no refusal message"
! grep -q '^argv' "$D/github.refused.out" || bad "github: gh ran for a refused subcommand"
! grep -qF -- "$GH_SECRET" "$D/github.refused.out" "$D/github.refused.err" || bad "github: the token was printed"
ok "github: auth token refused (77), gh never ran"

# ==========================================================================
step "2  aws (pattern A): no secret; the call's token file in a tmpfs"
# ==========================================================================
build_stub aws aws </dev/null
common_checks aws

TAG=call
CALL_ENV=(-e "WIRES_ID_TOKEN=demo-id-token-for-alice")
run "the wrapper, as a call by alice (analyst): sts get-caller-identity"
call_wrapper aws sts get-caller-identity
[ "$RC" -eq 0 ] || {
	dump "$D/aws.call.err"
	bad "aws: the wrapper exited $RC"
}
has "$D/aws.call.out" "uid $UID_WIRES" "aws: the call did not run as uid $UID_WIRES"
has "$D/aws.call.out" "arn:aws:sts::123456789012:assumed-role/wires-readonly/alice@example.com" \
	"aws: not the analyst's role, or the session is not alice's"
has "$D/aws.call.out" "file AWS_WEB_IDENTITY_TOKEN_FILE demo-id-token-for-alice" "aws: the token file does not hold the call's token"
grep -qE '^env AWS_WEB_IDENTITY_TOKEN_FILE=/var/lib/wires-examples/aws/call\.' "$D/aws.call.out" ||
	bad "aws: the token file is not under STATE_DIR (the tmpfs)"
! grep -q '^env WIRES_ID_TOKEN=' "$D/aws.call.out" || bad "aws: the CLI still has WIRES_ID_TOKEN"
ok "aws: the call's token in /var/lib/wires-examples/aws (tmpfs, uid $UID_WIRES); role wires-readonly"

TAG=refused
run "the wrapper: configure export-credentials   # would print the session's keys"
call_wrapper aws configure export-credentials
[ "$RC" -eq 77 ] || bad "aws: configure exited $RC, expected 77"
! grep -q '^argv' "$D/aws.refused.out" || bad "aws: the CLI ran for a refused subcommand"
ok "aws: configure refused (77), the CLI never ran"

# ==========================================================================
step "SUMMARY"
# ==========================================================================
printf '     images    : github and aws from examples/services/Dockerfile (stub CLIs), wires from %s\n' "$WIRES_IMAGE" >&2
printf '     as        : uid %s, read-only root, keystore volume at /data, no port published\n' "$UID_WIRES" >&2
printf '     secrets   : Compose secret under /run/secrets (B); tmpfs token files (A); %ss wall clock\n' "$((SECONDS - START))" >&2
