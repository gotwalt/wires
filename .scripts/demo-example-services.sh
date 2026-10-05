#!/usr/bin/env bash
#
# Demo (card 50): the example services in examples/services/, served by one
# loopback host through their real wrappers, with stand-in CLIs that record
# what each wrapper handed them (.scripts/fixtures/stub-cli.sh, linked as
# aws, gcloud, kubectl, gh, wrangler, vercel, supabase and stripe on
# `serve`'s PATH). No cloud is touched: pattern A's token exchange and
# pattern B's vendor API are where the stubs stop.
#
# Keystores on one machine, all loopback (as in demo-remote-cli.sh):
#
#   workbench -- `wires serve` over the eight examples' host.json fragments,
#                merged; also the network's one directory.
#   alice     -- alice@example.com, role analyst.
#   carol     -- carol@example.com, role sre.
#   bob       -- bob@example.com, role contractor: the policy lets him call
#                the services, and no wrapper maps his role.
#   root      -- the admin: roles, the eight services, `wires remove`.
#
# Asserted: pattern A wrappers (aws, gcp, k8s) hand the caller's own ID
# token to the exchange as a token file (AWS_WEB_IDENTITY_TOKEN_FILE,
# gcloud's credential_source.file, kubeconfig's tokenFile), name the AWS
# session after the caller's email, pick the cloud role, service account or
# namespace by wires role (analyst and sre get different ones), and leave no
# WIRES_ID_TOKEN in the CLI's environment; pattern B wrappers (github,
# cloudflare, vercel, supabase, stripe) set the vendor's variable from the
# role's credential file, which host.json names but doesn't hold; a
# subcommand outside a wrapper's allowlist (`gh auth token`) and an unmapped
# role (bob's) are refused with the CLI never run; no vendor credential
# appears anywhere on the callers' side; and after `wires remove
# alice@example.com` her next call exits 77 with the CLI never run.
#
#   ./.scripts/demo-example-services.sh            narrated
#   ./.scripts/demo-example-services.sh --quiet    assertions only
#   ./.scripts/demo-example-services.sh --keep     leave the state dir behind

set -euo pipefail

QUIET=""
KEEP=""
while [ $# -gt 0 ]; do
	case "$1" in
	--quiet)
		QUIET=1
		shift
		;;
	--keep)
		KEEP=1
		shift
		;;
	*)
		printf 'usage: %s [--quiet] [--keep]\n' "$0" >&2
		exit 2
		;;
	esac
done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
WIRES="${WIRES_BIN:-$repo/target/release/wires}"
WIRES_DEV="${WIRES_DEV_BIN:-$repo/target/release/wires-mock-idp}"
ALICE="alice@example.com"
CAROL="carol@example.com"
BOB="bob@example.com"
EXIT_DENIED=77
SERVICES="aws gcp k8s github cloudflare vercel supabase stripe"
START=$SECONDS

D="$(mktemp -d)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$repo/.scripts/lib.sh"
WB_PID=""
p=""
trap 'for p in $WB_PID $IDP_PID; do kill "$p" 2>/dev/null || true; done; [ -n "$KEEP" ] || rm -rf "$D"' EXIT INT TERM

admin() { WIRES_HOME="$root" "$WIRES" "$@"; }
# Run `wires call` as $1 (a keystore), output to $D/$2.out / .err; sets RC.
RC=0
call_as() {
	local home="$1" tag="$2"
	shift 2
	set +e
	WIRES_HOME="$home" WIRES_LOCKED=1 "$WIRES" call "$@" </dev/null >"$D/$tag.out" 2>"$D/$tag.err"
	RC=$?
	set -e
}
# The stub's record of the newest run of CLI $1.
# shellcheck disable=SC2012 # mktemp names: no odd characters
newest() { ls -t "$STUBS"/"$1".* 2>/dev/null | head -1; }
runs() { find "$STUBS" -type f | wc -l | tr -d ' '; }
# A pattern B credential, as the operator wrote it: $1 service, $2 role.
secret() { cat "$ETC/$1/$2.token"; }
# Assert that call $1 was refused by its wrapper: exit 1 at the caller (the
# wrapper's 77, reported), message $2 on stderr, nothing on stdout.
refused() {
	if [ "$RC" -ne 1 ] || ! grep -qF -- "$2" "$D/$1.err" || [ -s "$D/$1.out" ]; then
		cat "$D/$1.out" "$D/$1.err" >&2
		bad "$3 (exit $RC)"
	fi
}
# Assert that record $1 holds line $2 exactly.
has() { grep -qxF -- "$2" "$1" || {
	sed 's/^/  stub| /' "$1" >&2
	bad "$3"
}; }

build_wires
for c in curl jq; do command -v "$c" >/dev/null || bad "$c is not on PATH"; done

# ==========================================================================
# Setup (off camera): keystores, one signed policy, one IdP, the stub CLIs.
# ==========================================================================
root="$D/root"
wb="$D/wb"
alice="$D/alice"
carol="$D/carol"
bob="$D/bob"
mkdir -p "$root" "$wb" "$alice" "$carol" "$bob"

start_mock_idp "$ALICE"
admin init --issuer "$ISSUER" --client-id "$CLIENT_ID" --public-client-secret not-so-secret >/dev/null
WB_ID="$(WIRES_HOME="$wb" "$WIRES" id 2>/dev/null)"
[ -n "$WB_ID" ] || bad "setup: could not read the workbench's id"
admin role set analyst "$ALICE" >/dev/null 2>&1
admin role set sre "$CAROL" >/dev/null 2>&1
admin role set contractor "$BOB" >/dev/null 2>&1
admin directory add "workbench=$WB_ID" >/dev/null 2>"$D/dir.err" || {
	cat "$D/dir.err" >&2
	bad "setup: wires directory add failed"
}
for svc in $SERVICES; do
	admin service add "$svc" --allow analyst --allow sre --allow contractor --host workbench \
		--description "examples/services/$svc" >/dev/null 2>"$D/svc.err" || {
		cat "$D/svc.err" >&2
		bad "setup: wires service add $svc failed"
	}
done
NETWORK="$(admin network)"
WIRES_HOME="$wb" "$WIRES" join "$NETWORK" >/dev/null

# The host's side, as an operator would lay it out (examples/services/*/
# README.md), under $D: the role maps, the credential files (0600, read by
# serve's user only), the state dirs, and stub CLIs first on serve's PATH.
ETC="$D/etc/wires-examples"
VAR="$D/var/lib/wires-examples"
STUBS="$D/stub-log"
mkdir -p "$ETC" "$VAR" "$STUBS" "$D/bin"
for cli in aws gcloud kubectl gh wrangler vercel supabase stripe; do
	ln -s "$repo/.scripts/fixtures/stub-cli.sh" "$D/bin/$cli"
done
ARN_RO="arn:aws:iam::123456789012:role/wires-readonly"
ARN_OPS="arn:aws:iam::123456789012:role/wires-operator"
SA_RO="wires-readonly@acme-prod.iam.gserviceaccount.com"
SA_OPS="wires-operator@acme-prod.iam.gserviceaccount.com"
printf '# wires role -> IAM role\nanalyst %s\nsre %s\n' "$ARN_RO" "$ARN_OPS" >"$ETC/aws.roles"
printf 'analyst %s\nsre %s\n' "$SA_RO" "$SA_OPS" >"$ETC/gcp.roles"
printf 'analyst analytics\nsre default\n' >"$ETC/k8s.roles"
: >"$ETC/k8s-ca.crt"
for svc in github cloudflare vercel supabase stripe; do
	mkdir -p "$ETC/$svc" "$VAR/$svc"
	: >"$ETC/$svc.roles"
	for role in analyst sre; do
		s="demo-$svc-$role-$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
		(umask 077 && printf '%s\n' "$s" >"$ETC/$svc/$role.token")
		printf '%s %s\n' "$role" "$ETC/$svc/$role.token" >>"$ETC/$svc.roles"
	done
done

# host.json: the eight fragments, as shipped, with their paths moved under
# $D and the stubs' log dir added to each service's env.
HOST_JSON="$D/host.json"
for svc in $SERVICES; do
	sed -e "s|/opt/wires-examples|$repo/examples|g" -e "s|/etc/wires-examples|$ETC|g" \
		-e "s|/var/lib/wires-examples|$VAR|g" "$repo/examples/services/$svc/host.json"
done | jq -s --arg iss "$ISSUER" --arg aud "$CLIENT_ID" --arg log "$STUBS" '{
	version: 2,
	identity: {issuers: [{issuer: $iss, audiences: [$aud]}]},
	services: (map(.services) | add | map_values(.env.STUB_LOG = $log))
}' >"$HOST_JSON"
"$WIRES" serve --check "$HOST_JSON" >"$D/check.out" 2>&1 || {
	cat "$D/check.out" >&2
	bad "setup: serve --check rejected the merged host.json"
}
for svc in github cloudflare vercel supabase stripe; do
	! grep -qF "$(secret "$svc" analyst)" "$HOST_JSON" || bad "setup: host.json holds the $svc credential"
done

(cd "$D" && PATH="$D/bin:$PATH" WIRES_HOME="$wb" exec "$WIRES" serve "$HOST_JSON" >"$D/wb.out" 2>"$D/wb.err") &
WB_PID=$!
wait_for "$wb/run/hint" " " 300 || {
	sed 's/^/  workbench| /' "$D/wb.err" >&2
	bad "setup: the workbench never came up"
}
for h in "$root" "$alice" "$carol" "$bob"; do cp "$wb/run/hint" "$h/hints"; done
admin policy push >/dev/null 2>"$D/push0.err" || {
	cat "$D/push0.err" >&2
	bad "setup: wires policy push failed"
}
wait_for "$D/wb.err" "signed policy assigns every service to this host" 100 || {
	dump "$D/wb.err"
	bad "setup: the workbench never started serving"
}
login_as "$alice" "$ALICE" "$NETWORK"
login_as "$carol" "$CAROL" "$NETWORK"
login_as "$bob" "$BOB" "$NETWORK"
ALICE_TOKEN="$(cat "$alice/idp-token.jwt")"
CAROL_TOKEN="$(cat "$carol/idp-token.jwt")"
[ -n "$ALICE_TOKEN" ] && [ -n "$CAROL_TOKEN" ] || bad "setup: no ID token in the callers' keystores"

WIRES_HOME="$alice" "$WIRES" services >"$D/services.out" 2>/dev/null || true
for svc in $SERVICES; do
	grep -qE "^$svc " "$D/services.out" || {
		cat "$D/services.out" >&2
		bad "setup: alice does not see $svc"
	}
done
say "workbench ${WB_ID:0:8}...  serves eight examples through their wrappers; the CLIs are stubs"
say "alice (analyst), carol (sre), bob (contractor): signed in; locked to \`wires call\`"
show "$D/services.out"
beat 4

# ==========================================================================
step "1  pattern A, aws: the caller's ID token becomes a role session named after her"
# ==========================================================================
run "wires call aws -- sts get-caller-identity --query Arn --output text   # as alice"
call_as "$alice" a1 aws -- sts get-caller-identity --query Arn --output text
[ "$RC" -eq 0 ] || {
	cat "$D/a1.err" >&2
	bad "1: alice's aws call exited $RC"
}
grep -qxF "arn:aws:sts::123456789012:assumed-role/wires-readonly/$ALICE" "$D/a1.out" || {
	cat "$D/a1.out" >&2
	bad "1: alice's session is not wires-readonly/$ALICE"
}
show "$D/a1.out"
r="$(newest aws)"
has "$r" "env AWS_ROLE_ARN=$ARN_RO" "1: alice (analyst) did not get the read-only role"
has "$r" "env AWS_ROLE_SESSION_NAME=$ALICE" "1: the session is not named after alice"
has "$r" "file AWS_WEB_IDENTITY_TOKEN_FILE $ALICE_TOKEN" "1: the token file does not hold alice's ID token"
has "$r" "env AWS_EC2_METADATA_DISABLED=true" "1: the instance role is not ruled out"
! grep -q '^env WIRES_ID_TOKEN=' "$r" || bad "1: the CLI still has WIRES_ID_TOKEN in its environment"
ok "1: AWS_WEB_IDENTITY_TOKEN_FILE holds alice's own ID token; role wires-readonly; session $ALICE"

run "wires call aws -- sts get-caller-identity --query Arn --output text   # as carol (sre)"
call_as "$carol" a2 aws -- sts get-caller-identity --query Arn --output text
[ "$RC" -eq 0 ] || bad "1: carol's aws call exited $RC"
r="$(newest aws)"
has "$r" "env AWS_ROLE_ARN=$ARN_OPS" "1: carol (sre) did not get the operator role"
has "$r" "env AWS_ROLE_SESSION_NAME=$CAROL" "1: the session is not named after carol"
has "$r" "file AWS_WEB_IDENTITY_TOKEN_FILE $CAROL_TOKEN" "1: the token file does not hold carol's ID token"
show "$D/a2.out"
ok "1: carol, role sre -> wires-operator: the wires role picks the cloud role"
beat 3

# ==========================================================================
step "2  pattern A, gcp and k8s: the same token, as a federation file and a kubeconfig"
# ==========================================================================
run "wires call gcp -- compute instances list --format='json(name,status)'"
call_as "$alice" g1 gcp -- compute instances list "--format=json(name,status)"
[ "$RC" -eq 0 ] || {
	cat "$D/g1.err" >&2
	bad "2: alice's gcp call exited $RC"
}
login_rec="$(grep -l '^argv auth login --cred-file=' "$STUBS"/gcloud.* | head -1)"
[ -n "$login_rec" ] || bad "2: the wrapper never ran gcloud auth login --cred-file"
has "$login_rec" "file credential_source $ALICE_TOKEN" "2: gcloud's credential_source.file does not hold alice's token"
grep -qF "serviceAccounts/$SA_RO:generateAccessToken" "$login_rec" || bad "2: alice does not impersonate $SA_RO"
has "$(newest gcloud)" "argv compute instances list --format=json(name,status)" "2: gcloud did not run the agent's command"
ok "2: gcloud: credential_source.file = alice's token, impersonating $SA_RO"

run "wires call k8s -- get pods -o jsonpath='{.items[*].metadata.name}'"
call_as "$alice" k1 k8s -- get pods -o "jsonpath={.items[*].metadata.name}"
[ "$RC" -eq 0 ] || {
	cat "$D/k1.err" >&2
	bad "2: alice's k8s call exited $RC"
}
r="$(newest kubectl)"
has "$r" "file tokenFile $ALICE_TOKEN" "2: kubeconfig's tokenFile does not hold alice's token"
has "$r" "kubeconfig     namespace: analytics" "2: analyst's default namespace is not analytics"
! grep -qF -- "$ALICE_TOKEN" <(grep '^argv' "$r") || bad "2: the token is in kubectl's argv"
ok "2: kubectl: tokenFile = alice's token (not in argv); namespace analytics"
beat 3

# ==========================================================================
step "3  pattern B: the host holds one scoped credential per role; the caller never sees it"
# ==========================================================================
B_CALLS=(
	"github|gh|GH_TOKEN|pr list --json number,title --jq length"
	"cloudflare|wrangler|CLOUDFLARE_API_TOKEN|d1 list --json"
	"vercel|vercel|VERCEL_TOKEN|list my-app --status ERROR"
	"supabase|supabase|SUPABASE_ACCESS_TOKEN|projects list -o json"
	"stripe|stripe|STRIPE_API_KEY|charges list --limit 5"
)
for spec in "${B_CALLS[@]}"; do
	IFS='|' read -r svc cli var args <<<"$spec"
	run "wires call $svc -- $args"
	# shellcheck disable=SC2086 # the args are words on purpose
	call_as "$alice" "b-$svc" "$svc" -- $args
	[ "$RC" -eq 0 ] || {
		cat "$D/b-$svc.err" >&2
		bad "3: alice's $svc call exited $RC"
	}
	r="$(newest "$cli")"
	has "$r" "env $var=$(secret "$svc" analyst)" "3: $cli did not get analyst's $svc credential from its file"
	has "$r" "argv $args" "3: $cli did not run the agent's command"
	! grep -q '^env WIRES_ID_TOKEN=' "$r" || bad "3: $cli has the caller's ID token"
	ok "3: $svc: $var from $svc/analyst.token"
done
has "$(newest stripe)" "env STRIPE_DEVICE_NAME=wires:$ALICE" "3: stripe's device name does not name alice"
run "wires call github -- pr list   # as carol (sre)"
call_as "$carol" b-gh2 github -- pr list
[ "$RC" -eq 0 ] || bad "3: carol's github call exited $RC"
has "$(newest gh)" "env GH_TOKEN=$(secret github sre)" "3: carol (sre) did not get sre's token"
ok "3: carol gets sre's token: one credential per role, chosen by the host"
beat 3

# ==========================================================================
step "4  refused before the CLI runs: a subcommand off the allowlist, an unmapped role"
# ==========================================================================
before="$(runs)"
run "wires call github -- auth token   # would print the token"
call_as "$alice" r1 github -- auth token
# shellcheck disable=SC2016 # literal backticks in the message
refused r1 '`auth token` is not allowed on this host' "4: gh auth token was not refused by the wrapper"
show "$D/r1.err"
run "wires call aws -- sts get-caller-identity   # as bob: role contractor, in no role map"
call_as "$bob" r2 aws -- sts get-caller-identity
refused r2 "role contractor has no mapping for aws on this host" "4: bob's unmapped role was not refused"
call_as "$bob" r3 github -- pr list
refused r3 "role contractor has no mapping for github on this host" "4: bob's github call was not refused"
show "$D/r2.err"
[ "$(runs)" -eq "$before" ] || bad "4: a refused call ran a CLI"
ok "4: refused by the wrapper (exit 77 there, 1 at the caller); no CLI ran"
beat 3

# ==========================================================================
step "5  no vendor credential on the callers' side"
# ==========================================================================
for svc in github cloudflare vercel supabase stripe; do
	for role in analyst sre; do
		s="$(secret "$svc" "$role")"
		! grep -rqF -- "$s" "$alice" "$carol" "$bob" "$root" || bad "5: the $svc/$role credential is in a caller's or the admin's keystore"
		! cat "$D"/*.out "$D"/*.err 2>/dev/null | grep -qF -- "$s" || bad "5: the $svc/$role credential reached a caller's output"
	done
done
ok "5: none of the ten credentials is in any keystore or any call's output"
beat 2

# ==========================================================================
step "6  the admin removes $ALICE -- the next call is refused before any wrapper runs"
# ==========================================================================
run "wires remove $ALICE"
admin remove "$ALICE" >/dev/null 2>"$D/remove.err" || {
	cat "$D/remove.err" >&2
	bad "6: wires remove failed"
}
before="$(runs)"
run "wires call github -- pr list"
call_as "$alice" x1 github -- pr list
[ "$RC" -eq "$EXIT_DENIED" ] || {
	dump "$D/x1.err"
	bad "6: the removed caller's call exited $RC, expected $EXIT_DENIED"
}
[ ! -s "$D/x1.out" ] || bad "6: the refused call wrote to stdout"
[ "$(runs)" -eq "$before" ] || bad "6: a CLI ran for a removed caller"
show "$D/x1.err"
ok "6: exit $EXIT_DENIED, 0 bytes out, no CLI ran; no credential was rotated"
alive "$WB_PID" || bad "6: the workbench died"

# ==========================================================================
step "SUMMARY"
# ==========================================================================
printf '     pattern A : aws, gcp, k8s -- the caller'"'"'s ID token as a token file; role by wires role; aws session = email\n' >&2
printf '     pattern B : github, cloudflare, vercel, supabase, stripe -- credential read from a 0600 file per role\n' >&2
printf '     refused   : gh auth token (allowlist), contractor (unmapped role): no CLI ran\n' >&2
printf '     callers   : hold no vendor credential; removal -> exit 77, no rotation; %ss wall clock\n' "$((SECONDS - START))" >&2
[ -z "$KEEP" ] || say "state kept in $D"
