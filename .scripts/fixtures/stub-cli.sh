#!/usr/bin/env bash
#
# A stand-in for a vendor CLI (aws, gcloud, kubectl, gh, wrangler, vercel,
# supabase, stripe), for .scripts/demo-example-services.sh: linked under the
# CLI's name on `serve`'s PATH, it touches no cloud. Each run records what the
# example wrapper handed it, to a new file in $STUB_LOG:
#
#   argv <args>                       the arguments, one line
#   env NAME=VALUE                    its whole environment, sorted
#   file <what> <contents>            the token file a pattern A wrapper wrote
#                                     (AWS_WEB_IDENTITY_TOKEN_FILE, kubeconfig's
#                                     tokenFile, gcloud's credential_source.file)
#   kubeconfig / credfile <line>      the kubeconfig or gcloud credential file
#
# and prints one line, as the CLI would print something.

set -euo pipefail
name="$(basename "$0")"
[ -n "${STUB_LOG:-}" ] || {
	echo "stub $name: STUB_LOG is unset" >&2
	exit 3
}
log="$(mktemp "$STUB_LOG/$name.XXXXXX")"
{
	printf 'argv %s\n' "$*"
	env | LC_ALL=C sort | sed 's/^/env /'
	if [ -n "${AWS_WEB_IDENTITY_TOKEN_FILE:-}" ]; then
		printf 'file AWS_WEB_IDENTITY_TOKEN_FILE %s\n' "$(cat "$AWS_WEB_IDENTITY_TOKEN_FILE")"
	fi
	if [ -n "${KUBECONFIG:-}" ]; then
		sed 's/^/kubeconfig /' "$KUBECONFIG"
		printf 'file tokenFile %s\n' "$(cat "$(awk '/tokenFile:/{print $2}' "$KUBECONFIG")")"
	fi
	for a in "$@"; do
		case "$a" in
		--cred-file=*)
			f="${a#--cred-file=}"
			sed 's/^/credfile /' "$f"
			printf 'file credential_source %s\n' "$(cat "$(jq -r .credential_source.file "$f")")"
			;;
		esac
	done
} >"$log"

case "$name $*" in
"aws sts get-caller-identity"*)
	printf 'arn:aws:sts::123456789012:assumed-role/%s/%s\n' "${AWS_ROLE_ARN##*/}" "$AWS_ROLE_SESSION_NAME"
	;;
*) printf 'stub %s: ran %s\n' "$name" "$*" ;;
esac
