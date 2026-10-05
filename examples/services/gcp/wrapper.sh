#!/bin/sh
# wires service `gcp`: gcloud as the calling person (pattern A, see
# README.md). The caller's ID token is exchanged through Workload Identity
# Federation for the service account their role maps to; the host holds no
# Google Cloud credential.
set -eu
# shellcheck source-path=SCRIPTDIR source=../common.sh
. "$(dirname "$0")/../common.sh"

need_call
ALLOW="${ALLOW_COMMANDS:-compute storage logging projects run container sql functions artifacts}"
allow_command "$@"
map_role # MAPPED: the service account email for this wires role
[ -n "${GCP_WORKLOAD_PROVIDER:-}" ] || die 1 "GCP_WORKLOAD_PROVIDER is unset"
token_file
scrub

# An external_account credential configuration (google.aip.dev/auth/4117)
# whose subject token is this call's ID token file.
cat >"$CALL_DIR/credentials.json" <<EOF
{
  "type": "external_account",
  "audience": "//iam.googleapis.com/$GCP_WORKLOAD_PROVIDER",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "token_url": "https://sts.googleapis.com/v1/token",
  "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/$MAPPED:generateAccessToken",
  "credential_source": { "file": "$TOKEN_FILE", "format": { "type": "text" } }
}
EOF
# gcloud's state lives in the call's directory, so nothing is shared
# between people.
export CLOUDSDK_CONFIG="$CALL_DIR/gcloud"
export CLOUDSDK_CORE_DISABLE_PROMPTS=1
export HOME="$CALL_DIR"
gcloud auth login --cred-file="$CALL_DIR/credentials.json" --quiet >"$CALL_DIR/login.log" 2>&1 || {
	cat "$CALL_DIR/login.log" >&2
	die 1 "gcloud auth login --cred-file failed"
}
exec gcloud "$@"
