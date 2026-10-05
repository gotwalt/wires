#!/bin/sh
# wires service `aws`: the AWS CLI as the calling person (pattern A, see
# README.md). The caller's ID token becomes a role session named after
# their email; the host holds no AWS credential.
set -eu
# shellcheck source-path=SCRIPTDIR source=../common.sh
. "$(dirname "$0")/../common.sh"

need_call
ALLOW="${ALLOW_COMMANDS:-sts s3 s3api ec2 logs cloudwatch lambda ecs dynamodb cloudformation}"
allow_command "$@"
map_role # MAPPED: the IAM role ARN for this wires role
token_file
session_name
scrub

# The CLI's own web-identity provider calls AssumeRoleWithWebIdentity with
# these three. HOME is the call's directory, so no ~/.aws config or cache is
# shared between people, and the instance role is never a fallback.
export AWS_ROLE_ARN="$MAPPED"
export AWS_WEB_IDENTITY_TOKEN_FILE="$TOKEN_FILE"
export AWS_ROLE_SESSION_NAME="$SESSION"
export AWS_EC2_METADATA_DISABLED=true
export HOME="$CALL_DIR"
exec aws "$@"
