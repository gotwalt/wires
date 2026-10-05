#!/bin/sh
# wires service `vercel`: the Vercel CLI with a token the host holds
# (pattern B, see README.md). The caller's role picks which token file; the
# token never leaves the host.
set -eu
# shellcheck source-path=SCRIPTDIR source=../common.sh
. "$(dirname "$0")/../common.sh"

need_call
# Not `env` (`vercel env pull` writes a project's secrets) or `tokens`.
ALLOW="${ALLOW_COMMANDS:-list ls inspect logs api project domains}"
allow_command "$@"
map_role # MAPPED: the token file for this wires role
read_secret "$MAPPED"
scrub

# VERCEL_TOKEN, not --token: the docs recommend the variable because argv
# shows up in process lists.
export VERCEL_TOKEN="$SECRET"
export NO_COLOR=1
exec vercel "$@"
