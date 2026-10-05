#!/bin/sh
# wires service `cloudflare`: wrangler with an API token the host holds
# (pattern B, see README.md). The caller's role picks which token file; the
# token never leaves the host.
set -eu
# shellcheck source-path=SCRIPTDIR source=../common.sh
. "$(dirname "$0")/../common.sh"

need_call
ALLOW="${ALLOW_COMMANDS:-d1 deployments versions kv r2 tail}"
allow_command "$@"
map_role # MAPPED: the token file for this wires role
read_secret "$MAPPED"
scrub

# CLOUDFLARE_ACCOUNT_ID comes from host.json's env.
export CLOUDFLARE_API_TOKEN="$SECRET"
export WRANGLER_SEND_METRICS=false
exec wrangler "$@"
