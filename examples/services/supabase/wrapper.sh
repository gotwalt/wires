#!/bin/sh
# wires service `supabase`: the Supabase CLI with an access token the host
# holds (pattern B, see README.md). The caller's role picks which token
# file; the token never leaves the host.
set -eu
# shellcheck source-path=SCRIPTDIR source=../common.sh
. "$(dirname "$0")/../common.sh"

need_call
# Pairs, not words: `projects` alone would allow `projects delete`.
ALLOW="${ALLOW_COMMANDS:-projects:list functions:list}"
allow_command "$@"
map_role # MAPPED: the token file for this wires role
read_secret "$MAPPED"
scrub

export SUPABASE_ACCESS_TOKEN="$SECRET"
exec supabase "$@"
