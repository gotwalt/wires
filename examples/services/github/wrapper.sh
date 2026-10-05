#!/bin/sh
# wires service `github`: gh with a token the host holds (pattern B, see
# README.md). The caller's role picks which token file; the token never
# leaves the host.
set -eu
# shellcheck source-path=SCRIPTDIR source=../common.sh
. "$(dirname "$0")/../common.sh"

need_call
# Not `auth` (`gh auth token` prints the token), `alias`, `extension` or
# `config`, which can run or install commands.
ALLOW="${ALLOW_COMMANDS:-api issue pr repo run search release workflow label}"
allow_command "$@"
map_role # MAPPED: the token file for this wires role
read_secret "$MAPPED"
scrub

export GH_TOKEN="$SECRET"
export GH_PROMPT_DISABLED=1
export NO_COLOR=1
exec gh "$@"
