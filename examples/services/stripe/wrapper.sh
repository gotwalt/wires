#!/bin/sh
# wires service `stripe`: the Stripe CLI with a restricted key the host
# holds (pattern B, see README.md). The caller's role picks which key file;
# the key never leaves the host.
set -eu
# shellcheck source-path=SCRIPTDIR source=../common.sh
. "$(dirname "$0")/../common.sh"

need_call
# Reads only, by pair: not `config` (it shows keys), `listen` or `trigger`.
ALLOW="${ALLOW_COMMANDS:-customers:list customers:retrieve charges:list charges:retrieve payment_intents:list payment_intents:retrieve invoices:list invoices:retrieve events:list events:retrieve balance:retrieve}"
allow_command "$@"
map_role # MAPPED: the key file for this wires role
read_secret "$MAPPED"
session_name
scrub

export STRIPE_API_KEY="$SECRET"
# Stripe shows the CLI's device name in the Dashboard: name the person.
export STRIPE_DEVICE_NAME="wires:$SESSION"
exec stripe "$@"
