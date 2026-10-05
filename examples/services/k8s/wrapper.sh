#!/bin/sh
# wires service `k8s`: kubectl as the calling person (pattern A, see
# README.md). An API server that trusts the IdP takes the caller's ID token
# as a bearer token and applies RBAC to their email; the host holds no
# cluster credential.
set -eu
# shellcheck source-path=SCRIPTDIR source=../common.sh
. "$(dirname "$0")/../common.sh"

need_call
ALLOW="${ALLOW_COMMANDS:-get describe logs top events explain api-resources auth rollout}"
allow_command "$@"
map_role # MAPPED: the default namespace for this wires role
[ -n "${K8S_SERVER:-}" ] || die 1 "K8S_SERVER is unset"
[ -n "${K8S_CA_FILE:-}" ] || die 1 "K8S_CA_FILE is unset"
token_file
scrub

# A kubeconfig for this call alone. `tokenFile` keeps the token out of
# kubectl's argv (where `--token` would put it).
cat >"$CALL_DIR/kubeconfig" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: wires
  cluster:
    server: $K8S_SERVER
    certificate-authority: $K8S_CA_FILE
users:
- name: wires-caller
  user:
    tokenFile: $TOKEN_FILE
contexts:
- name: wires
  context:
    cluster: wires
    user: wires-caller
    namespace: $MAPPED
current-context: wires
EOF
export KUBECONFIG="$CALL_DIR/kubeconfig"
export HOME="$CALL_DIR"
exec kubectl "$@"
