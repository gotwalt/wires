#!/usr/bin/env bash
#
# Build the Node.js / TypeScript bindings for wires-native services
# into a package directory: the platform addon (wires.<platform>.node), the
# napi-rs loader (index.js), the types generated from bindings/node/lib.rs
# (index.d.ts), and package.json. Put it at node_modules/wires, or depend on
# it with `npm install <dir>`.
#
#   ./.scripts/build-node.sh [OUT_DIR]     default: target/node/wires
#
# Needs Node and npm; installs the napi CLI (bindings/node devDependencies)
# on first use.

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$repo/target/node/wires}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

cd "$repo/bindings/node"
[ -x node_modules/.bin/napi ] || npm install --no-audit --no-fund --silent >/dev/null
node_modules/.bin/napi build --platform --release -o "$out" >/dev/null 2>&1 || {
	node_modules/.bin/napi build --platform --release -o "$out"
	exit 1
}
cp package.json "$out/"
printf '%s\n' "$out"
