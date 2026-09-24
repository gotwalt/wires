#!/usr/bin/env bash
#
# Build the Python bindings for wires-native services (card 33): the
# `wires-ffi` cdylib plus its UniFFI-generated `wires.py`, side by side in
# one directory that goes on PYTHONPATH.
#
#   ./.scripts/build-python.sh [OUT_DIR]     default: target/python
#
# Then: PYTHONPATH=target/python python3 bindings/python/examples/kv.py …

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"
out="${1:-$repo/target/python}"

case "$(uname -s)" in
Darwin) lib=libwires_ffi.dylib ;;
*) lib=libwires_ffi.so ;;
esac

cargo build -q --release -p wires-ffi
mkdir -p "$out"
cargo run -q --release -p wires-ffi --bin uniffi-bindgen -- \
	generate --library "target/release/$lib" --language python --out-dir "$out" >/dev/null
cp "target/release/$lib" "$out/"
printf '%s\n' "$out"
