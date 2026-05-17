#!/usr/bin/env bash
#
# Cross-compile `wires-uniffi` for the three iOS Rust targets, lipo-merge the
# two simulator slices, generate Swift bindings with `uniffi-bindgen`, and
# package the whole thing as an xcframework that the Wires Xcode project
# consumes via the local `Wires/WiresKit` SwiftPM package.
#
# Prerequisite (one-time per developer):
#
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#
# Run from anywhere in the repo:
#
#   scripts/build-ioskit.sh
#
# Outputs:
#   - Wires/WiresKit/Frameworks/wires.xcframework
#   - Wires/WiresKit/Sources/WiresKit/wires_uniffi.swift
#
# Both are build artifacts; .gitignore'd inside Wires/WiresKit/.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET_DIR="$ROOT/target"
KIT_DIR="$ROOT/Wires/WiresKit"
FRAMEWORK_DIR="$KIT_DIR/Frameworks"
SOURCES_DIR="$KIT_DIR/Sources/WiresKit"

REQUIRED_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)

# --- pre-flight ---
missing=()
installed="$(rustup target list --installed)"
for t in "${REQUIRED_TARGETS[@]}"; do
  if ! grep -q "^${t}$" <<<"$installed"; then
    missing+=("$t")
  fi
done
if (( ${#missing[@]} > 0 )); then
  echo "Missing Rust iOS targets: ${missing[*]}"
  echo "Install with:"
  echo "  rustup target add ${missing[*]}"
  exit 1
fi

mkdir -p "$FRAMEWORK_DIR" "$SOURCES_DIR"

# --- compile per target ---
echo "==> Building wires-uniffi for iOS targets"
for T in "${REQUIRED_TARGETS[@]}"; do
  echo "  - $T"
  cargo build --release --target "$T" -p wires-uniffi
done

# --- lipo the two simulator slices into one fat library ---
echo "==> Lipo-ing simulator slices"
SIM_DIR="$TARGET_DIR/ios-sim-fat/release"
mkdir -p "$SIM_DIR"
lipo -create \
  "$TARGET_DIR/aarch64-apple-ios-sim/release/libwires_uniffi.a" \
  "$TARGET_DIR/x86_64-apple-ios/release/libwires_uniffi.a" \
  -output "$SIM_DIR/libwires_uniffi.a"

# --- generate Swift bindings + module headers ---
echo "==> Generating Swift bindings"
HEADERS_DIR="$TARGET_DIR/uniffi-headers"
rm -rf "$HEADERS_DIR"
mkdir -p "$HEADERS_DIR/include"
cargo run --release -p wires-uniffi --bin uniffi-bindgen -- \
  generate \
  --library "$TARGET_DIR/aarch64-apple-ios/release/libwires_uniffi.a" \
  --language swift \
  --out-dir "$HEADERS_DIR"

# Move headers + modulemap into a per-slice include dir for xcframework.
shopt -s nullglob
mv "$HEADERS_DIR"/*.h "$HEADERS_DIR/include/" 2>/dev/null || true
for mm in "$HEADERS_DIR"/*.modulemap; do
  mv "$mm" "$HEADERS_DIR/include/module.modulemap"
  break
done
shopt -u nullglob

# --- assemble xcframework ---
echo "==> Assembling xcframework"
rm -rf "$FRAMEWORK_DIR/wires.xcframework"
xcodebuild -create-xcframework \
  -library "$TARGET_DIR/aarch64-apple-ios/release/libwires_uniffi.a" \
  -headers "$HEADERS_DIR/include" \
  -library "$SIM_DIR/libwires_uniffi.a" \
  -headers "$HEADERS_DIR/include" \
  -output "$FRAMEWORK_DIR/wires.xcframework"

# --- copy Swift bindings into the WiresKit SwiftPM package sources ---
echo "==> Copying Swift bindings into WiresKit/Sources"
rm -f "$SOURCES_DIR"/*.swift
cp "$HEADERS_DIR"/*.swift "$SOURCES_DIR/"

echo
echo "Done. Built $FRAMEWORK_DIR/wires.xcframework"
echo "      Bindings $SOURCES_DIR/"
