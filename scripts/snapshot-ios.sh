#!/usr/bin/env bash
#
# snapshot-ios.sh — drive the WiresUITests/SnapshotSweep matrix.
#
# Usage:
#   scripts/snapshot-ios.sh [--fixture NAME] [--device UDID]
#                           [--keep-derived]
#
# Outputs:
#   Wires/screenshots/<run-id>/<flow>/<short>-<appearance>.png
#   Wires/screenshots/latest → <run-id>      (symlink)
#
# Exit non-zero on missing screenshots or test failures.

set -euo pipefail

# ----- Resolve repo root (works from any cwd inside the repo) ---------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# ----- Defaults -------------------------------------------------------
DEFAULT_UDID="161DAE86-C4C7-47FE-B25E-1FAF251F93F6"
DEVICE_UDID="$DEFAULT_UDID"
FIXTURE_FILTER=""
KEEP_DERIVED="0"
BUNDLE_ID="com.talmage.Wires"

# ----- Parse flags ----------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fixture)
      FIXTURE_FILTER="$2"
      shift 2
      ;;
    --device)
      DEVICE_UDID="$2"
      shift 2
      ;;
    --keep-derived)
      KEEP_DERIVED="1"
      shift
      ;;
    --help|-h)
      sed -n '2,/^$/p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown flag: $1" >&2
      exit 64
      ;;
  esac
done

# ----- Verify simulator exists ----------------------------------------
if ! xcrun simctl list devices | grep -q "$DEVICE_UDID"; then
  # Fall back to matching the default device by name + runtime.
  FALLBACK_UDID="$(
    xcrun simctl list devices available -j |
      python3 -c '
import json, sys
data = json.load(sys.stdin)
for runtime, devices in data["devices"].items():
    if "iOS-26" not in runtime: continue
    for d in devices:
        if d.get("name") == "iPhone 17 Pro" and d.get("isAvailable", False):
            print(d["udid"])
            sys.exit(0)
'
  )"
  if [[ -z "$FALLBACK_UDID" ]]; then
    echo "Boot iPhone 17 Pro (iOS 26.x) in Simulator.app or install the iOS 26 simulator runtime." >&2
    exit 65
  fi
  echo "Default UDID not present; using fallback iPhone 17 Pro: $FALLBACK_UDID" >&2
  DEVICE_UDID="$FALLBACK_UDID"
fi

# ----- Boot if needed -------------------------------------------------
echo "Booting simulator $DEVICE_UDID …"
xcrun simctl bootstatus "$DEVICE_UDID" -b >/dev/null

# ----- Pre-grant camera permission ------------------------------------
# The bundle declares NSCameraUsageDescription, so iOS preflights a
# permission dialog on first launch even though fixture mode renders
# the placeholder. Grant proactively so the dialog never appears on
# top of seeded fixture screens.
xcrun simctl privacy "$DEVICE_UDID" grant camera "$BUNDLE_ID" 2>/dev/null || true

# ----- Compute run dir + export env for the UITest --------------------
# xcodebuild forwards variables prefixed with TEST_RUNNER_ to the
# simulator-side UITest runner process (with the prefix stripped).
# Host-side env (no prefix) is *not* visible to the test runner.
RUN_ID="$(date +%Y-%m-%d-%H%M)"
RUN_DIR="$REPO_ROOT/Wires/screenshots/$RUN_ID"
mkdir -p "$RUN_DIR"
export TEST_RUNNER_WIRES_SCREENSHOT_DIR="$RUN_DIR"
export TEST_RUNNER_WIRES_RUN_ID="$RUN_ID"

# ----- Build the -only-testing argument -------------------------------
if [[ -n "$FIXTURE_FILTER" ]]; then
  # Translate fixture name (e.g. bootstrap_scan_denied) to test method name.
  ONLY_TEST="WiresUITests/SnapshotSweep/test_${FIXTURE_FILTER}"
else
  ONLY_TEST="WiresUITests/SnapshotSweep"
fi

XCRESULT="$RUN_DIR/.xcresult"
echo "Running snapshot sweep → $RUN_DIR"
set +e
xcodebuild test \
  -project Wires/Wires.xcodeproj \
  -scheme Wires \
  -destination "platform=iOS Simulator,id=$DEVICE_UDID" \
  -only-testing:"$ONLY_TEST" \
  -resultBundlePath "$XCRESULT" \
  -quiet
TEST_EXIT=$?
set -e

# ----- Write .meta.json ----------------------------------------------
APP_COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
HOST_MACOS="$(sw_vers -productVersion 2>/dev/null || echo unknown)"
SIM_RUNTIME="$(xcrun simctl list runtimes available | grep -i 'iOS' | head -1 | sed 's/^[[:space:]]*//')"
cat > "$RUN_DIR/.meta.json" <<JSON
{
  "run_id": "$RUN_ID",
  "device_udid": "$DEVICE_UDID",
  "simulator_runtime": "$SIM_RUNTIME",
  "app_commit": "$APP_COMMIT",
  "host_macos": "$HOST_MACOS",
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON

# ----- Refresh `latest` symlink atomically ---------------------------
# `ln -sfn` on macOS replaces an existing symlink in place. The previous
# `ln -sfn; mv -f` dance was a no-op because `mv -f latest` follows the
# existing symlink and moves the source *into* the target directory.
cd "$REPO_ROOT/Wires/screenshots"
ln -sfn "$RUN_ID" latest
cd "$REPO_ROOT"

# ----- Print manifest --------------------------------------------------
echo
echo "Manifest:"
find "$RUN_DIR" -name '*.png' -type f | sort | sed "s|^$RUN_DIR/|  |"

# ----- Clean DerivedData unless asked to keep -------------------------
if [[ "$KEEP_DERIVED" == "0" ]]; then
  rm -rf "$XCRESULT" 2>/dev/null || true
fi

# ----- Done ----------------------------------------------------------
PNG_COUNT="$(find "$RUN_DIR" -name '*.png' -type f | wc -l | tr -d ' ')"
echo
echo "Run: $RUN_ID"
echo "PNGs: $PNG_COUNT"
echo "Path: $RUN_DIR"
echo "Symlink: $REPO_ROOT/Wires/screenshots/latest"

if [[ "$TEST_EXIT" != "0" ]]; then
  echo "WARNING: xcodebuild test exited $TEST_EXIT — some fixtures may be missing." >&2
  exit "$TEST_EXIT"
fi
