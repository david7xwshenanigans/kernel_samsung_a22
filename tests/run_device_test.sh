#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TEST_BIN="$SCRIPT_DIR/test_backports_arm64"
REMOTE_TMP="/tmp/test_backports_arm64"
REMOTE_STAGE="/data/local/tmp/test_backports_arm64"

# ANSI Colors
RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[34m"
BOLD="\033[1m"
RESET="\033[0m"

log_info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
log_error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo -e "${BOLD}Usage:${RESET} $0 [TEST_OPTIONS]"
    echo ""
    echo "Deploys and executes the static ARM64 test binary on a connected Android device."
    echo "Bypasses /data/local/tmp noexec (NX) by staging and executing from /tmp using 'su'."
    echo ""
    echo -e "${BOLD}Options passed through to test_backports_arm64:${RESET}"
    echo "  -s, --suite <name>  Run only the specified test suite"
    echo "  -l, --list          List all available test suites on device"
    echo "  -h, --help          Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${RESET}"
    echo "  $0"
    echo "  $0 --suite io_uring"
    echo "  $0 --suite syscalls_sync_fs"
    echo "  $0 --list"
    exit 0
fi

# 1. Verify / Build ARM64 Static Binary
if [[ ! -f "$TEST_BIN" ]]; then
    log_info "Static binary not found. Building ARM64 test binary..."
    make -C "$SCRIPT_DIR" arm64
fi

log_ok "Using test binary: $TEST_BIN ($(du -h "$TEST_BIN" | awk '{print $1}'))"

# 2. Verify ADB Environment
if ! command -v adb >/dev/null 2>&1; then
    log_error "'adb' command not found in PATH."
    exit 1
fi

DEVICE_STATE="$(adb get-state 2>/dev/null || echo "offline")"
if [[ "$DEVICE_STATE" != "device" ]]; then
    log_warn "No authorized ADB device currently connected (state: $DEVICE_STATE)."
    log_info "Waiting for device..."
    adb wait-for-device
fi

DEVICE_MODEL="$(adb shell getprop ro.product.model 2>/dev/null || echo "Unknown")"
DEVICE_BUILD="$(adb shell getprop ro.build.display.id 2>/dev/null || echo "Unknown")"
log_ok "Connected to device: $DEVICE_MODEL ($DEVICE_BUILD)"

# 3. Verify su (root) access
log_info "Verifying root (su) access..."
if ! adb shell "su -c id" 2>/dev/null | grep -q "uid=0(root)"; then
    log_error "Root access via 'su' failed or was denied on device."
    exit 1
fi
log_ok "Root access confirmed (uid=0)."

KMSG_PID=""
KMSG_LOG="$REPO_ROOT/logs/device_test_kmsg_$(date +%Y%m%d_%H%M%S).log"

cleanup() {
    if [[ -n "$KMSG_PID" ]]; then
        kill "$KMSG_PID" 2>/dev/null || true
    fi
    adb shell "su -c 'rm -f $REMOTE_TMP'" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 4. Stage binary to /data/local/tmp and move to executable /tmp
log_info "Pushing binary to device staging area..."
adb push "$TEST_BIN" "$REMOTE_STAGE" >/dev/null

log_info "Moving binary to /tmp (bypassing /data/local/tmp noexec) and setting permissions..."
adb shell "su -c '
    mkdir -p /tmp
    if ! mountpoint -q /tmp 2>/dev/null; then
        mount -t tmpfs -o rw,exec,nosuid,nodev tmpfs /tmp 2>/dev/null || true
    fi
    cp $REMOTE_STAGE $REMOTE_TMP
    chmod 755 $REMOTE_TMP
    rm -f $REMOTE_STAGE
'"

# 5. Start background live kmsg streaming
mkdir -p "$REPO_ROOT/logs"
adb shell "su -c 'dmesg -w 2>/dev/null || cat /proc/kmsg 2>/dev/null'" > "$KMSG_LOG" 2>&1 &
KMSG_PID=$!
log_info "Live kernel log streaming active -> $KMSG_LOG"

# 6. Execute test suite on device with arguments passed through
log_info "Executing test suite on device..."
echo -e "${BOLD}===================================================================${RESET}"

set +e
adb shell -t "su -c '$REMOTE_TMP $*'"
TEST_EXIT_CODE=$?
set -e

echo -e "${BOLD}===================================================================${RESET}"

# Stop kmsg capture
if [[ -n "$KMSG_PID" ]]; then
    kill "$KMSG_PID" 2>/dev/null || true
    KMSG_PID=""
fi

if [[ $TEST_EXIT_CODE -eq 0 ]]; then
    log_ok "Device test execution completed successfully (exit code 0)."
else
    log_error "Device test execution reported failures (exit code $TEST_EXIT_CODE)."
    log_info "Review kernel log for details: $KMSG_LOG"
fi

exit $TEST_EXIT_CODE
