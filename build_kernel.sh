#!/usr/bin/env bash
# =============================================================================
# AI AGENT CONTEXT — read this before doing anything with this script
# =============================================================================
#
# PURPOSE
#   Builds a custom Android kernel for the Samsung Galaxy A22 (SM-A225F/M),
#   which runs a MediaTek Dimensity MT6768 SoC. The output is a compressed
#   kernel Image that can be flashed via AnyKernel3 (a zip-based flasher).
#
# DEVICE / KERNEL CONTEXT
#   Device       : Samsung Galaxy A22 (codename: a22, a22x)
#   SoC          : MediaTek MT6768 (Helio G80), arm64
#   Base kernel  : Linux 4.14.x (Android kernel LTS branch)
#   Kernel tree  : wherever this script lives (PREFIX=$(pwd) at runtime)
#   Defconfig    : a22_wmk_defconfig  (Samsung base + KernelSU + SUSFS patches)
#   KernelSU     : yes — "ksunext" variant with SUSFS overlay
#   Out-of-tree  : build outputs go to <tree>/out/, NOT in-tree
#
# TOOLCHAIN
#   Compiler     : LLVM/Clang (custom build "clang-wmk", searched via CLANG_SEARCH_DIRS)
#   Linker       : ld.lld (part of the LLVM toolchain, NOT GNU ld)
#   Cross targets: aarch64-linux-gnu- (64-bit), arm-linux-gnueabi- (32-bit compat)
#   The script searches CLANG_SEARCH_DIRS in order and fails with EC_TOOLCHAIN
#   if no valid toolchain is found.
#
# BUILD PIPELINE (phases in order)
#   1. preflight   — host tool checks, disk space, source zip presence
#   2. toolchain   — locate and verify LLVM toolchain
#   3. defconfig   — `make a22_wmk_defconfig` writes <out>/.config
#   4. build       — `make` compiles the kernel; Image lands in <out>/arch/arm64/boot/
#   5. copy_image  — Image is copied to <tree>/arch/arm64/boot/Image (AnyKernel3 expects it here)
#   6. zip         — (optional, --zip) packages Image into a flashable AnyKernel3 zip
#
# EXIT CODES — branch on these, do NOT parse log text
#   0  EC_OK           Everything succeeded
#   1  EC_BAD_ARGS     Invalid CLI arguments
#   2  EC_TOOLCHAIN    No valid LLVM toolchain found
#   3  EC_PREFLIGHT    Missing host tool, low disk, or missing source zip
#   4  EC_CONFIG       `make defconfig` failed
#   5  EC_BUILD        `make` compilation failed (see error log for details)
#   6  EC_POST_COPY    Kernel Image not found after build (unexpected)
#   7  EC_ZIP          AnyKernel3 zip creation failed
#   130 EC_INTERRUPTED  SIGINT or SIGTERM received
#
# KEY FLAGS
#   --json      Emit a single JSON object to stdout summarising the build result.
#               Use this when calling from an agent or CI pipeline. The JSON
#               includes status, exit_code, failed_phase, git info, image/zip
#               paths and sizes, build/error log paths, and per-phase results.
#   --dry-run   Run preflight + toolchain + defconfig; skip compilation and post
#               steps. Safe to use for environment validation.
#   --zip       Create a flashable AnyKernel3 zip after a successful build.
#               Requires SOURCE_ZIP to exist (see PATHS below). Off by default.
#   --quiet     Suppress make output on the terminal; everything still goes to
#               the build log. Errors are still shown.
#   --keep-going  Pass -k to make: keep compiling past the first error. Useful
#               for auditing how many things are broken at once.
#   --jobs N    Parallel make jobs (default: nproc).
#
# PATHS (all relative to the kernel tree root unless noted)
#   Source zip   : $SOURCE_ZIP (set near top of script)
#                  A pre-built AnyKernel3 zip WITHOUT a kernel Image inside.
#                  The script copies this and injects the freshly built Image.
#   AnyKernel3   : <tree>/AnyKernel3/  — output zips are written here
#   Build log    : <tree>/logs/build_<timestamp>.log  — full make output
#   Error log    : <tree>/logs/error_<timestamp>.log  — errors extracted from build log
#   Kernel Image : <tree>/out/arch/arm64/boot/Image  (primary output)
#                  <tree>/arch/arm64/boot/Image       (copy for AnyKernel3)
#
# COMMON FAILURE MODES AN AGENT SHOULD KNOW ABOUT
#   EC_BUILD + "arch_has_hw_pte_young" in error log
#       → MGLRU backport conflict in mm/vmscan.c; the function is declared both
#         statically (backport) and implicitly (caller). Fix: add a forward
#         declaration or make the inline non-static before its first use.
#   EC_BUILD + "undefined reference to" in error log
#       → Usually a missing Kconfig symbol or a driver using an out-of-tree
#         symbol not exported via EXPORT_SYMBOL.
#   EC_TOOLCHAIN
#       → The clang-wmk toolchain is missing or incomplete. Check CLANG_SEARCH_DIRS
#         at the top of the script, then re-clone or rebuild the toolchain.
#   EC_PREFLIGHT + "Source AnyKernel3 zip not found"
#       → SOURCE_ZIP (set near top of script) points to a missing file. Locate
#         the zip or build without --zip.
#
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# EXIT CODES — every failure path returns a distinct code so an agent can
# branch on exactly what went wrong without parsing log text.
# -----------------------------------------------------------------------------
readonly EC_OK=0
readonly EC_BAD_ARGS=1
readonly EC_TOOLCHAIN=2
readonly EC_PREFLIGHT=3
readonly EC_CONFIG=4
readonly EC_BUILD=5
readonly EC_POST_COPY=6
readonly EC_ZIP=7
readonly EC_PUBLISH=8
readonly EC_INTERRUPTED=130

# -----------------------------------------------------------------------------
# DEFAULTS
# -----------------------------------------------------------------------------
QUIET_MODE=false
KEEP_GOING=false
CREATE_ZIP=false
JSON_MODE=false        # --json  : emit a machine-readable summary to stdout
DRY_RUN=false          # --dry-run: validate everything, skip actual make
SKIP_UPLOAD=false      # --skip-upload: do not publish to the artifact registry

DEFCONFIG="a22_wmk_defconfig"
JOBS=$(nproc 2>/dev/null || echo 4)
ARCH=arm64
SOURCE_ZIP="/home/zears/Documents/WMKernel-ksunext-susfs.zip"
CLANG_SEARCH_DIRS=(
    "/home/zears/clang-wmk"
    "${PWD}/toolchain/clang/host/linux-x86/clang-r383902"
)

# Build state — populated as the script runs, used in the final summary
BUILD_PHASE="init"
BUILD_STATUS="unknown"
declare -A PHASE_RESULTS=()   # phase -> ok|fail|skip
readonly ALL_PHASES=("preflight" "toolchain" "defconfig" "build" "copy_image" "zip" "publish")


# -----------------------------------------------------------------------------
# ARGUMENT PARSING
# -----------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  -q, --quiet       Suppress make output (errors still shown)
  -k, --keep-going  Pass -k to make (continue past first error)
  -z, --zip         Create a flashable AnyKernel3 zip after a successful build
  -j, --jobs N      Parallel make jobs (default: $(nproc))
      --json        Emit a JSON summary line to stdout on completion/failure
      --dry-run     Validate environment and config; skip compilation
      --skip-upload Skip uploading the final zip to the artifact registry
  -h, --help        Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -q|--quiet)      QUIET_MODE=true;  shift ;;
        -k|--keep-going) KEEP_GOING=true;  shift ;;
        -z|--zip)        CREATE_ZIP=true;  shift ;;
        --json)          JSON_MODE=true;   shift ;;
        --dry-run)       DRY_RUN=true;     shift ;;
        --skip-upload)   SKIP_UPLOAD=true; shift ;;
        -j|--jobs)
            [[ "${2:-}" =~ ^[0-9]+$ ]] || { echo "ERROR: --jobs requires a number"; exit $EC_BAD_ARGS; }
            JOBS="$2"; shift 2 ;;
        -h|--help)       usage; exit $EC_OK ;;
        *) echo "ERROR: Unknown option: $1"; usage; exit $EC_BAD_ARGS ;;
    esac
done

# -----------------------------------------------------------------------------
# PATHS (derived after arg parsing so PWD is stable)
# -----------------------------------------------------------------------------
PREFIX="$(pwd)"
OUT_DIR="$PREFIX/out"
LOG_DIR="$PREFIX/logs"
BUILD_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BUILD_LOG="$LOG_DIR/build_${BUILD_TIMESTAMP}.log"
ERROR_LOG="$LOG_DIR/error_${BUILD_TIMESTAMP}.log"
KERNEL_IMAGE_OUT="$OUT_DIR/arch/arm64/boot/Image"
KERNEL_IMAGE_TREE="$PREFIX/arch/arm64/boot/Image"
ANYKERNEL_DIR="$PREFIX/AnyKernel3"

mkdir -p "$LOG_DIR"

# -----------------------------------------------------------------------------
# LOGGING
# All log functions write to both the terminal and BUILD_LOG.
# In JSON mode the human-readable prefix is still written to the log file —
# only the final JSON summary goes to stdout so agents can reliably parse it.
# -----------------------------------------------------------------------------
_ts() { date '+%Y-%m-%dT%H:%M:%S'; }

_log() {
    local level="$1"; shift
    local msg="$*"
    local line="[$(_ts)] [$level] $msg"
    echo "$line" >> "$BUILD_LOG"
    if [[ "$JSON_MODE" == false ]]; then
        echo "$line"
    fi
}

log_info()    { _log "INFO"    "$@"; }
log_ok()      { _log "OK"      "$@"; }
log_warn()    { _log "WARN"    "$@"; }
log_error()   { _log "ERROR"   "$@"; echo "[$(_ts)] [ERROR] $*" >> "$ERROR_LOG"; }
log_section() { _log "SECTION" "=== $* ==="; }

# Print to terminal regardless of JSON mode (for interactive prompts etc.)
log_tty() { echo "$*" >/dev/tty 2>/dev/null || echo "$*"; }

# -----------------------------------------------------------------------------
# JSON SUMMARY
# Emitted exactly once: at normal exit or on trapped error.
# Fields are intentionally flat so agents don't need deep parsing.
# -----------------------------------------------------------------------------
_json_value() {
    # Cheap JSON string escape (handles the common cases)
    echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

emit_json_summary() {
    local status="$1"      # success | failed
    local exit_code="$2"
    local failed_phase="${3:-}"
    local end_ts
    end_ts="$(_ts)"

    local git_commit git_branch kernel_version zip_path="" zip_size="" image_size=""
    git_commit="$(git -C "$PREFIX" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    git_branch="$(git -C "$PREFIX" symbolic-ref --short HEAD 2>/dev/null || echo 'unknown')"
    kernel_version="$(make -s -C "$PREFIX" O="$OUT_DIR" kernelversion 2>/dev/null || echo 'unknown')"

    if [[ -f "$KERNEL_IMAGE_TREE" ]]; then
        image_size="$(du -h "$KERNEL_IMAGE_TREE" | cut -f1)"
    fi

    # Find the most recent zip if it was created
    if [[ -d "$ANYKERNEL_DIR" ]]; then
        zip_path="$(ls -t "$ANYKERNEL_DIR"/WMKernel-*.zip 2>/dev/null | head -1 || true)"
        if [[ -n "$zip_path" && -f "$zip_path" ]]; then
            zip_size="$(du -h "$zip_path" | cut -f1)"
        fi
    fi

    # Build phase_results JSON object
    local phases_json="{"
    local first=true
    for phase in "${ALL_PHASES[@]}"; do
        local res="${PHASE_RESULTS[$phase]:-pending}"
        [[ "$first" == true ]] || phases_json+=","
        phases_json+="\"$(_json_value "$phase")\":\"$(_json_value "$res")\"" 
        first=false
    done
    phases_json+="}"

    cat <<JSON
{
  "status": "$(_json_value "$status")",
  "exit_code": $exit_code,
  "failed_phase": "$(_json_value "$failed_phase")",
  "build_timestamp": "$BUILD_TIMESTAMP",
  "end_timestamp": "$end_ts",
  "git_commit": "$(_json_value "$git_commit")",
  "git_branch": "$(_json_value "$git_branch")",
  "kernel_version": "$(_json_value "$kernel_version")",
  "defconfig": "$(_json_value "$DEFCONFIG")",
  "arch": "$ARCH",
  "jobs": $JOBS,
  "dry_run": $DRY_RUN,
  "kernel_image": "$(_json_value "${image_size}")",
  "zip_path": "$(_json_value "$zip_path")",
  "zip_size": "$(_json_value "$zip_size")",
  "build_log": "$(_json_value "$BUILD_LOG")",
  "error_log": "$(_json_value "$ERROR_LOG")",
  "phases": $phases_json
}
JSON
}

# -----------------------------------------------------------------------------
# TRAP — runs on any unhandled error, SIGINT, or SIGTERM.
# Guarantees JSON is always emitted even on unexpected crashes.
# -----------------------------------------------------------------------------
_TRAP_EXIT_CODE=$EC_OK
_cleanup() {
    local code=${1:-$?}
    # Only fire once
    trap - EXIT ERR INT TERM

    # Map signals to exit codes
    if [[ $code -eq 130 ]]; then
        BUILD_PHASE="interrupted"
        PHASE_RESULTS["interrupted"]="fail"
    fi

    BUILD_STATUS="failed"

    if [[ "$JSON_MODE" == true ]]; then
        emit_json_summary "failed" "$code" "$BUILD_PHASE"
    else
        log_error "Build failed in phase: $BUILD_PHASE (exit code: $code)"
        log_error "Error log: $ERROR_LOG"
        log_error "Build log: $BUILD_LOG"
    fi

    exit "$code"
}

trap '_cleanup $?' EXIT ERR
trap '_cleanup $EC_INTERRUPTED' INT TERM

# Disarm the trap on intentional success
_success_exit() {
    trap - EXIT ERR INT TERM
    BUILD_STATUS="success"
    if [[ "$JSON_MODE" == true ]]; then
        emit_json_summary "success" "$EC_OK" ""
    fi
    exit $EC_OK
}

# Helper: mark a phase result and update current phase
phase_start() { BUILD_PHASE="$1"; log_section "$1"; }
phase_ok()    { PHASE_RESULTS["$BUILD_PHASE"]="ok";   log_ok   "$BUILD_PHASE completed"; }
phase_skip()  { PHASE_RESULTS["$BUILD_PHASE"]="skip"; log_info "$BUILD_PHASE skipped"; }
phase_fail()  { PHASE_RESULTS["$BUILD_PHASE"]="fail"; }  # trap will handle exit

# -----------------------------------------------------------------------------
# PRE-FLIGHT CHECKS
# Validate everything that can be validated before touching make.
# Fail fast with a specific exit code so agents know exactly what's missing.
# -----------------------------------------------------------------------------
phase_start "preflight"

_preflight_errors=0

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        log_error "Required command not found: $1"
        (( _preflight_errors++ )) || true
    fi
}

check_disk() {
    local path="$1" required_gb="$2"
    local available_kb
    available_kb="$(df -k "$path" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)"
    local available_gb=$(( available_kb / 1024 / 1024 ))
    if (( available_gb < required_gb )); then
        log_warn "Low disk space at $path: ${available_gb}GB available (recommend ${required_gb}GB+)"
    fi
}

# Required host tools
for cmd in make zip git ccache; do
    check_cmd "$cmd"
done

# Disk space sanity
check_disk "$PREFIX" 10

# Source zip only matters if --zip was requested
if [[ "$CREATE_ZIP" == true && ! -f "$SOURCE_ZIP" ]]; then
    log_error "Source AnyKernel3 zip not found: $SOURCE_ZIP (required with --zip)"
    (( _preflight_errors++ )) || true
fi

if (( _preflight_errors > 0 )); then
    phase_fail
    exit $EC_PREFLIGHT
fi

phase_ok

# -----------------------------------------------------------------------------
# TOOLCHAIN DETECTION
# -----------------------------------------------------------------------------
phase_start "toolchain"

verify_toolchain() {
    local tc_path="$1"
    [[ -z "$tc_path" || ! -d "$tc_path/bin" ]] && return 1

    local required_tools=(clang llvm-ar llvm-nm ld.lld llvm-objcopy llvm-objdump llvm-strip)
    local missing=()
    for tool in "${required_tools[@]}"; do
        [[ -x "$tc_path/bin/$tool" ]] || missing+=("$tool")
    done

    if (( ${#missing[@]} > 0 )); then
        log_warn "Toolchain at $tc_path missing: ${missing[*]}"
        return 1
    fi

    # Smoke-test clang
    "$tc_path/bin/clang" --version &>/dev/null || return 1
    return 0
}

CLANG_DIR=""
for candidate in "${CLANG_SEARCH_DIRS[@]}"; do
    if verify_toolchain "$candidate"; then
        CLANG_DIR="$candidate"
        log_ok "Toolchain: $CLANG_DIR"
        CLANG_VERSION="$("$CLANG_DIR/bin/clang" --version | head -1)"
        log_info "Clang: $CLANG_VERSION"
        break
    fi
done

if [[ -z "$CLANG_DIR" ]]; then
    # Last resort: interactive prompt (not useful in non-TTY agent environments)
    if [[ -t 0 ]]; then
        log_warn "No toolchain found in default locations. Enter path manually."
        for attempt in 1 2 3; do
            read -rp "Toolchain path (attempt $attempt/3, or 'quit'): " user_path
            [[ "$user_path" == "quit" || "$user_path" == "q" ]] && exit $EC_OK
            user_path="${user_path/#\~/$HOME}"
            if verify_toolchain "$user_path"; then
                CLANG_DIR="$user_path"
                break
            fi
            log_error "Verification failed: $user_path"
        done
    fi

    if [[ -z "$CLANG_DIR" ]]; then
        phase_fail
        log_error "No valid LLVM toolchain found. Set CLANG_SEARCH_DIRS or provide one interactively."
        exit $EC_TOOLCHAIN
    fi
fi

export PATH="$CLANG_DIR/bin:$PATH"
export ARCH="$ARCH"

# Compiler wrapper
CC_CMD="clang"
if command -v ccache &>/dev/null; then
    CC_CMD="ccache clang"
    ccache -z &>/dev/null
    log_info "ccache: enabled"
else
    log_warn "ccache not found — builds will be slower"
fi
local_toolchain="$(clang --version | head -n 1)"

phase_ok

# -----------------------------------------------------------------------------
# KERNEL CONFIGURATION
# -----------------------------------------------------------------------------
phase_start "defconfig"

log_info "defconfig: $DEFCONFIG"

if [[ "$DRY_RUN" == false ]]; then
    if ! make -C "$PREFIX" O="$OUT_DIR" ARCH="$ARCH" "$DEFCONFIG" \
            >> "$BUILD_LOG" 2>&1; then
        phase_fail
        exit $EC_CONFIG
    fi
else
    log_info "[dry-run] Skipping defconfig"
fi

phase_ok

# -----------------------------------------------------------------------------
# KERNEL COMPILATION
# -----------------------------------------------------------------------------
phase_start "build"

log_info "jobs=$JOBS arch=$ARCH compiler=$CC_CMD keep-going=$KEEP_GOING"

MAKE_FLAGS=(
    -j"$JOBS"
    ARCH="$ARCH"
    SUBARCH="$ARCH"
    O="$OUT_DIR"
    CC="$CC_CMD"
    AR="llvm-ar"
    NM="llvm-nm"
    LD="ld.lld"
    OBJCOPY="llvm-objcopy"
    OBJDUMP="llvm-objdump"
    STRIP="llvm-strip"
    CLANG_TRIPLE="aarch64-linux-gnu-"
    CROSS_COMPILE="aarch64-linux-gnu-"
    CROSS_COMPILE_ARM32="arm-linux-gnueabi-"
    CROSS_COMPILE_COMPAT="arm-linux-gnueabi-"
    LLVM=1
    LLVM_IAS=1
    INSTALL_MOD_STRIP=1
    KCFLAGS="-w"
    CONFIG_SECTION_MISMATCH_WARN_ONLY=y
    KBUILD_BUILD_USER="$(git -C "$PREFIX" rev-parse --short HEAD 2>/dev/null | cut -c1-7 || echo 'unknown')"
    KBUILD_BUILD_HOST="$(git -C "$PREFIX" symbolic-ref --short HEAD 2>/dev/null || echo 'unknown')"
)

[[ "$KEEP_GOING" == true ]] && MAKE_FLAGS+=(-k)

if [[ "$DRY_RUN" == true ]]; then
    log_info "[dry-run] Skipping compilation"
    phase_skip
else
    if [[ "$QUIET_MODE" == true ]]; then
        # Quiet: only errors reach the terminal; everything goes to the log
        if ! make -C "$PREFIX" "${MAKE_FLAGS[@]}" 2>&1 \
                | tee -a "$BUILD_LOG" \
                | grep -E "^(error:|../.*error:|make\[|ld:)" >&2; then
            # grep exit 1 (no matches) should not abort — only make failure matters
            true
        fi
        # Re-run make to capture the real exit code (tee ate it above)
        # Better: use a temp file for the exit code
        make -C "$PREFIX" "${MAKE_FLAGS[@]}" >> "$BUILD_LOG" 2>&1 || {
            phase_fail
            log_error "Compilation failed. See $BUILD_LOG and $ERROR_LOG"
            grep -E "error:" "$BUILD_LOG" >> "$ERROR_LOG" 2>/dev/null || true
            exit $EC_BUILD
        }
    else
        if ! make -C "$PREFIX" "${MAKE_FLAGS[@]}" 2>&1 | tee -a "$BUILD_LOG"; then
            phase_fail
            log_error "Compilation failed. See $BUILD_LOG and $ERROR_LOG"
            grep -E "error:" "$BUILD_LOG" >> "$ERROR_LOG" 2>/dev/null || true
            exit $EC_BUILD
        fi
    fi

    phase_ok
fi

# -----------------------------------------------------------------------------
# POST-BUILD: copy Image
# -----------------------------------------------------------------------------
phase_start "copy_image"

if [[ "$DRY_RUN" == true ]]; then
    phase_skip
elif [[ -f "$KERNEL_IMAGE_OUT" ]]; then
    mkdir -p "$(dirname "$KERNEL_IMAGE_TREE")"
    cp "$KERNEL_IMAGE_OUT" "$KERNEL_IMAGE_TREE"
    log_ok "Image copied → $KERNEL_IMAGE_TREE ($(du -h "$KERNEL_IMAGE_TREE" | cut -f1))"
    phase_ok
else
    phase_fail
    log_error "Kernel image not found at: $KERNEL_IMAGE_OUT"
    exit $EC_POST_COPY
fi

# -----------------------------------------------------------------------------
# CCACHE STATS (informational only)
# -----------------------------------------------------------------------------
if command -v ccache &>/dev/null && [[ "$DRY_RUN" == false ]]; then
    log_section "ccache stats"
    ccache -s >> "$BUILD_LOG" 2>&1
    log_info "ccache stats written to build log"
fi

# -----------------------------------------------------------------------------
# FLASHABLE ZIP (only with --zip)
# -----------------------------------------------------------------------------
phase_start "zip"

if [[ "$CREATE_ZIP" == false ]]; then
    phase_skip
elif [[ "$DRY_RUN" == true ]]; then
    log_info "[dry-run] Skipping zip"
    phase_skip
else
    git_commit="$(git -C "$PREFIX" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
    git_branch="$(git -C "$PREFIX" symbolic-ref --short HEAD 2>/dev/null \
                    | sed 's/[^a-zA-Z0-9._-]/_/g' || echo 'unknown')"
    zip_ts="$(date +%Y%m%d_%H%M)"
    output_zip="$ANYKERNEL_DIR/WMKernel-ksunext-susfs-dev_${zip_ts}_${git_commit}_${git_branch}.zip"

    mkdir -p "$ANYKERNEL_DIR"

    if ! cp "$SOURCE_ZIP" "$output_zip"; then
        phase_fail
        log_error "Failed to copy base zip: $SOURCE_ZIP"
        exit $EC_ZIP
    fi

    # Add the kernel image in-place; cd dance avoids storing full path inside zip
    if ! (cd "$(dirname "$KERNEL_IMAGE_OUT")" && \
          zip -j "$output_zip" "$(basename "$KERNEL_IMAGE_OUT")" >> "$BUILD_LOG" 2>&1); then
        phase_fail
        log_error "Failed to add Image to zip"
        rm -f "$output_zip"
        exit $EC_ZIP
    fi

    log_ok "Flashable zip: $output_zip ($(du -h "$output_zip" | cut -f1))"
    phase_ok
fi

# -----------------------------------------------------------------------------
# PUBLISH ARTIFACT (nightly.zears.xyz)
# -----------------------------------------------------------------------------
phase_start "publish"

PUBLISH_SCRIPT="/home/zears/nightly.zears.xyz/scripts/publish.py"

if [[ ! -f "$PUBLISH_SCRIPT" ]]; then
    log_info "Skipping publish: registry tools not found at $PUBLISH_SCRIPT"
    phase_skip
elif [[ "$CREATE_ZIP" == false ]]; then
    log_info "Skipping publish: no zip created"
    phase_skip
elif [[ "$DRY_RUN" == true ]]; then
    log_info "[dry-run] Skipping publish"
    phase_skip
elif [[ "$SKIP_UPLOAD" == true ]]; then
    log_info "Skipping publish due to --skip-upload"
    phase_skip
else
    log_info "Publishing artifact to registry..."
    
    
    # Capture exact build environment context
    local_os="$(uname -srm)"

    # Activate the registry python environment and publish
    if ! (
        source /home/zears/nightly.zears.xyz/scripts/.venv/bin/activate
        python /home/zears/nightly.zears.xyz/scripts/publish.py \
            --file "$output_zip" \
            --project WMKernel \
            --component a22 \
            --channel nightly \
            --commit "$git_commit" \
            --branch "$git_branch" \
            --toolchain "$local_toolchain" \
            --host-os "$local_os" >> "$BUILD_LOG" 2>&1
    ); then
        phase_fail
        log_error "Failed to publish artifact. See build log for details."
        exit $EC_PUBLISH
    fi

    log_ok "Artifact successfully published to nightly.zears.xyz"
    phase_ok
fi

# -----------------------------------------------------------------------------
# BUILD SUMMARY (human-readable, or JSON if --json)
# -----------------------------------------------------------------------------
log_section "BUILD COMPLETE"
log_ok  "Kernel image : $KERNEL_IMAGE_TREE"
log_info "Build log   : $BUILD_LOG"
log_info "Git commit  : $(git -C "$PREFIX" rev-parse --short HEAD 2>/dev/null || echo 'n/a')"
log_info "Git branch  : $(git -C "$PREFIX" symbolic-ref --short HEAD 2>/dev/null || echo 'n/a')"
[[ -f "$KERNEL_IMAGE_TREE" ]] && \
    log_info "Image size  : $(du -h "$KERNEL_IMAGE_TREE" | cut -f1)"

# Disarm trap and exit cleanly
_success_exit