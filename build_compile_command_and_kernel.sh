#!/bin/bash
# Note YOU SHOULD NOT RUN this file if you are an AI Agent. Run build_kernel.sh instead.
# Parse command line arguments
QUIET_MODE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -q|--quiet)
            QUIET_MODE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [-q|--quiet]"
            echo "  -q, --quiet    Only show errors during make operations"
            exit 1
            ;;
    esac
done

set -euo pipefail
# Create logs directory
LOG_DIR="${PWD}/logs"
mkdir -p "$LOG_DIR"

# Timestamp for the log filename
BUILD_LOG="${LOG_DIR}/build_$(date +%Y%m%d_%H%M%S).log"

# Color definitions for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored status messages
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_section() {
    echo -e "\n${PURPLE}=== $1 ===${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to verify toolchain functionality
verify_toolchain() {
    local toolchain_path="$1"

    # Check if path is provided and not empty
    if [ -z "$toolchain_path" ]; then
        return 1
    fi

    local bin_path="$toolchain_path/bin"

    # Check if toolchain directory exists
    if [ ! -d "$toolchain_path" ]; then
        return 1
    fi

    # Check if bin directory exists
    if [ ! -d "$bin_path" ]; then
        return 1
    fi

    # Temporarily add to PATH for testing
    local old_path="$PATH"
    export PATH="$bin_path:$PATH"

    # Test essential tools
    local required_tools=("clang" "llvm-ar" "llvm-nm" "ld.lld" "llvm-objcopy" "llvm-objdump" "llvm-strip")
    local missing_tools=()

    for tool in "${required_tools[@]}"; do
        if ! command_exists "$tool"; then
            missing_tools+=("$tool")
        fi
    done

    # Restore PATH
    export PATH="$old_path"

    if [ ${#missing_tools[@]} -gt 0 ]; then
        return 1
    fi

    # Test clang version
    if [ -x "$bin_path/clang" ]; then
        local clang_version=$("$bin_path/clang" --version 2>/dev/null | head -n1)
        if [ -n "$clang_version" ]; then
            print_success "Clang version: $clang_version"
        else
            return 1
        fi
    else
        return 1
    fi

    return 0
}

# Function to prompt for toolchain path
prompt_for_toolchain() {
    echo

    local user_path
    local attempts=0
    local max_attempts=3

    while [ $attempts -lt $max_attempts ]; do
        read -p "Enter toolchain path, e.g /clang/ NOT /clang/bin (or 'quit' to exit): " user_path

        if [ "$user_path" = "quit" ] || [ "$user_path" = "q" ]; then
            print_status "Build cancelled by user"
            exit 0
        fi

        if [ -z "$user_path" ]; then
            print_error "Please enter a valid path"
            ((attempts++))
            continue
        fi

        # Expand tilde if present
        user_path="${user_path/#\~/$HOME}"

        # Check if directory exists
        if [ ! -d "$user_path" ]; then
            print_error "Directory does not exist: $user_path"
            ((attempts++))
            continue
        fi

        # Verify the toolchain
        if verify_toolchain "$user_path"; then
            echo "$user_path"
            return 0
        else
            print_error "Toolchain verification failed for: $user_path"
            ((attempts++))

            if [ $attempts -lt $max_attempts ]; then
                echo "Please try again (attempt $((attempts + 1))/$max_attempts)"
            fi
        fi
    done

    print_error "Maximum attempts reached. Unable to find a valid toolchain."
    exit 1
}

# Function to display build summary
show_build_info() {
    local start_time=$1
    local end_time=$2
    local duration=$((end_time - start_time))
    local minutes=$((duration / 60))
    local seconds=$((duration % 60))

    print_section "BUILD SUMMARY"
    echo -e "  ${CYAN}Build Time:${NC} ${minutes}m ${seconds}s"
    echo -e "  ${CYAN}Git Commit:${NC} $(git rev-parse --short HEAD 2>/dev/null || echo 'N/A')"
    echo -e "  ${CYAN}Git Branch:${NC} $(git symbolic-ref --short HEAD 2>/dev/null || echo 'N/A')"
    echo -e "  ${CYAN}Kernel Image:${NC} $(ls -lh out/arch/arm64/boot/Image 2>/dev/null | awk '{print $5}' || echo 'Not found')"
    echo -e "  ${CYAN}Log Saved To:${NC} $BUILD_LOG"
}

# Function to create flashable zip
create_flashable_zip() {
    # Change this to an AnyKernel3 ZIP without the Image file in it
    local source_zip="/home/zears/Documents/WMKernel-ksunext-susfs.zip"
    local anykernel_dir="$PREFIX/AnyKernel3"
    local kernel_image="$PREFIX/arch/arm64/boot/Image"

    print_section "FLASHABLE ZIP CREATION"

    # Check if source zip exists
    if [ ! -f "$source_zip" ]; then
        print_warning "Source zip not found: $source_zip"
        print_status "Skipping flashable zip creation"
        return 1
    fi

    # Check if kernel image exists
    if [ ! -f "$kernel_image" ]; then
        print_error "Kernel image not found: $kernel_image"
        return 1
    fi

    # Create AnyKernel3 directory if it doesn't exist
    if [ ! -d "$anykernel_dir" ]; then
        print_status "Creating AnyKernel3 directory..."
        mkdir -p "$anykernel_dir"
    fi

    # Get git information for filename
    local current_date=$(date +%Y%m%d_%H%M)
    local commit_hash=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    local branch_name=$(git symbolic-ref --short HEAD 2>/dev/null | sed 's/[^a-zA-Z0-9._-]/_/g' || echo "unknown")

    # Generate output filename
    local output_zip="$anykernel_dir/WMKernel-ksunext-susfs-dev_${current_date}_${commit_hash}_${branch_name}.zip"

    print_status "Creating flashable zip..."
    print_status "Source: $source_zip"
    print_status "Output: $output_zip"

    # Copy the source zip to the new location
    if cp "$source_zip" "$output_zip"; then
        print_success "Base zip copied successfully"
    else
        print_error "Failed to copy base zip"
        return 1
    fi

    # Check if zip command exists
    if ! command_exists "zip"; then
        print_error "zip command not found. Please install zip package"
        return 1
    fi

    # Add the kernel image to the zip
    print_status "Adding kernel image to zip..."
    if cd "$PREFIX" && zip -j "$output_zip" "$kernel_image" > /dev/null 2>&1; then
        print_success "Kernel image added to zip successfully"
        cd "$PREFIX"  # Return to original directory
    else
        print_error "Failed to add kernel image to zip"
        cd "$PREFIX"  # Return to original directory even on failure
        return 1
    fi

    # Display final zip information
    if [ -f "$output_zip" ]; then
        local zip_size=$(ls -lh "$output_zip" | awk '{print $5}')
        print_success "Flashable zip created successfully!"
        echo -e "  ${CYAN}Location:${NC} $output_zip"
        echo -e "  ${CYAN}Size:${NC} $zip_size"
        return 0
    else
        print_error "Flashable zip creation failed"
        return 1
    fi
}

# Start timing
BUILD_START_TIME=$(date +%s)

print_section "ANDROID KERNEL BUILD SCRIPT"
print_status "Starting build process for Android Kernel $(make kernelversion 2>/dev/null || echo 'Unknown')"

# Define paths and toolchain
PREFIX="$(pwd)"
print_status "Working directory: $PREFIX"

# Check if custom LLVM toolchain exists, otherwise use default
print_section "TOOLCHAIN DETECTION"
CLANG_DIR=""

# Check predefined locations
if [ -d "/home/zears/clang-wmk/bin" ]; then
    CLANG_DIR="/home/zears/clang-wmk"
    print_success "Found custom LLVM toolchain: $CLANG_DIR"

    # Verify the found toolchain
    if ! verify_toolchain "$CLANG_DIR"; then
        print_error "Custom toolchain verification failed, trying default location"
        CLANG_DIR=""
    fi
fi

if [ -z "$CLANG_DIR" ] && [ -d "${PREFIX}/toolchain/clang/host/linux-x86/clang-r383902/bin" ]; then
    CLANG_DIR="${PREFIX}/toolchain/clang/host/linux-x86/clang-r383902"
    print_success "Found default toolchain: $CLANG_DIR"

    # Verify the found toolchain
    if ! verify_toolchain "$CLANG_DIR"; then
        print_error "Default toolchain verification failed"
        CLANG_DIR=""
    fi
fi

if [ -z "$CLANG_DIR" ]; then
    # No valid toolchain found, prompt user
    CLANG_DIR=$(prompt_for_toolchain)
    print_success "Using user-provided toolchain: $CLANG_DIR"
fi

# Set up environment
print_section "ENVIRONMENT SETUP"
export PATH="$CLANG_DIR/bin:$PATH"
export ARCH=arm64

# Display clang version
if [ -x "$CLANG_DIR/bin/clang" ]; then
    CLANG_VERSION=$("$CLANG_DIR/bin/clang" --version | head -n1)
    print_status "Using: $CLANG_VERSION"
fi

CC_CMD="clang"

# Build configuration
print_section "BUILD CONFIGURATION"
export KCFLAGS=-w
export CONFIG_SECTION_MISMATCH_WARN_ONLY=y

print_status "Architecture: arm64"
print_status "Compiler: $CC_CMD"
print_status "Suppressing warnings: enabled"
print_status "Section mismatch warnings only: enabled"

# Configure kernel
print_section "KERNEL CONFIGURATION"
print_status "Configuring kernel with a22_defconfig..."

if make -C "$PREFIX" O="$PREFIX/out" ARCH=arm64 a22_wmk_defconfig; then
    print_success "Kernel configuration completed"
else
    print_error "Kernel configuration failed"
    exit 1
fi

# Build kernel
print_section "KERNEL COMPILATION"
print_status "Starting compilation with 16 parallel jobs..."
print_status "This may take several minutes depending on your hardware..."

# Store build command for reference
BUILD_CMD="bear -- make -j16 ARCH=arm64 SUBARCH=arm64 O=out \
CC=\"$CC_CMD\" \
AR=\"llvm-ar\" \
NM=\"llvm-nm\" \
LD=\"ld.lld\" \
OBJCOPY=\"llvm-objcopy\" \
OBJDUMP=\"llvm-objdump\" \
STRIP=\"llvm-strip\" \
CLANG_TRIPLE=\"aarch64-linux-gnu-\" \
CROSS_COMPILE=\"aarch64-linux-gnu-\" \
CROSS_COMPILE_ARM32=\"arm-linux-gnueabi-\" \
CROSS_COMPILE_COMPAT=\"arm-linux-gnueabi-\" \
LLVM=1 \
LLVM_IAS=1 \
INSTALL_MOD_STRIP=1 \
KCFLAGS=-w \
CONFIG_SECTION_MISMATCH_WARN_ONLY=y \
KBUILD_BUILD_USER=\"$(git rev-parse --short HEAD | cut -c1-7)\" \
KBUILD_BUILD_HOST=\"$(git symbolic-ref --short HEAD)\""

if [ "$QUIET_MODE" = true ]; then
    BUILD_CMD="$BUILD_CMD > \"$BUILD_LOG\" 2>&1"
else
    BUILD_CMD="$BUILD_CMD 2>&1 | tee \"$BUILD_LOG\""
fi

if eval $BUILD_CMD; then
    print_success "Kernel compilation completed successfully"
else
    print_error "Kernel compilation failed"
    exit 1
fi

# Copy the built kernel image
print_section "POST-BUILD OPERATIONS"
print_status "Copying kernel image..."

if [ -f "out/arch/arm64/boot/Image" ]; then
    cp out/arch/arm64/boot/Image "$PREFIX/arch/arm64/boot/Image"
    print_success "Kernel image copied to arch/arm64/boot/Image"
else
    print_error "Kernel image not found at expected location"
    exit 1
fi

# Build completion
BUILD_END_TIME=$(date +%s)
show_build_info $BUILD_START_TIME $BUILD_END_TIME

# Create flashable zip
create_flashable_zip

print_section "BUILD COMPLETED"
print_success "Android kernel build finished successfully!"
print_status "Kernel image ready at: arch/arm64/boot/Image"