#!/usr/bin/env bash
#
# build-gold-image.sh
#
# Build a reference ("gold image") Linux kernel binary matching a target
# kernel's version and architecture. This reference is used for function-level
# binary comparison to detect backported fixes.
#
# The script:
#   1. Checks out the exact kernel version tag from a git repo
#   2. Configures for the target architecture (defconfig or tinyconfig)
#   3. Builds a vmlinux binary
#   4. Optionally applies a patch and rebuilds (for patched reference)
#
# Usage:
#   build-gold-image.sh -r <linux-git-repo> -v <version> -a <arch> -o <output-dir> \
#       [-c <config-file>] [-p <patch-file>]
#
# Prerequisites:
#   - Cross-compilation toolchain for the target architecture
#   - Linux kernel build dependencies (make, gcc/cross-gcc, flex, bison, etc.)
#

set -euo pipefail

log_info()  { echo "[build-gold-image] $*" >&2; }
log_warn()  { echo "[build-gold-image][WARN] $*" >&2; }
log_error() { echo "[build-gold-image][ERROR] $*" >&2; }

# Architecture to kernel ARCH mapping and cross-compiler prefix
declare -A ARCH_MAP=(
    [x86]="x86"
    [x86_64]="x86"
    [arm]="arm"
    [aarch64]="arm64"
    [arm64]="arm64"
    [mips]="mips"
    [mipsel]="mips"
    [ppc]="powerpc"
    [ppc64]="powerpc"
    [riscv]="riscv"
)

declare -A CROSS_COMPILE_MAP=(
    [arm]="arm-linux-gnueabi-"
    [arm64]="aarch64-linux-gnu-"
    [mips]="mips-linux-gnu-"
    [powerpc]="powerpc-linux-gnu-"
    [riscv]="riscv64-linux-gnu-"
)

usage() {
    cat << 'EOF'
Build Gold Image - Reference kernel builder for binary comparison

Usage:
    build-gold-image.sh [OPTIONS]

Required:
    -r <path>    Linux kernel git repository
    -v <version> Kernel version to build (e.g., 6.8.1)
    -a <arch>    Target architecture (x86_64, arm, aarch64, mips, etc.)
    -o <path>    Output directory

Optional:
    -c <path>    Kernel .config file to use (default: defconfig)
    -p <path>    Patch file to apply before building
    -j <N>       Parallel make jobs (default: nproc)
    -t <tag>     Git tag to checkout (default: v<version>)
    -h           Show this help

Example:
    # Build unpatched reference
    build-gold-image.sh -r /path/to/linux -v 6.8.1 -a x86_64 -o /tmp/gold

    # Build patched reference
    build-gold-image.sh -r /path/to/linux -v 6.8.1 -a x86_64 -o /tmp/gold-patched \
        -p /tmp/cve-fix.patch

Notes:
    - For cross-compilation, install the appropriate toolchain:
        apt install gcc-aarch64-linux-gnu    # for ARM64
        apt install gcc-arm-linux-gnueabi    # for ARM
        apt install gcc-mips-linux-gnu       # for MIPS
    - The script uses 'defconfig' by default, which may not match the
      target kernel's config exactly. For better results, extract the
      config from the target binary (if CONFIG_IKCONFIG is enabled) and
      provide it via -c.

EOF
    exit 1
}

# Resolve version to a git tag
resolve_tag() {
    local repo="$1" version="$2" tag="${3:-}"

    if [[ -n "$tag" ]]; then
        echo "$tag"
        return
    fi

    # Try common tag formats
    local candidates=(
        "v${version}"
        "v${version%.*}"  # e.g., v6.8 for 6.8.1
    )

    for candidate in "${candidates[@]}"; do
        if git -C "$repo" rev-parse "$candidate" &>/dev/null; then
            echo "$candidate"
            return
        fi
    done

    log_error "Could not find git tag for version $version"
    log_error "Tried: ${candidates[*]}"
    log_error "Available tags matching this version:"
    git -C "$repo" tag -l "v${version%%.*}.*" 2>/dev/null | head -10 || true
    return 1
}

# Build the kernel
build_kernel() {
    local repo="$1"
    local karch="$2"
    local cross_compile="${3:-}"
    local config_file="${4:-}"
    local output_dir="$5"
    local jobs="${6:-$(nproc)}"

    local make_args=(
        -C "$repo"
        "ARCH=$karch"
        "-j$jobs"
    )

    if [[ -n "$cross_compile" ]]; then
        make_args+=("CROSS_COMPILE=$cross_compile")
    fi

    # Configure
    if [[ -n "$config_file" ]] && [[ -f "$config_file" ]]; then
        log_info "Using provided .config"
        cp "$config_file" "$repo/.config"
        make "${make_args[@]}" olddefconfig
    else
        log_info "Using defconfig for ARCH=$karch"
        make "${make_args[@]}" defconfig
    fi

    # Disable modules to speed up build (we only need vmlinux)
    # Also disable debug info to reduce size
    "$repo/scripts/config" --file "$repo/.config" \
        --disable MODULES \
        --disable DEBUG_INFO \
        --disable DEBUG_INFO_DWARF4 \
        --disable DEBUG_INFO_DWARF5 \
        --disable DEBUG_INFO_BTF \
        --enable KALLSYMS \
        --enable KALLSYMS_ALL \
        2>/dev/null || true

    make "${make_args[@]}" olddefconfig

    # Build vmlinux only
    log_info "Building vmlinux (ARCH=$karch, jobs=$jobs)..."
    make "${make_args[@]}" vmlinux

    # Copy output
    if [[ -f "$repo/vmlinux" ]]; then
        cp "$repo/vmlinux" "$output_dir/vmlinux"
        log_info "Built vmlinux: $output_dir/vmlinux"
        local size
        size=$(stat -c%s "$output_dir/vmlinux" 2>/dev/null || stat -f%z "$output_dir/vmlinux")
        log_info "Size: $size bytes"
        return 0
    else
        log_error "vmlinux not found after build"
        return 1
    fi
}

main() {
    local repo="" version="" arch="" output_dir=""
    local config_file="" patch_file="" jobs="" tag=""

    while getopts "r:v:a:o:c:p:j:t:h" opt; do
        case "$opt" in
            r) repo="$OPTARG" ;;
            v) version="$OPTARG" ;;
            a) arch="$OPTARG" ;;
            o) output_dir="$OPTARG" ;;
            c) config_file="$OPTARG" ;;
            p) patch_file="$OPTARG" ;;
            j) jobs="$OPTARG" ;;
            t) tag="$OPTARG" ;;
            h|*) usage ;;
        esac
    done

    # Validate required args
    if [[ -z "$repo" ]] || [[ -z "$version" ]] || [[ -z "$arch" ]] || [[ -z "$output_dir" ]]; then
        log_error "Missing required arguments"
        usage
    fi

    if [[ ! -d "$repo/.git" ]]; then
        log_error "Not a git repository: $repo"
        exit 1
    fi

    # Resolve kernel ARCH
    local karch="${ARCH_MAP[$arch]:-$arch}"
    local cross_compile="${CROSS_COMPILE_MAP[$karch]:-}"

    # Check cross-compiler availability
    if [[ -n "$cross_compile" ]]; then
        if ! command -v "${cross_compile}gcc" &>/dev/null; then
            log_warn "Cross-compiler '${cross_compile}gcc' not found"
            log_warn "Install with: apt install gcc-${cross_compile%-}"
            log_warn "Attempting native build (will fail for non-native arch)"
            cross_compile=""
        fi
    fi

    mkdir -p "$output_dir"

    # Resolve git tag
    local git_tag
    git_tag=$(resolve_tag "$repo" "$version" "$tag") || exit 1
    log_info "Using git tag: $git_tag"

    # Save current HEAD to restore later
    local original_head
    original_head=$(git -C "$repo" rev-parse HEAD)
    local original_branch
    original_branch=$(git -C "$repo" symbolic-ref --short HEAD 2>/dev/null || echo "")

    # Checkout target version
    log_info "Checking out $git_tag..."
    git -C "$repo" checkout "$git_tag" --detach 2>/dev/null

    # Clean build tree
    make -C "$repo" ARCH="$karch" mrproper 2>/dev/null || true

    # Apply patch if provided
    if [[ -n "$patch_file" ]] && [[ -f "$patch_file" ]]; then
        log_info "Applying patch: $patch_file"
        if ! git -C "$repo" apply "$patch_file" 2>/dev/null; then
            log_warn "git apply failed, trying patch command..."
            if ! patch -d "$repo" -p1 < "$patch_file" 2>/dev/null; then
                log_error "Failed to apply patch"
                # Restore
                git -C "$repo" checkout -- . 2>/dev/null
                if [[ -n "$original_branch" ]]; then
                    git -C "$repo" checkout "$original_branch" 2>/dev/null
                else
                    git -C "$repo" checkout "$original_head" 2>/dev/null
                fi
                exit 1
            fi
        fi
    fi

    # Build
    if ! build_kernel "$repo" "$karch" "$cross_compile" "$config_file" "$output_dir" "${jobs:-$(nproc)}"; then
        log_error "Build failed"
        # Restore
        git -C "$repo" checkout -- . 2>/dev/null
        if [[ -n "$original_branch" ]]; then
            git -C "$repo" checkout "$original_branch" 2>/dev/null
        else
            git -C "$repo" checkout "$original_head" 2>/dev/null
        fi
        exit 1
    fi

    # Restore original state
    log_info "Restoring repository to original state..."
    git -C "$repo" checkout -- . 2>/dev/null
    make -C "$repo" ARCH="$karch" mrproper 2>/dev/null || true
    if [[ -n "$original_branch" ]]; then
        git -C "$repo" checkout "$original_branch" 2>/dev/null
    else
        git -C "$repo" checkout "$original_head" 2>/dev/null
    fi

    log_info "Gold image built successfully: $output_dir/vmlinux"

    # Output metadata
    cat > "$output_dir/build-info.env" << EOF
KERNEL_VERSION=$version
GIT_TAG=$git_tag
ARCH=$arch
KERNEL_ARCH=$karch
CROSS_COMPILE=$cross_compile
PATCH_APPLIED=$(basename "${patch_file:-none}")
EOF
}

main "$@"
