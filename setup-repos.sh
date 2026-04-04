#!/usr/bin/env bash
#
# setup-repos.sh
#
# Helper script to clone the required Git repositories for Kernel Backport Checker.
# The upstream and stable Linux kernel repositories are large (~3-5 GB each) and
# require full history for the checker to work correctly.
#
# This script clones:
#   1. Upstream Linux kernel (torvalds/linux.git)
#   2. Stable Linux kernel (stable/linux.git) — optional but recommended
#
# It can also help download supplemental data:
#   3. NVD JSON data feeds (fkie-cad/nvd-json-data-feeds)
#   4. CISA KEV data (cisagov/kev-data)
#
# Usage:
#   ./setup-repos.sh [-d <target-dir>] [-u] [-s] [-n] [-k] [-a] [-j <jobs>]
#

set -euo pipefail

# ---- Defaults ----
TARGET_DIR=""
CLONE_UPSTREAM=false
CLONE_STABLE=false
DOWNLOAD_NVD=false
DOWNLOAD_KEV=false
CLONE_ALL=false
JOBS=4

# ---- Git URLs ----
UPSTREAM_URL="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"
STABLE_URL="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
NVD_REPO_URL="https://github.com/fkie-cad/nvd-json-data-feeds.git"
KEV_REPO_URL="https://github.com/cisagov/kev-data.git"

# =============================================================================
# Utility
# =============================================================================

log_info()  { echo "[INFO] $*"; }
log_warn()  { echo "[WARN] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

usage() {
    cat << EOF
Kernel Backport Checker — Repository Setup

Clones the required Git repositories with full history so that
kernel-backport-checker.sh can look up commits across all kernel versions.

Usage:
    $0 [OPTIONS]

Options:
    -d <path>    Target directory for clones (default: current directory)
    -u           Clone upstream Linux kernel (torvalds/linux.git)
    -s           Clone stable Linux kernel (stable/linux.git)
    -n           Download NVD JSON data feeds (fkie-cad/nvd-json-data-feeds)
    -k           Download CISA KEV data (cisagov/kev-data)
    -a           Clone/download everything (equivalent to -u -s -n -k)
    -j <N>       Number of parallel clone/download jobs (default: 4)
    -h           Show this help

Without any action flags (-u/-s/-n/-k/-a), the script prints information
about the required repositories and exits.

Repository sizes (approximate, full history):
    Upstream kernel:  ~5 GB
    Stable kernel:    ~4 GB
    NVD feeds:        ~200 MB
    CISA KEV:         ~10 MB

Examples:
    # Clone everything to ~/kernel-data
    $0 -d ~/kernel-data -a

    # Clone only the upstream kernel
    $0 -d ~/kernel-data -u

    # Clone upstream + stable (needed for most checker runs)
    $0 -d ~/kernel-data -u -s

    # Clone repos and download data feeds
    $0 -d ~/kernel-data -a -j 8

After cloning, run the checker like:
    ./kernel-backport-checker.sh \\
        -s ../linux-6.1.1 \\
        -d ~/kernel-data/linux \\
        -b ~/kernel-data/linux-stable \\
        -e ~/kernel-data/kev-data \\
        -f ~/kernel-data/nvd-json-data-feeds \\
        -k ../linux-6.1.1/.config \\
        -o output -j 4

EOF
    exit 0
}

# =============================================================================
# Argument parsing
# =============================================================================

parse_args() {
    while getopts "d:usnkaj:h" opt; do
        case $opt in
            d) TARGET_DIR="$OPTARG" ;;
            u) CLONE_UPSTREAM=true ;;
            s) CLONE_STABLE=true ;;
            n) DOWNLOAD_NVD=true ;;
            k) DOWNLOAD_KEV=true ;;
            a) CLONE_ALL=true ;;
            j) JOBS="$OPTARG" ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    if [[ "$CLONE_ALL" == true ]]; then
        CLONE_UPSTREAM=true
        CLONE_STABLE=true
        DOWNLOAD_NVD=true
        DOWNLOAD_KEV=true
    fi
}

# =============================================================================
# Checks
# =============================================================================

check_dependencies() {
    local missing=0

    if ! command -v git &>/dev/null; then
        log_error "git is required. Install: apt install git / yum install git"
        missing=1
    fi

    if [[ "$DOWNLOAD_NVD" == true || "$DOWNLOAD_KEV" == true ]]; then
        if ! command -v jq &>/dev/null; then
            log_warn "jq is recommended for data feeds. Install: apt install jq / yum install jq"
        fi
    fi

    if [[ "$missing" -eq 1 ]]; then
        exit 1
    fi
}

# =============================================================================
# Clone a Git repository with full history
# =============================================================================

clone_repo() {
    local url="$1"
    local dest="$2"
    local label="$3"

    if [[ -d "$dest/.git" ]]; then
        log_info "$label already exists at $dest, skipping"
        return 0
    fi

    if [[ -d "$dest" ]]; then
        log_warn "Directory $dest exists but is not a git repo, removing"
        rm -rf "$dest"
    fi

    log_info "Cloning $label ..."
    log_info "  URL: $url"
    log_info "  Destination: $dest"
    log_info "  This may take a while (full history, several GB)..."

    git clone -- "$url" "$dest"
    local count
    count=$(git -C "$dest" rev-list --all --count 2>/dev/null || echo "?")
    log_info "$label clone complete: $count commits"
}

# =============================================================================
# Download data feeds (shallow clone is sufficient)
# =============================================================================

download_data() {
    local url="$1"
    local dest="$2"
    local label="$3"

    if [[ -d "$dest/.git" ]]; then
        log_info "$label already exists at $dest, skipping"
        return 0
    fi

    if [[ -d "$dest" ]]; then
        log_warn "Directory $dest exists but is not a git repo, removing"
        rm -rf "$dest"
    fi

    log_info "Downloading $label ..."
    log_info "  URL: $url"
    log_info "  Destination: $dest"

    git clone --depth 1 -- "$url" "$dest"
    log_info "$label download complete"
}

# =============================================================================
# Main
# =============================================================================

main() {
    parse_args "$@"

    # If no action requested, print info and exit
    if [[ "$CLONE_UPSTREAM" != true && "$CLONE_STABLE" != true && \
          "$DOWNLOAD_NVD" != true && "$DOWNLOAD_KEV" != true ]]; then
        log_info "No action specified. Use -a to clone everything, or -h for help."
        echo ""
        log_info "Required repositories for kernel-backport-checker.sh:"
        echo ""
        echo "  1. Upstream Linux kernel (torvalds/linux.git)"
        echo "     URL: $UPSTREAM_URL"
        echo "     Used for: fix commit hash lookup, diff extraction"
        echo "     Size: ~5 GB (full history)"
        echo ""
        echo "  2. Stable Linux kernel (stable/linux.git) — recommended"
        echo "     URL: $STABLE_URL"
        echo "     Used for: backport commit detection across stable branches"
        echo "     Size: ~4 GB (full history)"
        echo ""
        echo "  3. NVD JSON data feeds (fkie-cad/nvd-json-data-feeds)"
        echo "     URL: $NVD_REPO_URL"
        echo "     Used for: CVE database with CPE matching"
        echo "     Size: ~200 MB"
        echo ""
        echo "  4. CISA KEV data (cisagov/kev-data)"
        echo "     URL: $KEV_REPO_URL"
        echo "     Used for: known exploited vulnerabilities catalog"
        echo "     Size: ~10 MB"
        echo ""
        log_info "Run '$0 -a -d <target-dir>' to clone everything."
        exit 0
    fi

    check_dependencies

    # Resolve target directory
    if [[ -z "$TARGET_DIR" ]]; then
        TARGET_DIR="$(pwd)"
    fi
    mkdir -p "$TARGET_DIR"

    log_info "Target directory: $TARGET_DIR"
    echo ""

    # Build parallel job list
    local jobs=()

    if [[ "$CLONE_UPSTREAM" == true ]]; then
        jobs+=("clone|${UPSTREAM_URL}|${TARGET_DIR}/linux|Upstream Linux kernel")
    fi

    if [[ "$CLONE_STABLE" == true ]]; then
        jobs+=("clone|${STABLE_URL}|${TARGET_DIR}/linux-stable|Stable Linux kernel")
    fi

    if [[ "$DOWNLOAD_NVD" == true ]]; then
        jobs+=("data|${NVD_REPO_URL}|${TARGET_DIR}/nvd-json-data-feeds|NVD JSON data feeds")
    fi

    if [[ "$DOWNLOAD_KEV" == true ]]; then
        jobs+=("data|${KEV_REPO_URL}|${TARGET_DIR}/kev-data|CISA KEV data")
    fi

    # Run in parallel using background processes
    local pids=()
    local results_file
    results_file=$(mktemp)

    for job in "${jobs[@]}"; do
        IFS='|' read -r type url dest label <<< "$job"
        (
            if [[ "$type" == "clone" ]]; then
                if clone_repo "$url" "$dest" "$label"; then
                    echo "OK|$label" >> "$results_file"
                else
                    echo "FAIL|$label" >> "$results_file"
                fi
            else
                if download_data "$url" "$dest" "$label"; then
                    echo "OK|$label" >> "$results_file"
                else
                    echo "FAIL|$label" >> "$results_file"
                fi
            fi
        ) &
        pids+=($!)

        # Limit concurrency
        if [[ "${#pids[@]}" -ge "$JOBS" ]]; then
            wait "${pids[0]}"
            pids=("${pids[@]:1}")
        fi
    done

    # Wait for remaining jobs
    for pid in "${pids[@]}"; do
        wait "$pid"
    done

    echo ""
    log_info "==== Setup Summary ===="

    local ok=0 fail=0
    while IFS='|' read -r status label; do
        if [[ "$status" == "OK" ]]; then
            log_info "  [OK] $label"
            ((ok++)) || true
        else
            log_error "  [FAIL] $label"
            ((fail++)) || true
        fi
    done < "$results_file"
    rm -f "$results_file"

    echo ""
    if [[ "$fail" -gt 0 ]]; then
        log_error "$fail task(s) failed. Check output above for details."
        exit 1
    fi

    log_info "All $ok task(s) completed successfully."
    echo ""

    # Print usage hint
    if [[ "$CLONE_UPSTREAM" == true || "$CLONE_STABLE" == true ]]; then
        log_info "To use with kernel-backport-checker.sh:"
        echo ""
        echo "    ./kernel-backport-checker.sh \\"
        echo "        -s <kernel-source-dir> \\"
        echo "        -d ${TARGET_DIR}/linux \\"
        if [[ "$CLONE_STABLE" == true ]]; then
            echo "        -b ${TARGET_DIR}/linux-stable \\"
        fi
        echo "        -e ${TARGET_DIR}/kev-data \\"
        echo "        -f ${TARGET_DIR}/nvd-json-data-feeds \\"
        echo "        -k <kernel-source-dir>/.config \\"
        echo "        -o output \\"
        echo "        -j $(nproc 2>/dev/null || echo 4)"
        echo ""
    fi
}

main "$@"
