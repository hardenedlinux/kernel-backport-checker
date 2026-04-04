#!/usr/bin/env bash
#
# kernel-binary-backport-checker.sh
#
# Determines which CVEs affect a Linux kernel binary and checks which have
# been fixed via backport, using binary analysis techniques (no source code
# required).
#
# This is the binary counterpart to kernel-backport-checker.sh. Instead of
# analyzing source code + git history, it analyzes the compiled kernel binary
# using string/symbol matching and optional function-level comparison.
#
# Workflow:
#   1. Detect binary format and extract vmlinux if needed
#   2. Extract metadata: version, arch, symbols, embedded config
#   3. Scan NVD JSON feeds for CVEs affecting the detected kernel version
#   4. Extract upstream fix commit hashes from NVD references
#   5. Generate fix signatures from upstream git diffs
#   6. Match signatures against the kernel binary
#   7. Output CSV report
#
# Usage:
#   ./kernel-binary-backport-checker.sh -b <kernel-binary> -d <upstream-linux-git-dir> \
#       -e <kev-data> -f <nvd-json-data-feeds> -o <output-dir> \
#       [-a <arch>] [-j <jobs>]
#

set -euo pipefail

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- Global variables ----
BINARY_INPUT=""
KERNEL_DIR=""         # Upstream linux git repo (for diffs)
STABLE_DIR=""         # Stable/vendor git repo (for backport diffs)
KEV_FILE=""
NVD_FEEDS_DIR=""
OUTPUT_DIR=""
ARCH_OVERRIDE=""
KERNEL_CONFIG=""      # User-provided .config file (optional)
MODULES_DIR=""        # Directory containing .ko module files (optional)
JOBS=0                # 0 = auto-detect
USE_R2="yes"          # Use radare2 if available

# ---- Detected from binary ----
KERNEL_VERSION=""
KERNEL_BASE=""        # Major.Minor.Patch without extra
DETECTED_ARCH=""
IS_ELF="no"
HAS_SYMBOLS="no"
HAS_IKCONFIG="no"
VMLINUX_PATH=""       # Path to the normalized vmlinux/blob

# ---- Working file paths (set in main) ----
AFFECTED_CVES_FILE=""
NVD_FIX_REFS_FILE=""
KEV_INDEX=""
RESULTS_FILE=""
METADATA_DIR=""
SIG_DB_DIR=""

# =============================================================================
# Utility
# =============================================================================

log_info()  { echo "[INFO] $*"; }
log_warn()  { echo "[WARN] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

usage() {
    cat << EOF
Kernel Binary Backport Checker v${VERSION}

Determines which CVEs affect a Linux kernel binary and checks which have
been fixed via backport, using binary analysis (no source code required).

Usage:
    $0 [OPTIONS]

Required Options:
    -b <path>    Kernel binary (vmlinux, bzImage, uImage, or raw blob)
    -d <path>    Upstream Linux kernel git directory (e.g., torvalds/linux.git clone)
                 Used for: extracting fix commit diffs for signature generation
    -e <path>    CISA KEV data directory or JSON file
    -f <path>    NVD JSON data feeds directory (fkie-cad/nvd-json-data-feeds)
    -o <path>    Output directory for results

Optional:
    -B <path>    Stable/vendor git repository with backport commits (e.g.,
                 linux-stable.git). Enables extraction of signatures from
                 stable-branch backport commits (NVD references often point to
                 stable-branch hashes that don't exist in the upstream repo)
                 and searching git log for CVE mentions.
    -k <path>    Kernel .config file (enables CONFIG-based filtering to eliminate
                 CVEs affecting code not compiled into the binary; greatly improves
                 detection accuracy -- highly recommended for development use)
    -m <path>    Directory containing kernel modules (.ko files). The tool will
                 recursively scan for .ko/.ko.xz/.ko.zst/.ko.gz files and extract
                 their symbols and strings, merging them with the vmlinux analysis.
                 This enables detection of CVEs in loadable module code.
                 (e.g., kernel build tree, /lib/modules/<ver>/, or extracted firmware)
    -a <arch>    Override architecture detection (x86, x86_64, arm, aarch64, mips)
    -j <N>       Number of parallel jobs (default: nproc/2, min 1)
    --no-r2      Disable radare2 usage (string-matching only)
    -h           Show this help

Supported Binary Formats:
    - ELF vmlinux (uncompressed, with or without symbols)
    - bzImage / zImage (compressed kernel images)
    - uImage (U-Boot wrapped kernel)
    - gzip / bzip2 / xz / lz4 / zstd compressed kernel
    - Raw decompressed kernel blob (from extract-vmlinux, binwalk, EMBA)

Example:
    $0 -b vmlinux -d linux -e kev-data -f nvd-json-data-feeds -o output
    $0 -b vmlinux -d linux -B linux-stable -e kev-data -f nvd-json-data-feeds -o output
    $0 -b vmlinux -d linux -B linux-stable -e kev-data -f nvd-json-data-feeds -o output -k /path/to/.config
    $0 -b vmlinux -d linux -e kev-data -f nvd-json-data-feeds -o output -m /lib/modules/6.8.1/
    $0 -b firmware-kernel.bin -d linux -e kev-data -f nvd-json-data-feeds -o output -a arm

Output:
    <output-dir>/binary-backport-report.csv

Dependencies:
    bash 4+, jq, git, python3, strings
    Optional: radare2 (r2), r2pipe (pip), vmlinux-to-elf (pip)

EOF
    exit 1
}

# =============================================================================
# Dependency checks
# =============================================================================

check_dependencies() {
    local missing=()
    local optional_missing=()

    for cmd in jq git python3 strings file hexdump; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        log_error "Install with: apt install ${missing[*]}"
        exit 1
    fi

    # Check Python modules
    if ! python3 -c "import json, re, sys, hashlib, os" 2>/dev/null; then
        log_error "Python3 standard library modules not available"
        exit 1
    fi

    # Optional dependencies
    if ! command -v r2 &>/dev/null; then
        optional_missing+=("radare2")
    fi

    if ! python3 -c "import r2pipe" 2>/dev/null; then
        optional_missing+=("r2pipe (pip install r2pipe)")
    fi

    if ! command -v vmlinux-to-elf &>/dev/null; then
        optional_missing+=("vmlinux-to-elf (pip install vmlinux-to-elf)")
    fi

    if [[ ${#optional_missing[@]} -gt 0 ]]; then
        log_warn "Optional tools not found: ${optional_missing[*]}"
        log_warn "These enable deeper binary analysis. Falling back to string matching."
    fi

    # Check bash version
    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        log_error "Bash 4+ required (found ${BASH_VERSION})"
        exit 1
    fi
}

# =============================================================================
# Argument parsing
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -b) BINARY_INPUT="$2"; shift 2 ;;
            -B) STABLE_DIR="$2"; shift 2 ;;
            -d) KERNEL_DIR="$2"; shift 2 ;;
            -e) KEV_FILE="$2"; shift 2 ;;
            -f) NVD_FEEDS_DIR="$2"; shift 2 ;;
            -o) OUTPUT_DIR="$2"; shift 2 ;;
            -k) KERNEL_CONFIG="$2"; shift 2 ;;
            -m) MODULES_DIR="$2"; shift 2 ;;
            -a) ARCH_OVERRIDE="$2"; shift 2 ;;
            -j) JOBS="$2"; shift 2 ;;
            --no-r2) USE_R2="no"; shift ;;
            -h|--help) usage ;;
            *) log_error "Unknown option: $1"; usage ;;
        esac
    done

    # Validate required args
    local errors=0
    if [[ -z "$BINARY_INPUT" ]]; then
        log_error "Missing: -b <kernel-binary>"
        errors=1
    elif [[ ! -f "$BINARY_INPUT" ]]; then
        log_error "File not found: $BINARY_INPUT"
        errors=1
    fi

    if [[ -z "$KERNEL_DIR" ]]; then
        log_error "Missing: -d <upstream-linux-git-dir>"
        errors=1
    elif [[ ! -d "$KERNEL_DIR/.git" ]]; then
        log_error "Not a git repository: $KERNEL_DIR"
        errors=1
    fi

    if [[ -z "$KEV_FILE" ]]; then
        log_error "Missing: -e <kev-data>"
        errors=1
    else
        # Resolve KEV file
        if [[ -d "$KEV_FILE" ]]; then
            if [[ -f "$KEV_FILE/known_exploited_vulnerabilities.json" ]]; then
                KEV_FILE="$KEV_FILE/known_exploited_vulnerabilities.json"
            else
                log_error "KEV directory does not contain known_exploited_vulnerabilities.json"
                errors=1
            fi
        elif [[ ! -f "$KEV_FILE" ]]; then
            log_error "KEV file not found: $KEV_FILE"
            errors=1
        fi
    fi

    if [[ -z "$NVD_FEEDS_DIR" ]]; then
        log_error "Missing: -f <nvd-json-data-feeds>"
        errors=1
    elif [[ ! -d "$NVD_FEEDS_DIR" ]]; then
        log_error "NVD feeds directory not found: $NVD_FEEDS_DIR"
        errors=1
    fi

    if [[ -z "$OUTPUT_DIR" ]]; then
        log_error "Missing: -o <output-dir>"
        errors=1
    fi

    if [[ -n "$KERNEL_CONFIG" && ! -f "$KERNEL_CONFIG" ]]; then
        log_error "Config file not found: $KERNEL_CONFIG"
        errors=1
    fi

    if [[ -n "$STABLE_DIR" ]]; then
        if [[ ! -d "$STABLE_DIR/.git" ]]; then
            log_error "Not a git repository: $STABLE_DIR"
            errors=1
        fi
    fi

    if [[ -n "$MODULES_DIR" && ! -d "$MODULES_DIR" ]]; then
        log_error "Modules directory not found: $MODULES_DIR"
        errors=1
    fi

    [[ "$errors" -gt 0 ]] && exit 1

    mkdir -p "$OUTPUT_DIR"

    # Resolve paths
    BINARY_INPUT=$(realpath "$BINARY_INPUT")
    KERNEL_DIR=$(realpath "$KERNEL_DIR")
    KEV_FILE=$(realpath "$KEV_FILE")
    NVD_FEEDS_DIR=$(realpath "$NVD_FEEDS_DIR")
    OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
    [[ -n "$KERNEL_CONFIG" ]] && KERNEL_CONFIG=$(realpath "$KERNEL_CONFIG")
    [[ -n "$STABLE_DIR" ]] && STABLE_DIR=$(realpath "$STABLE_DIR")
    [[ -n "$MODULES_DIR" ]] && MODULES_DIR=$(realpath "$MODULES_DIR")

    # Set jobs
    if [[ "$JOBS" -eq 0 ]]; then
        JOBS=$(( $(nproc 2>/dev/null || echo 2) / 2 ))
        [[ "$JOBS" -lt 1 ]] && JOBS=1
    fi

    # Set working file paths
    METADATA_DIR="$OUTPUT_DIR/.metadata"
    SIG_DB_DIR="$OUTPUT_DIR/.signatures"
    KEV_INDEX="$OUTPUT_DIR/.kev_index.txt"
    RESULTS_FILE="$OUTPUT_DIR/.results.tsv"
}

# =============================================================================
# Stage 1: Detect format and extract binary
# =============================================================================

detect_and_extract_binary() {
    log_info "=== Stage 1: Detecting binary format ==="

    local detect_output
    detect_output=$(bash "$SCRIPT_DIR/bin/detect-format.sh" "$BINARY_INPUT" "$METADATA_DIR" 2>&1)

    # Parse the KEY=VALUE output (only lines matching the pattern)
    local format="" output="" is_elf="" compression="" arch=""
    while IFS='=' read -r key value; do
        case "$key" in
            FORMAT) format="$value" ;;
            OUTPUT) output="$value" ;;
            IS_ELF) is_elf="$value" ;;
            COMPRESSION) compression="$value" ;;
            ARCH) arch="$value" ;;
        esac
    done < <(echo "$detect_output" | grep -E '^[A-Z_]+=')

    # Print stderr lines (log messages from detect-format)
    echo "$detect_output" | grep -E '^\[' >&2 || true

    if [[ -z "$output" ]] || [[ ! -f "$output" ]]; then
        log_error "Binary extraction failed"
        exit 1
    fi

    VMLINUX_PATH="$output"
    IS_ELF="${is_elf:-no}"

    if [[ -n "$ARCH_OVERRIDE" ]]; then
        DETECTED_ARCH="$ARCH_OVERRIDE"
    elif [[ -n "$arch" ]]; then
        DETECTED_ARCH="$arch"
    fi

    log_info "Binary: $VMLINUX_PATH (format=$format, elf=$IS_ELF, compression=$compression)"
}

# =============================================================================
# Stage 2: Extract metadata from binary
# =============================================================================

extract_binary_metadata() {
    log_info "=== Stage 2: Extracting binary metadata ==="

    local meta_args=("$VMLINUX_PATH" "$METADATA_DIR")
    [[ -n "$ARCH_OVERRIDE" ]] && meta_args+=(--arch "$ARCH_OVERRIDE")
    [[ "$IS_ELF" == "yes" ]] && meta_args+=(--elf)

    bash "$SCRIPT_DIR/bin/extract-metadata.sh" "${meta_args[@]}" 2>&1 | \
        grep -E '^\[' >&2 || true

    # Load metadata
    if [[ -f "$METADATA_DIR/metadata.env" ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                KERNEL_VERSION) KERNEL_VERSION="$value" ;;
                KERNEL_BASE) KERNEL_BASE="$value" ;;
                ARCH) [[ -z "$DETECTED_ARCH" ]] && DETECTED_ARCH="$value" ;;
                IS_ELF) IS_ELF="$value" ;;
                HAS_SYMBOLS) HAS_SYMBOLS="$value" ;;
                HAS_IKCONFIG) HAS_IKCONFIG="$value" ;;
            esac
        done < "$METADATA_DIR/metadata.env"
    fi

    if [[ -z "$KERNEL_VERSION" ]] || [[ "$KERNEL_VERSION" == "unknown" ]]; then
        log_error "Could not detect kernel version from binary"
        log_error "This file may not be a Linux kernel binary"
        exit 1
    fi

    # Extract base version (strip vendor suffix for NVD matching)
    if [[ -z "$KERNEL_BASE" ]]; then
        KERNEL_BASE=$(echo "$KERNEL_VERSION" | grep -oP '^[0-9]+\.[0-9]+\.[0-9]+' || echo "$KERNEL_VERSION")
    fi

    log_info "Kernel version: $KERNEL_VERSION (base: $KERNEL_BASE)"
    log_info "Architecture: $DETECTED_ARCH"
    log_info "ELF format: $IS_ELF"
    log_info "Has symbols: $HAS_SYMBOLS"
    log_info "Has embedded config: $HAS_IKCONFIG"
}

# =============================================================================
# Stage 2b: Extract metadata from kernel modules (.ko files)
# =============================================================================

extract_module_metadata() {
    if [[ -z "$MODULES_DIR" ]]; then
        return
    fi

    log_info "=== Stage 2b: Scanning kernel modules (.ko files) ==="

    local mod_syms_file="$METADATA_DIR/module_kallsyms.txt"
    local mod_strings_file="$METADATA_DIR/module_strings.txt"
    local mod_list_file="$METADATA_DIR/module_list.txt"

    # Find all .ko files (handle compressed modules too)
    local ko_files=()
    local ko_count=0

    while IFS= read -r -d '' kofile; do
        ko_files+=("$kofile")
        ((ko_count++)) || true
    done < <(find "$MODULES_DIR" \( -name "*.ko" -o -name "*.ko.xz" \
             -o -name "*.ko.zst" -o -name "*.ko.gz" \) -print0 2>/dev/null)

    if [[ "$ko_count" -eq 0 ]]; then
        log_warn "No .ko files found in $MODULES_DIR"
        return
    fi

    log_info "Found $ko_count kernel module files"

    # Extract symbols and strings from all modules
    > "$mod_syms_file"
    > "$mod_strings_file"
    > "$mod_list_file"

    local processed=0
    local tmp_ko=""

    for kofile in "${ko_files[@]}"; do
        local basename_ko
        basename_ko=$(basename "$kofile")
        local mod_name="${basename_ko%%.*}"  # Strip .ko.* extension

        echo "$mod_name" >> "$mod_list_file"

        # Handle compressed modules
        local actual_ko="$kofile"
        if [[ "$kofile" == *.ko.xz ]]; then
            tmp_ko=$(mktemp /tmp/ko_XXXXXX.ko)
            xz -dc "$kofile" > "$tmp_ko" 2>/dev/null || continue
            actual_ko="$tmp_ko"
        elif [[ "$kofile" == *.ko.zst ]]; then
            tmp_ko=$(mktemp /tmp/ko_XXXXXX.ko)
            zstd -dc "$kofile" > "$tmp_ko" 2>/dev/null || continue
            actual_ko="$tmp_ko"
        elif [[ "$kofile" == *.ko.gz ]]; then
            tmp_ko=$(mktemp /tmp/ko_XXXXXX.ko)
            gzip -dc "$kofile" > "$tmp_ko" 2>/dev/null || continue
            actual_ko="$tmp_ko"
        fi

        # Extract symbols (nm format)
        nm "$actual_ko" 2>/dev/null >> "$mod_syms_file" || true

        # Extract strings (min length 8)
        strings -n 8 "$actual_ko" 2>/dev/null >> "$mod_strings_file" || true

        # Clean up temp file
        [[ -n "$tmp_ko" && -f "$tmp_ko" ]] && rm -f "$tmp_ko"
        tmp_ko=""

        ((processed++)) || true
        if (( processed % 500 == 0 )); then
            log_info "  Processed $processed/$ko_count modules..."
        fi
    done

    log_info "  Processed $processed modules"

    # Merge module symbols into main kallsyms.txt
    local main_syms="$METADATA_DIR/kallsyms.txt"
    if [[ -s "$mod_syms_file" ]]; then
        local mod_sym_count
        mod_sym_count=$(wc -l < "$mod_syms_file")

        # Append module symbols to the main file
        # The Python loader (BinaryMatcher._load_symbols) uses a dict,
        # so duplicates are harmless (last occurrence wins).
        cat "$mod_syms_file" >> "$main_syms"

        local total
        total=$(wc -l < "$main_syms")
        log_info "  Merged symbols: +${mod_sym_count} from modules (total: $total)"
    fi

    # Merge module strings into main strings.txt
    local main_strings="$METADATA_DIR/strings.txt"
    if [[ -s "$mod_strings_file" ]]; then
        local mod_str_count
        mod_str_count=$(wc -l < "$mod_strings_file")

        # Append module strings to the main file
        # The Python loader (BinaryMatcher._load_strings) uses a set,
        # so duplicates are harmless.
        cat "$mod_strings_file" >> "$main_strings"

        local total
        total=$(wc -l < "$main_strings")
        log_info "  Merged strings: +${mod_str_count} from modules (total: $total)"
    fi

    # Update HAS_SYMBOLS if modules provided new symbols
    if [[ -s "$mod_syms_file" ]]; then
        HAS_SYMBOLS="yes"
    fi

    log_info "Module scan complete"
}

# =============================================================================
# Stage 3: Scan NVD for kernel CVEs (adapted from kernel-backport-checker.sh)
# =============================================================================

scan_nvd_for_kernel_cves() {
    local cache_file="$OUTPUT_DIR/.nvd_kernel_cves_${KERNEL_BASE}.tsv"

    if [[ -f "$cache_file" ]]; then
        log_info "Using cached NVD scan: $cache_file"
        AFFECTED_CVES_FILE="$cache_file"
        local count
        count=$(wc -l < "$cache_file")
        log_info "  Cached: $count CVEs affecting kernel $KERNEL_BASE"
        return
    fi

    log_info "=== Stage 3: Scanning NVD feeds for CVEs affecting kernel $KERNEL_BASE ==="

    # Phase 1: Find all JSON files with Linux kernel CPEs
    log_info "  Phase 1: Finding kernel CVE files..."
    local kernel_cve_list="$OUTPUT_DIR/.kernel_cve_files.txt"
    find "$NVD_FEEDS_DIR" -name "*.json" -path "*/CVE-*" \
        -exec grep -l "cpe:2.3:o:linux:linux_kernel" {} + 2>/dev/null > "$kernel_cve_list" || true

    local total_files
    total_files=$(wc -l < "$kernel_cve_list")
    log_info "  Found $total_files CVE files with Linux kernel CPEs"

    # Phase 2: Bulk extract version ranges
    log_info "  Phase 2: Extracting version ranges..."
    local raw_ranges="$OUTPUT_DIR/.raw_ranges.tsv"

    cat "$kernel_cve_list" | xargs -P1 -n200 jq -r '
        select(.configurations) |
        .id as $id |
        (
            if .metrics.cvssMetricV31 then
                (.metrics.cvssMetricV31 | sort_by(if .type == "Primary" then 0 else 1 end) | .[0].cvssData |
                    [(.baseScore | tostring), .baseSeverity])
            elif .metrics.cvssMetricV30 then
                (.metrics.cvssMetricV30 | sort_by(if .type == "Primary" then 0 else 1 end) | .[0].cvssData |
                    [(.baseScore | tostring), .baseSeverity])
            elif .metrics.cvssMetricV2 then
                (.metrics.cvssMetricV2 | sort_by(if .type == "Primary" then 0 else 1 end) | .[0] |
                    [(.cvssData.baseScore | tostring), (.baseSeverity // "N/A")])
            else
                ["N/A", "N/A"]
            end
        ) as $cvss |
        ((.descriptions // []) | map(select(.lang == "en")) | .[0].value // "N/A" |
            gsub("[\\n\\r\\t\\\\n]"; " ") | gsub("\\s+"; " ") | .[0:200]) as $desc |
        .configurations[]?.nodes[]?.cpeMatch[]? |
        select(.vulnerable == true) |
        select(.criteria | test("cpe:2\\.3:o:linux:linux_kernel:")) |
        (.criteria | split(":") | .[5]) as $cpe_ver |
        if $cpe_ver == "*" then
            [$id, $cvss[0], $cvss[1],
             (.versionStartIncluding // ""), (.versionStartExcluding // ""),
             (.versionEndIncluding // ""), (.versionEndExcluding // ""),
             "", $desc] | @tsv
        else
            [$id, $cvss[0], $cvss[1],
             "", "", "", "",
             $cpe_ver, $desc] | @tsv
        end
    ' 2>/dev/null > "$raw_ranges" || true

    local range_count
    range_count=$(wc -l < "$raw_ranges")
    log_info "  Extracted $range_count version entries"

    # Phase 3: Filter by kernel version
    log_info "  Phase 3: Filtering for version $KERNEL_BASE..."

    awk -F'\t' -v kver="$KERNEL_BASE" '
        function ver_cmp(a, b,    na, nb, pa, pb, i, max) {
            na = split(a, pa, ".")
            nb = split(b, pb, ".")
            max = na > nb ? na : nb
            for (i = 1; i <= max; i++) {
                if ((pa[i]+0) < (pb[i]+0)) return -1
                if ((pa[i]+0) > (pb[i]+0)) return 1
            }
            return 0
        }
        {
            si = $4; se = $5; ei = $6; ee = $7; exact = $8
            ok = 0

            if (exact != "") {
                if (ver_cmp(kver, exact) == 0) ok = 1
            } else if (si == "" && se == "" && ei == "" && ee == "") {
                ok = 0
            } else {
                ok = 1
                if (si != "" && ver_cmp(kver, si) < 0) ok = 0
                if (se != "" && ver_cmp(kver, se) <= 0) ok = 0
                if (ei != "" && ver_cmp(kver, ei) > 0) ok = 0
                if (ee != "" && ver_cmp(kver, ee) >= 0) ok = 0
            }

            if (ok && !seen[$1]++) {
                print $1 "\t" $2 "\t" $3 "\t" $9
            }
        }
    ' "$raw_ranges" > "$cache_file"

    rm -f "$kernel_cve_list" "$raw_ranges"

    AFFECTED_CVES_FILE="$cache_file"
    local matched
    matched=$(wc -l < "$cache_file")
    log_info "NVD scan complete: $matched CVEs affect kernel $KERNEL_BASE"
}

# =============================================================================
# Stage 4: Extract fix references from NVD
# =============================================================================

extract_nvd_fix_refs() {
    local cache_file="$OUTPUT_DIR/.nvd_fix_refs_${KERNEL_BASE}.tsv"

    if [[ -f "$cache_file" ]]; then
        log_info "Using cached NVD fix refs: $cache_file"
        NVD_FIX_REFS_FILE="$cache_file"
        local count
        count=$(awk -F'\t' '{print $1}' "$cache_file" | sort -u | wc -l)
        log_info "  Cached: fix refs for $count CVEs"
        return
    fi

    log_info "=== Stage 4: Extracting fix commit hashes from NVD references (jobs=$JOBS) ==="

    local nvd_dir="$NVD_FEEDS_DIR"

    cut -f1 "$AFFECTED_CVES_FILE" | \
    xargs -P"$JOBS" -I{} bash -c '
        cve_id="{}"
        nvd_dir="'"$nvd_dir"'"
        year="CVE-${cve_id:4:4}"
        num="${cve_id##*-}"
        numlen=${#num}
        if [[ "$numlen" -le 2 ]]; then
            prefix="${year}-${num}xx"
        else
            prefix="${year}-${num:0:$((numlen-2))}xx"
        fi
        json_path="$nvd_dir/$year/$prefix/$cve_id.json"
        [[ -f "$json_path" ]] || exit 0
        jq -r --arg cve "$cve_id" '"'"'
            [.references[]?.url |
             select(
                 test("git\\.kernel\\.org.*/c/[0-9a-f]") or
                 test("git\\.kernel\\.org.*/commit/\\?.*id=[0-9a-f]") or
                 test("github\\.com/torvalds/linux/commit/[0-9a-f]") or
                 test("kernel\\.dance/[0-9a-f]") or
                 test("[?&;]h=[0-9a-f]{8}") or
                 test("%3Bh=[0-9a-f]{8}")
             ) |
             if   test("git\\.kernel\\.org.*/c/[0-9a-f]")                then capture(".*/c/(?<h>[0-9a-f]+)").h
             elif test("[?&]id=[0-9a-f]{8}")                              then capture("[?&]id=(?<h>[0-9a-f]+)").h
             elif test("github\\.com/torvalds/linux/commit/[0-9a-f]")    then capture("/commit/(?<h>[0-9a-f]+)").h
             elif test("kernel\\.dance/[0-9a-f]")                        then capture("dance/(?<h>[0-9a-f]+)").h
             elif test("%3Bh=[0-9a-f]{8}")                               then capture("%3Bh=(?<h>[0-9a-f]+)").h
             elif test(";h=[0-9a-f]{8}")                                  then capture(";h=(?<h>[0-9a-f]+)").h
             else empty end |
             select(. != null) | select(length >= 8)
            ] | unique[] |
            $cve + "\t" + .
        '"'"' "$json_path" 2>/dev/null
    ' > "$cache_file" || true

    NVD_FIX_REFS_FILE="$cache_file"
    local ref_count cve_count
    ref_count=$(wc -l < "$cache_file")
    cve_count=$(awk -F'\t' '{print $1}' "$cache_file" | sort -u | wc -l)
    log_info "Extracted $ref_count fix commit refs for $cve_count CVEs"
}

# =============================================================================
# Stage 5: Build CISA KEV index
# =============================================================================

build_kev_index() {
    log_info "=== Stage 5: Building CISA KEV index ==="
    jq -r '.vulnerabilities[].cveID' "$KEV_FILE" 2>/dev/null | sort -u > "$KEV_INDEX"
    local count
    count=$(wc -l < "$KEV_INDEX")
    log_info "KEV index built: $count CVEs"
}

# =============================================================================
# Stage 5b: Search git log for CVE mentions (backported CVEs)
# =============================================================================

extract_backported_cves() {
    local backported_file="$OUTPUT_DIR/.backported_cves.txt"
    > "$backported_file"

    log_info "=== Stage 5b: Searching git log for CVE mentions ==="

    # Search upstream repo
    log_info "  Searching upstream repo..."
    git -C "$KERNEL_DIR" log --all --grep='CVE-' --format='%H %s' 2>/dev/null | \
    while IFS=' ' read -r hash subject; do
        # Extract CVE IDs from the subject/commit message
        echo "$subject" | grep -oP 'CVE-[0-9]{4}-[0-9]+' | while read -r cve_id; do
            printf '%s\t%s\n' "$cve_id" "$hash"
        done
    done >> "$backported_file" || true

    # Search stable/vendor repo if provided
    if [[ -n "$STABLE_DIR" ]]; then
        log_info "  Searching stable/vendor repo..."
        git -C "$STABLE_DIR" log --all --grep='CVE-' --format='%H %s' 2>/dev/null | \
        while IFS=' ' read -r hash subject; do
            echo "$subject" | grep -oP 'CVE-[0-9]{4}-[0-9]+' | while read -r cve_id; do
                printf '%s\t%s\n' "$cve_id" "$hash"
            done
        done >> "$backported_file" || true
    fi

    # Deduplicate
    sort -u -o "$backported_file" "$backported_file"

    local bp_count
    bp_count=$(wc -l < "$backported_file")
    log_info "  Found $bp_count CVE-commit mappings from git log"
}

# =============================================================================
# Stage 6: Generate fix signatures from upstream and stable branch diffs
# =============================================================================

generate_fix_signatures() {
    log_info "=== Stage 6: Generating fix signatures from commit diffs (jobs=$JOBS) ==="

    if [[ ! -f "$NVD_FIX_REFS_FILE" ]]; then
        log_warn "No fix references available, skipping signature generation"
        return
    fi

    local ref_count
    ref_count=$(wc -l < "$NVD_FIX_REFS_FILE")
    log_info "Generating signatures for $ref_count commit references..."

    # Build commit-CVE mapping file for the Python module
    local mapping_file="$OUTPUT_DIR/.cve_commit_mapping.tsv"
    cp "$NVD_FIX_REFS_FILE" "$mapping_file"

    # If we also have backported CVEs from git log search, append those
    local backported_cves_file="$OUTPUT_DIR/.backported_cves.txt"
    if [[ -f "$backported_cves_file" ]]; then
        local extra
        extra=$(wc -l < "$backported_cves_file")
        log_info "  Adding $extra backported CVE-commit mappings from git log search"
        cat "$backported_cves_file" >> "$mapping_file"
    fi

    # Run signature generation against upstream repo first
    log_info "  Extracting signatures from upstream repo..."
    python3 "$SCRIPT_DIR/lib/signature_db.py" generate \
        "$KERNEL_DIR" \
        "$mapping_file" \
        --db "$SIG_DB_DIR" \
        --jobs "$JOBS"

    # If a stable/vendor repo is provided, try to extract signatures for
    # commits that failed in the upstream repo (these are stable-branch
    # backport commit hashes that only exist in the stable repo).
    if [[ -n "$STABLE_DIR" ]]; then
        # Find hashes that have index entries but no signature files
        local retry_mapping="$OUTPUT_DIR/.retry_mapping.tsv"
        python3 -c "
import json, os, sys
sig_dir = '$SIG_DB_DIR'
index_file = os.path.join(sig_dir, 'index.json')
if not os.path.exists(index_file):
    sys.exit(0)
with open(index_file) as f:
    index = json.load(f)
count = 0
for cve_id, hashes in index.items():
    for h in hashes:
        sig_path = os.path.join(sig_dir, 'sigs', h[:2], h + '.json')
        if not os.path.exists(sig_path):
            print(f'{cve_id}\t{h}')
            count += 1
print(f'[INFO]   {count} commits need stable branch lookup', file=sys.stderr)
" > "$retry_mapping" 2>&1 | grep -E '^\[' >&2 || true

        local retry_count
        retry_count=$(wc -l < "$retry_mapping")
        if [[ "$retry_count" -gt 0 ]]; then
            log_info "  Extracting $retry_count signatures from stable repo..."
            python3 "$SCRIPT_DIR/lib/signature_db.py" generate \
                "$STABLE_DIR" \
                "$retry_mapping" \
                --db "$SIG_DB_DIR" \
                --jobs "$JOBS"
        fi
        rm -f "$retry_mapping"
    fi

    rm -f "$mapping_file"
}

# =============================================================================
# Stage 7: Match signatures against binary
# =============================================================================

match_signatures_against_binary() {
    log_info "=== Stage 7: Matching fix signatures against kernel binary ==="

    # Prepare file paths for the matcher
    local strings_file="$METADATA_DIR/strings.txt"
    local symbols_file="$METADATA_DIR/kallsyms.txt"
    local r2_flag=""
    [[ "$USE_R2" == "no" ]] && r2_flag="--no-r2"

    # Build the results by processing each CVE
    > "$RESULTS_FILE"

    local total_cves
    total_cves=$(wc -l < "$AFFECTED_CVES_FILE")
    log_info "Processing $total_cves CVEs..."

    # Determine config file to use:
    # Priority: user-provided -k > ikconfig > builtin_modules inference
    local config_file=""
    local builtin_modules_file="$METADATA_DIR/builtin_modules.txt"
    local ikconfig_file="$METADATA_DIR/ikconfig.txt"

    if [[ -n "$KERNEL_CONFIG" ]]; then
        config_file="$KERNEL_CONFIG"
        log_info "Using user-provided kernel config: $config_file"
    elif [[ -f "$ikconfig_file" ]]; then
        config_file="$ikconfig_file"
        log_info "Using embedded ikconfig from binary"
    else
        log_info "No .config available; will use module/symbol inference for CONFIG filtering"
    fi

    # Process CVEs using a Python driver script for efficiency
    # (avoids starting a new Python process per CVE)
    python3 - "$VMLINUX_PATH" "$AFFECTED_CVES_FILE" "$NVD_FIX_REFS_FILE" \
              "$SIG_DB_DIR" "$RESULTS_FILE" "$KEV_INDEX" \
              "$strings_file" "$symbols_file" \
              "$IS_ELF" "$DETECTED_ARCH" "$USE_R2" \
              "$JOBS" "$config_file" "$KERNEL_DIR" \
              "$builtin_modules_file" << 'PYTHON_DRIVER'
import sys
import os
import json
from concurrent.futures import ProcessPoolExecutor, as_completed

# Add the script directory's lib to path
script_dir = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv[0] else '.'
# We're running inline, so find lib relative to the actual script dir
# The args tell us where things are

binary_path = sys.argv[1]
affected_cves_file = sys.argv[2]
fix_refs_file = sys.argv[3]
sig_db_dir = sys.argv[4]
results_file = sys.argv[5]
kev_index_file = sys.argv[6]
strings_file = sys.argv[7]
symbols_file = sys.argv[8]
is_elf = sys.argv[9] == "yes"
arch = sys.argv[10]
use_r2 = sys.argv[11] == "yes"
max_jobs = int(sys.argv[12])
config_file = sys.argv[13] if len(sys.argv) > 13 else ""
kernel_src_dir = sys.argv[14] if len(sys.argv) > 14 else ""
builtin_modules_file = sys.argv[15] if len(sys.argv) > 15 else ""

# Find lib directory
# The driver is invoked from the binary-checker directory
lib_dir = None
for candidate in [
    os.path.join(os.path.dirname(os.path.realpath(binary_path)), '..', 'lib'),
    os.path.join(os.getcwd(), 'lib'),
    os.path.join(os.getcwd(), 'binary-checker', 'lib'),
]:
    if os.path.exists(os.path.join(candidate, 'binary_matcher.py')):
        lib_dir = os.path.dirname(candidate)
        break

# Also try relative to where main.sh lives
for env_var in ['SCRIPT_DIR']:
    val = os.environ.get(env_var, '')
    if val:
        candidate = os.path.join(val, 'lib')
        if os.path.exists(os.path.join(candidate, 'binary_matcher.py')):
            lib_dir = val
            break

if lib_dir is None:
    # Last resort: check parent dirs
    check = os.path.dirname(os.path.abspath(affected_cves_file))
    while check != '/':
        candidate = os.path.join(check, 'binary-checker', 'lib')
        if os.path.exists(os.path.join(candidate, 'binary_matcher.py')):
            lib_dir = os.path.join(check, 'binary-checker')
            break
        check = os.path.dirname(check)

if lib_dir:
    sys.path.insert(0, lib_dir)

from lib.binary_matcher import BinaryMatcher, MatchResult
from lib.signature_db import SignatureDatabase
from lib.config_resolver import ConfigResolver

# Load affected CVEs with their details
cves = {}  # CVE-ID -> {cvss, severity, description}
with open(affected_cves_file, 'r') as f:
    for line in f:
        parts = line.rstrip('\n').split('\t')
        if len(parts) >= 4:
            cves[parts[0]] = {
                'cvss': parts[1],
                'severity': parts[2],
                'description': parts[3],
            }

# Load fix refs: CVE -> [commit_hashes]
fix_refs = {}
if os.path.exists(fix_refs_file):
    with open(fix_refs_file, 'r') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) >= 2:
                cve_id, commit_hash = parts[0], parts[1]
                if cve_id not in fix_refs:
                    fix_refs[cve_id] = []
                fix_refs[cve_id].append(commit_hash)

# Load KEV index
kev_set = set()
if os.path.exists(kev_index_file):
    with open(kev_index_file, 'r') as f:
        for line in f:
            kev_set.add(line.strip())

# Initialize matcher and signature database
print(f"[INFO] Initializing binary matcher (elf={is_elf}, arch={arch}, r2={use_r2})",
      file=sys.stderr)

sf = strings_file if os.path.exists(strings_file) else None
syf = symbols_file if os.path.exists(symbols_file) else None

matcher = BinaryMatcher(
    binary_path,
    strings_file=sf,
    symbols_file=syf,
    is_elf=is_elf,
    arch=arch,
    use_r2=use_r2,
)

db = SignatureDatabase(sig_db_dir)

# Initialize CONFIG resolver for filtering
config_resolver = None
binary_symbols = None  # For source-file applicability checks

if kernel_src_dir and os.path.isdir(kernel_src_dir):
    config_resolver = ConfigResolver(kernel_src_dir, arch=arch)

    # Always build Makefile mapping first (needed for module auto-mapping)
    print(f"[INFO] Building CONFIG mapping from kernel Makefiles...",
          file=sys.stderr)
    file_count, dir_count = config_resolver.build_config_mapping()
    print(f"[INFO] CONFIG mapping: {file_count} files, {dir_count} directories",
          file=sys.stderr)

    # Load config (priority: user .config > ikconfig > inferred from binary)
    config_count = 0
    if config_file and os.path.exists(config_file):
        config_count = config_resolver.load_config(config_file)
        print(f"[INFO] Loaded {config_count} enabled CONFIGs from user-provided .config",
              file=sys.stderr)
    elif os.path.exists(strings_file.replace('strings.txt', 'ikconfig.txt')):
        ikconfig_path = strings_file.replace('strings.txt', 'ikconfig.txt')
        config_count = config_resolver.load_ikconfig(ikconfig_path)
        print(f"[INFO] Loaded {config_count} enabled CONFIGs from embedded ikconfig",
              file=sys.stderr)
    elif builtin_modules_file and os.path.exists(builtin_modules_file):
        config_count = config_resolver.infer_config_from_modules(
            builtin_modules_file, syf)
        print(f"[INFO] Inferred {config_count} enabled CONFIGs from modules/symbols",
              file=sys.stderr)

    if config_count == 0:
        config_resolver = None
        print(f"[INFO] No kernel config available, skipping CONFIG filtering",
              file=sys.stderr)

    # Load symbol set for source-file applicability checks
    if syf and os.path.exists(syf):
        binary_symbols = set()
        with open(syf, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3:
                    binary_symbols.add(parts[2])

# Process each CVE
total = len(cves)
processed = 0
results = []

for cve_id, cve_info in sorted(cves.items()):
    processed += 1
    in_kev = "Yes" if cve_id in kev_set else "No"

    # Get signatures for this CVE
    sigs = db.get_signatures_for_cve(cve_id)

    if not sigs:
        # No fix references or signature generation failed
        verdict = "INCONCLUSIVE"
        confidence = 0.0
        details_str = "No fix commit references available"
    else:
        # Match against binary
        result = matcher.match_cve(sigs)
        verdict = result.verdict
        confidence = result.confidence
        reasons = result.details.get('reasons', [])
        if not reasons and 'per_commit' in result.details:
            # Aggregate result
            reasons = [f"Commits: {result.details.get('verdict_counts', {})}"]
        details_str = "; ".join(reasons) if reasons else ""

    # Determine config status using ConfigResolver
    config_status = "UNKNOWN"
    affected_config = "N/A"

    if config_resolver and sigs:
        # Collect all affected files across all fix commits for this CVE
        all_affected_files = []
        for sig in sigs:
            all_affected_files.extend(sig.affected_files)

        if all_affected_files:
            affected_config, config_status = config_resolver.get_config_status_for_files(
                all_affected_files)

            # Config-based verdict overrides:
            #
            # 1. DISABLED or wrong arch -> NOT_APPLICABLE
            if config_status in ("DISABLED", "NOT_THIS_ARCH"):
                verdict = "NOT_APPLICABLE"
                confidence = 0.9

            # 2. ENABLED + matcher said NOT_APPLICABLE (functions not found):
            #    The config proves the code IS compiled in. Functions missing
            #    from symbols because they're static/inlined. Trust the config.
            elif config_status == "ENABLED" and verdict == "NOT_APPLICABLE":
                verdict = "UNFIXED"
                confidence = 0.4

            # 3. ENABLED + INCONCLUSIVE (no usable signatures):
            #    We know the code is compiled in but can't find fix evidence.
            #    Only override to UNFIXED if there's positive vulnerability
            #    evidence (removed strings still present).  When the signature
            #    is truly empty (no strings/symbols to match), the fix may
            #    be present but undetectable at the binary level — keep
            #    INCONCLUSIVE to avoid inflating the UNFIXED count with
            #    unreliable 0.3-confidence verdicts.
            elif config_status == "ENABLED" and verdict == "INCONCLUSIVE":
                if (hasattr(result, 'string_removed_matched') and
                        result.string_removed_matched > 0):
                    # Vulnerable strings found in binary -> genuinely unfixed
                    verdict = "UNFIXED"
                    confidence = 0.35
                # else: keep INCONCLUSIVE — no signal either way

            # 4. UNKNOWN config + NOT_APPLICABLE/INCONCLUSIVE:
            #    Config mapping didn't find the CONFIG. Fall back to checking
            #    if any function from the affected SOURCE FILES exists in
            #    the binary symbol table (handles static/inlined functions).
            elif (config_status == "UNKNOWN" and
                  verdict in ("NOT_APPLICABLE", "INCONCLUSIVE") and
                  binary_symbols and config_resolver):
                if config_resolver.check_files_compiled_in(
                        all_affected_files, binary_symbols):
                    config_status = "INFERRED"
                    verdict = "UNFIXED"
                    confidence = 0.35

    # Also handle CVEs with no signatures but config available
    if config_resolver and not sigs:
        pass

    # Write result line
    # Format: CVE-ID \t Severity \t CVSS \t KEV \t Status \t Confidence \t Config \t ConfigStatus \t Description
    result_line = (f"{cve_id}\t{cve_info['severity']}\t{cve_info['cvss']}\t"
                   f"{in_kev}\t{verdict}\t{confidence:.3f}\t"
                   f"{affected_config}\t{config_status}\t{cve_info['description']}")
    results.append(result_line)

    if processed % 50 == 0 or processed == total:
        print(f"\r[INFO]   Processed {processed}/{total} CVEs "
              f"({processed*100//total}%)", end='', file=sys.stderr)

print(file=sys.stderr)

# Write results
with open(results_file, 'w') as f:
    for line in results:
        f.write(line + '\n')

# Print summary
verdicts = {}
for line in results:
    v = line.split('\t')[4]
    verdicts[v] = verdicts.get(v, 0) + 1

print(f"[INFO] Matching complete. Verdict distribution:", file=sys.stderr)
for v in ['FIXED', 'LIKELY_FIXED', 'UNFIXED', 'INCONCLUSIVE', 'NOT_APPLICABLE']:
    if v in verdicts:
        print(f"[INFO]   {v}: {verdicts[v]}", file=sys.stderr)

# Config status summary
config_statuses = {}
for line in results:
    cs = line.split('\t')[7]
    config_statuses[cs] = config_statuses.get(cs, 0) + 1
if any(cs != "UNKNOWN" for cs in config_statuses):
    print(f"[INFO] Config status distribution:", file=sys.stderr)
    for cs in ['ENABLED', 'DISABLED', 'UNKNOWN']:
        if cs in config_statuses:
            print(f"[INFO]   {cs}: {config_statuses[cs]}", file=sys.stderr)

matcher.close()
PYTHON_DRIVER

    local result_count
    result_count=$(wc -l < "$RESULTS_FILE")
    log_info "Matching complete: $result_count CVEs processed"
}

# =============================================================================
# Stage 8: Generate CSV report
# =============================================================================

generate_csv() {
    log_info "=== Stage 8: Generating CSV report ==="

    local csv_file="$OUTPUT_DIR/binary-backport-report.csv"

    # Compute summary statistics
    local total fixed unfixed likely inconclusive not_applicable
    total=$(wc -l < "$RESULTS_FILE")
    fixed=$(awk -F'\t' '$5=="FIXED"' "$RESULTS_FILE" | wc -l)
    unfixed=$(awk -F'\t' '$5=="UNFIXED"' "$RESULTS_FILE" | wc -l)
    likely=$(awk -F'\t' '$5=="LIKELY_FIXED"' "$RESULTS_FILE" | wc -l)
    inconclusive=$(awk -F'\t' '$5=="INCONCLUSIVE"' "$RESULTS_FILE" | wc -l)
    not_applicable=$(awk -F'\t' '$5=="NOT_APPLICABLE"' "$RESULTS_FILE" | wc -l)

    local kev_total kev_unfixed
    kev_total=$(awk -F'\t' '$4=="Yes"' "$RESULTS_FILE" | wc -l)
    kev_unfixed=$(awk -F'\t' '$4=="Yes" && $5=="UNFIXED"' "$RESULTS_FILE" | wc -l)

    local crit_total high_total med_total low_total
    crit_total=$(awk -F'\t' '$2=="CRITICAL"' "$RESULTS_FILE" | wc -l)
    high_total=$(awk -F'\t' '$2=="HIGH"' "$RESULTS_FILE" | wc -l)
    med_total=$(awk -F'\t' '$2=="MEDIUM"' "$RESULTS_FILE" | wc -l)
    low_total=$(awk -F'\t' '$2=="LOW"' "$RESULTS_FILE" | wc -l)

    local unfixed_crit unfixed_high unfixed_med unfixed_low
    unfixed_crit=$(awk -F'\t' '$5=="UNFIXED" && $2=="CRITICAL"' "$RESULTS_FILE" | wc -l)
    unfixed_high=$(awk -F'\t' '$5=="UNFIXED" && $2=="HIGH"' "$RESULTS_FILE" | wc -l)
    unfixed_med=$(awk -F'\t' '$5=="UNFIXED" && $2=="MEDIUM"' "$RESULTS_FILE" | wc -l)
    unfixed_low=$(awk -F'\t' '$5=="UNFIXED" && $2=="LOW"' "$RESULTS_FILE" | wc -l)

    # Write CSV
    {
        echo "# Kernel Binary Backport Checker Report"
        echo "# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "# Binary: $(basename "$BINARY_INPUT")"
        echo "# Kernel Version: $KERNEL_VERSION (base: $KERNEL_BASE)"
        echo "# Architecture: $DETECTED_ARCH"
        echo "# ELF Format: $IS_ELF | Has Symbols: $HAS_SYMBOLS | Has ikconfig: $HAS_IKCONFIG"
        [[ -n "$STABLE_DIR" ]] && echo "# Stable/Vendor Repo: $STABLE_DIR"
        if [[ -n "$MODULES_DIR" ]]; then
            local mod_count=0
            [[ -f "$METADATA_DIR/module_list.txt" ]] && mod_count=$(wc -l < "$METADATA_DIR/module_list.txt")
            echo "# Modules: $mod_count .ko files scanned from $MODULES_DIR"
        fi
        echo "#"
        echo "# Total CVEs: $total"
        echo "#   FIXED: $fixed | LIKELY_FIXED: $likely | UNFIXED: $unfixed"
        echo "#   INCONCLUSIVE: $inconclusive | NOT_APPLICABLE: $not_applicable"
        echo "#"
        echo "# CISA KEV: $kev_total in KEV, $kev_unfixed unfixed"
        echo "#"
        echo "# Severity (all):     CRITICAL=$crit_total HIGH=$high_total MEDIUM=$med_total LOW=$low_total"
        echo "# Severity (unfixed): CRITICAL=$unfixed_crit HIGH=$unfixed_high MEDIUM=$unfixed_med LOW=$unfixed_low"
        echo "#"
        echo "# Analysis Method: Binary signature matching (string/symbol/constant)"
        echo "# NOTE: Binary analysis has inherent limitations. INCONCLUSIVE verdicts"
        echo "# indicate the fix changes only code logic without distinctive string"
        echo "# or symbol changes detectable at the binary level."
        echo "#"
        echo "CVE-ID,Severity,CVSS-Score,In-CISA-KEV,Fix-Status,Confidence,Affected-Config,Config-Status,Description"

        # Sort: UNFIXED first (descending), then by severity
        sort -t$'\t' -k5,5r -k2,2 "$RESULTS_FILE" | \
        awk -F'\t' '{
            # Escape description for CSV
            desc = $9
            gsub(/"/, "'\''", desc)
            gsub(/,/, ";", desc)
            # Output CSV
            printf "%s,%s,%s,%s,%s,%s,%s,%s,\"%s\"\n",
                   $1, $2, $3, $4, $5, $6, $7, $8, desc
        }'
    } > "$csv_file"

    # Cleanup
    rm -f "$RESULTS_FILE"

    log_info "Report written to: $csv_file"

    # Console summary
    echo ""
    echo "============================================================"
    echo "  KERNEL BINARY BACKPORT CHECKER REPORT"
    echo "============================================================"
    echo "  Binary:          $(basename "$BINARY_INPUT")"
    echo "  Kernel Version:  $KERNEL_VERSION"
    echo "  Architecture:    $DETECTED_ARCH"
    echo "  Symbols:         $HAS_SYMBOLS"
    echo "------------------------------------------------------------"
    echo "  Total CVEs:      $total"
    echo "  FIXED:           $fixed"
    echo "  LIKELY_FIXED:    $likely"
    echo "  UNFIXED:         $unfixed"
    echo "  INCONCLUSIVE:    $inconclusive"
    echo "  NOT_APPLICABLE:  $not_applicable"
    echo "------------------------------------------------------------"
    echo "  CISA KEV:        $kev_total total, $kev_unfixed unfixed"
    echo "------------------------------------------------------------"
    echo "  Unfixed by severity:"
    echo "    CRITICAL: $unfixed_crit  HIGH: $unfixed_high"
    echo "    MEDIUM:   $unfixed_med  LOW:  $unfixed_low"
    echo "============================================================"
    echo "  Report: $csv_file"
    echo "============================================================"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    check_dependencies
    parse_args "$@"

    log_info "Kernel Binary Backport Checker v${VERSION}"
    log_info "Binary: $BINARY_INPUT"
    if [[ -n "$STABLE_DIR" ]]; then
        log_info "Stable/Vendor Repo: $STABLE_DIR"
    fi
    if [[ -n "$KERNEL_CONFIG" ]]; then
        log_info "Kernel config: $KERNEL_CONFIG"
    fi
    if [[ -n "$MODULES_DIR" ]]; then
        log_info "Modules dir: $MODULES_DIR"
    fi
    log_info "Jobs: $JOBS"
    echo ""

    local start_time
    start_time=$(date +%s)

    # Export SCRIPT_DIR for Python driver
    export SCRIPT_DIR

    detect_and_extract_binary
    extract_binary_metadata
    extract_module_metadata
    scan_nvd_for_kernel_cves
    extract_nvd_fix_refs
    build_kev_index
    extract_backported_cves
    generate_fix_signatures
    match_signatures_against_binary
    generate_csv

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$(( end_time - start_time ))
    log_info "Total time: ${elapsed}s"
}

main "$@"
