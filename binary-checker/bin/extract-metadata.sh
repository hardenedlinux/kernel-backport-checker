#!/usr/bin/env bash
#
# extract-metadata.sh
#
# Extract metadata from a kernel binary: version string, architecture,
# kallsyms symbols, ikconfig, and built-in module information.
#
# Usage:
#   extract-metadata.sh <kernel-binary> <output-dir> [--arch <arch>]
#
# Output files in <output-dir>:
#   metadata.env        - KEY=VALUE pairs (version, arch, has_symbols, etc.)
#   kallsyms.txt        - Extracted symbol table (if available)
#   ikconfig.txt        - Extracted kernel config (if available)
#   builtin_modules.txt - List of built-in modules (if available)
#   strings.txt         - All printable strings from the binary
#

set -euo pipefail

log_info()  { echo "[extract-metadata] $*" >&2; }
log_warn()  { echo "[extract-metadata][WARN] $*" >&2; }
log_error() { echo "[extract-metadata][ERROR] $*" >&2; }

# =========================================================================
# Version Detection
# =========================================================================

# Extract Linux kernel version string from binary
detect_version() {
    local binary="$1"
    local version_str

    # Method 1: Look for "Linux version X.Y.Z" string
    version_str=$(strings "$binary" 2>/dev/null | \
        grep -oP 'Linux version \K[0-9]+\.[0-9]+\.[0-9]+[^\s]*' | \
        head -1 || true)

    if [[ -n "$version_str" ]]; then
        echo "$version_str"
        return 0
    fi

    # Method 2: Look for version in UTS string format
    version_str=$(strings "$binary" 2>/dev/null | \
        grep -oP '^[0-9]+\.[0-9]+\.[0-9]+[-+.\w]*\s+\(.*@.*\)' | \
        head -1 | awk '{print $1}' || true)

    if [[ -n "$version_str" ]]; then
        echo "$version_str"
        return 0
    fi

    # Method 3: Look for vermagic string (used by modules)
    version_str=$(strings "$binary" 2>/dev/null | \
        grep -oP 'vermagic=\K[0-9]+\.[0-9]+\.[0-9]+[^\s]*' | \
        head -1 || true)

    if [[ -n "$version_str" ]]; then
        echo "$version_str"
        return 0
    fi

    return 1
}

# Parse version into components: MAJOR.MINOR.PATCH
parse_version() {
    local version="$1"
    local major minor patch extra

    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)
    # Patch may have suffix like -rc1, -vendor, etc.
    patch=$(echo "$version" | cut -d. -f3 | grep -oP '^[0-9]+' || echo "0")
    extra=$(echo "$version" | sed -E 's/^[0-9]+\.[0-9]+\.[0-9]+//' || true)

    echo "KERNEL_VERSION=$version"
    echo "KERNEL_MAJOR=$major"
    echo "KERNEL_MINOR=$minor"
    echo "KERNEL_PATCH=$patch"
    echo "KERNEL_EXTRA=$extra"
    echo "KERNEL_BASE=${major}.${minor}.${patch}"
}

# =========================================================================
# Architecture Detection
# =========================================================================

# Detect architecture from binary content (for non-ELF / raw blobs)
detect_arch_from_binary() {
    local binary="$1"
    local is_elf="${2:-no}"

    if [[ "$is_elf" == "yes" ]]; then
        # Use ELF header
        local ei_data em_byte1 em_byte2 e_machine
        ei_data=$(hexdump -v -s 5 -n 1 -e '1/1 "%02x"' "$binary" 2>/dev/null)
        em_byte1=$(hexdump -v -s 18 -n 1 -e '1/1 "%02x"' "$binary" 2>/dev/null)
        em_byte2=$(hexdump -v -s 19 -n 1 -e '1/1 "%02x"' "$binary" 2>/dev/null)

        if [[ "$ei_data" == "01" ]]; then
            e_machine=$(( 16#${em_byte2}${em_byte1} ))
        else
            e_machine=$(( 16#${em_byte1}${em_byte2} ))
        fi

        case "$e_machine" in
            3)   echo "x86" ;;
            8)   echo "mips" ;;
            20)  echo "ppc" ;;
            21)  echo "ppc64" ;;
            40)  echo "arm" ;;
            62)  echo "x86_64" ;;
            183) echo "aarch64" ;;
            243) echo "riscv" ;;
            *)   echo "unknown" ;;
        esac
        return 0
    fi

    # For raw blobs: use heuristics from strings
    local arch_hint

    # Check "Linux version" line for arch hints
    arch_hint=$(strings "$binary" 2>/dev/null | grep "Linux version" | head -1 || true)

    if echo "$arch_hint" | grep -qi "aarch64\|arm64"; then
        echo "aarch64"
    elif echo "$arch_hint" | grep -qi "armv7\|armv6\|arm "; then
        echo "arm"
    elif echo "$arch_hint" | grep -qi "mips"; then
        echo "mips"
    elif echo "$arch_hint" | grep -qi "x86_64\|amd64"; then
        echo "x86_64"
    elif echo "$arch_hint" | grep -qi "i[3456]86\|x86"; then
        echo "x86"
    elif echo "$arch_hint" | grep -qi "ppc\|powerpc"; then
        echo "ppc"
    elif echo "$arch_hint" | grep -qi "riscv\|risc-v"; then
        echo "riscv"
    else
        # Check compiler string
        local gcc_str
        gcc_str=$(strings "$binary" 2>/dev/null | grep -i "gcc.*version\|compiled by" | head -1 || true)
        if echo "$gcc_str" | grep -qi "aarch64"; then
            echo "aarch64"
        elif echo "$gcc_str" | grep -qi "arm"; then
            echo "arm"
        elif echo "$gcc_str" | grep -qi "mips"; then
            echo "mips"
        elif echo "$gcc_str" | grep -qi "x86_64"; then
            echo "x86_64"
        else
            echo "unknown"
        fi
    fi
}

# =========================================================================
# Kallsyms Extraction
# =========================================================================

# Check if kallsyms data is present in the binary
has_kallsyms() {
    local binary="$1"
    # Look for kallsyms markers
    strings "$binary" 2>/dev/null | grep -q "kallsyms" && return 0

    # Look for typical kernel symbol patterns (T/t/D/d type markers)
    # In a kallsyms-enabled kernel, we find sequences of address + type + name
    # Also check for the token table which is a distinctive marker
    grep -qaoP 'kallsyms_token_table|kallsyms_names|kallsyms_markers' "$binary" 2>/dev/null && return 0

    return 1
}

# Extract symbols using multiple strategies
extract_symbols() {
    local binary="$1" output="$2" is_elf="$3"
    local count=0

    if [[ "$is_elf" == "yes" ]]; then
        # Method 1: Standard ELF symbol table (nm/readelf)
        if command -v nm &>/dev/null; then
            nm "$binary" 2>/dev/null | sort > "$output" && \
                count=$(wc -l < "$output")
            if [[ "$count" -gt 100 ]]; then
                log_info "Extracted $count symbols via nm (ELF symbol table)"
                return 0
            fi
        fi

        if command -v readelf &>/dev/null; then
            readelf -s "$binary" 2>/dev/null | \
                awk '/FUNC|OBJECT/ {print $2, $4, $8}' | \
                sort > "$output" && \
                count=$(wc -l < "$output")
            if [[ "$count" -gt 100 ]]; then
                log_info "Extracted $count symbols via readelf"
                return 0
            fi
        fi
    fi

    # Method 2: Use vmlinux-to-elf if available (handles embedded kallsyms)
    if command -v vmlinux-to-elf &>/dev/null; then
        local elf_out="${output%.txt}.elf"
        if vmlinux-to-elf "$binary" "$elf_out" 2>/dev/null; then
            if command -v nm &>/dev/null; then
                nm "$elf_out" 2>/dev/null | sort > "$output" && \
                    count=$(wc -l < "$output")
                if [[ "$count" -gt 100 ]]; then
                    log_info "Extracted $count symbols via vmlinux-to-elf + nm"
                    return 0
                fi
            fi
        fi
        rm -f "$elf_out"
    fi

    # Method 3: Use radare2 to extract function names
    if command -v r2 &>/dev/null; then
        log_info "Attempting symbol extraction via radare2 (this may take a while)..."
        local r2_flags=""
        if [[ "$is_elf" != "yes" ]]; then
            r2_flags="-b 32"  # Assume 32-bit for raw blobs, user can override
        fi
        # Quick analysis - just get flags/symbols without full analysis
        r2 -q $r2_flags -c 'fs symbols; f~[2]' "$binary" 2>/dev/null | \
            sort -u > "$output" && \
            count=$(wc -l < "$output")
        if [[ "$count" -gt 10 ]]; then
            log_info "Extracted $count symbols via radare2"
            return 0
        fi
    fi

    # Method 4: Brute-force kallsyms extraction from raw binary
    # Look for the token table and reconstruct symbol names
    if has_kallsyms "$binary"; then
        log_info "Kallsyms data detected but could not extract symbols"
        log_info "Hint: install 'vmlinux-to-elf' for better symbol extraction:"
        log_info "  pip install vmlinux-to-elf"
        # Write a marker so downstream knows kallsyms exists
        echo "# kallsyms detected but extraction failed" > "$output"
        echo "# Install vmlinux-to-elf: pip install vmlinux-to-elf" >> "$output"
        return 1
    fi

    log_warn "No symbols found in binary (fully stripped, no kallsyms)"
    echo "# No symbols found" > "$output"
    return 1
}

# =========================================================================
# Ikconfig Extraction
# =========================================================================

# Extract embedded kernel config (CONFIG_IKCONFIG)
extract_ikconfig() {
    local binary="$1" output="$2"

    # The ikconfig blob is wrapped with magic markers:
    #   IKCFG_ST (start) and IKCFG_ED (end)
    # Between them is a gzip-compressed .config

    local start_marker="IKCFG_ST"
    local end_marker="IKCFG_ED"

    # Find the start marker
    local start_offset
    start_offset=$(grep -aboF "$start_marker" "$binary" 2>/dev/null | head -1 | cut -d: -f1 || true)

    if [[ -z "$start_offset" ]]; then
        log_info "No embedded kernel config found (CONFIG_IKCONFIG not enabled)"
        return 1
    fi

    log_info "Found IKCFG_ST marker at offset $start_offset"

    # Skip past the marker itself
    start_offset=$(( start_offset + ${#start_marker} ))

    # Find the end marker
    local end_offset
    end_offset=$(grep -aboF "$end_marker" "$binary" 2>/dev/null | head -1 | cut -d: -f1 || true)

    if [[ -z "$end_offset" ]]; then
        log_warn "Found IKCFG_ST but not IKCFG_ED -- corrupt ikconfig?"
        return 1
    fi

    local blob_size=$(( end_offset - start_offset ))
    if [[ "$blob_size" -lt 10 ]]; then
        log_warn "ikconfig blob too small ($blob_size bytes)"
        return 1
    fi

    log_info "Extracting ikconfig ($blob_size bytes compressed)"

    # Extract and decompress
    dd if="$binary" bs=1 skip="$start_offset" count="$blob_size" 2>/dev/null | \
        gunzip -c > "$output" 2>/dev/null

    local lines
    lines=$(wc -l < "$output" 2>/dev/null || echo 0)
    if [[ "$lines" -gt 10 ]]; then
        log_info "Successfully extracted kernel config ($lines lines)"
        return 0
    else
        log_warn "ikconfig extraction produced too few lines ($lines)"
        rm -f "$output"
        return 1
    fi
}

# =========================================================================
# Built-in Module Detection
# =========================================================================

# Extract list of built-in modules/subsystems from the binary
extract_builtin_info() {
    local binary="$1" output="$2"

    {
        # Method 1: Look for __initcall entries (indicates compiled-in modules)
        # These appear as strings like "__initcall_<name>6" in the binary
        strings "$binary" 2>/dev/null | \
            grep -oP '__initcall_\K[a-zA-Z0-9_]+' | \
            sed 's/[0-9]*$//' | sort -u

        # Method 2: Look for module descriptions/authors
        # MODULE_DESCRIPTION("...") and MODULE_AUTHOR("...") compile into strings
        strings "$binary" 2>/dev/null | \
            grep -oP 'description=\K[^\x00]+' || true

        # Method 3: Look for "file:" vermagic references
        strings "$binary" 2>/dev/null | \
            grep -oP 'file:\K[a-zA-Z0-9_/]+\.c' | \
            sort -u || true

    } > "$output" 2>/dev/null

    local count
    count=$(wc -l < "$output" 2>/dev/null || echo 0)
    if [[ "$count" -gt 0 ]]; then
        log_info "Found $count built-in module/subsystem indicators"
        return 0
    fi
    return 1
}

# =========================================================================
# String Extraction
# =========================================================================

# Extract all strings with minimum length, useful for signature matching
extract_strings() {
    local binary="$1" output="$2"
    local min_length="${3:-8}"

    strings -n "$min_length" "$binary" 2>/dev/null | sort -u > "$output"

    local count
    count=$(wc -l < "$output" 2>/dev/null || echo 0)
    log_info "Extracted $count unique strings (min length: $min_length)"
}

# =========================================================================
# Compiler/Build Info
# =========================================================================

# Extract compiler and build information
extract_build_info() {
    local binary="$1"

    # GCC version
    local gcc_version
    gcc_version=$(strings "$binary" 2>/dev/null | \
        grep -oP 'gcc[- ]version \K[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)

    if [[ -z "$gcc_version" ]]; then
        gcc_version=$(strings "$binary" 2>/dev/null | \
            grep -oP 'GCC: \(.*\) \K[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    fi

    # Clang version
    local clang_version
    clang_version=$(strings "$binary" 2>/dev/null | \
        grep -oP 'clang version \K[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)

    # Build timestamp
    local build_time
    build_time=$(strings "$binary" 2>/dev/null | \
        grep -oP 'Linux version [^ ]+ \([^)]+\) .* \K(#[0-9]+ .*)' | head -1 || true)

    # Full Linux version line (includes compiler, build user, timestamp)
    local full_version_line
    full_version_line=$(strings "$binary" 2>/dev/null | \
        grep "Linux version [0-9]" | head -1 || true)

    if [[ -n "$gcc_version" ]]; then
        echo "COMPILER=gcc"
        echo "COMPILER_VERSION=$gcc_version"
    elif [[ -n "$clang_version" ]]; then
        echo "COMPILER=clang"
        echo "COMPILER_VERSION=$clang_version"
    else
        echo "COMPILER=unknown"
        echo "COMPILER_VERSION=unknown"
    fi

    if [[ -n "$build_time" ]]; then
        echo "BUILD_INFO=$build_time"
    fi

    if [[ -n "$full_version_line" ]]; then
        echo "FULL_VERSION_LINE=$full_version_line"
    fi
}

# =========================================================================
# Main
# =========================================================================

main() {
    local binary=""
    local outdir=""
    local arch_override=""
    local is_elf="no"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --arch)
                arch_override="$2"
                shift 2
                ;;
            --elf)
                is_elf="yes"
                shift
                ;;
            *)
                if [[ -z "$binary" ]]; then
                    binary="$1"
                elif [[ -z "$outdir" ]]; then
                    outdir="$1"
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$binary" ]] || [[ -z "$outdir" ]]; then
        echo "Usage: $0 <kernel-binary> <output-dir> [--arch <arch>] [--elf]" >&2
        exit 1
    fi

    if [[ ! -f "$binary" ]]; then
        log_error "Binary not found: $binary"
        exit 1
    fi

    mkdir -p "$outdir"

    # Auto-detect ELF
    local magic
    magic=$(hexdump -v -s 0 -n 4 -e '1/1 "%02x"' "$binary" 2>/dev/null)
    if [[ "$magic" == "7f454c46" ]]; then
        is_elf="yes"
    fi

    local metadata_file="$outdir/metadata.env"
    > "$metadata_file"

    # ---- Version detection ----
    log_info "=== Detecting kernel version ==="
    local version
    if version=$(detect_version "$binary"); then
        log_info "Kernel version: $version"
        parse_version "$version" >> "$metadata_file"
    else
        log_error "Could not detect kernel version from binary"
        log_error "This binary may not be a Linux kernel, or the version string is missing"
        echo "KERNEL_VERSION=unknown" >> "$metadata_file"
    fi

    # ---- Architecture detection ----
    log_info "=== Detecting architecture ==="
    local arch
    if [[ -n "$arch_override" ]]; then
        arch="$arch_override"
        log_info "Architecture (user-specified): $arch"
    else
        arch=$(detect_arch_from_binary "$binary" "$is_elf")
        log_info "Architecture (detected): $arch"
    fi
    echo "ARCH=$arch" >> "$metadata_file"
    echo "IS_ELF=$is_elf" >> "$metadata_file"

    # ---- Compiler/build info ----
    log_info "=== Extracting build info ==="
    extract_build_info "$binary" >> "$metadata_file"

    # ---- Symbol extraction ----
    log_info "=== Extracting symbols ==="
    local sym_file="$outdir/kallsyms.txt"
    if extract_symbols "$binary" "$sym_file" "$is_elf"; then
        echo "HAS_SYMBOLS=yes" >> "$metadata_file"
        local sym_count
        sym_count=$(grep -cv '^#' "$sym_file" 2>/dev/null || echo 0)
        echo "SYMBOL_COUNT=$sym_count" >> "$metadata_file"
    else
        echo "HAS_SYMBOLS=no" >> "$metadata_file"
        echo "SYMBOL_COUNT=0" >> "$metadata_file"
    fi

    # ---- Ikconfig extraction ----
    log_info "=== Checking for embedded kernel config ==="
    local config_file="$outdir/ikconfig.txt"
    if extract_ikconfig "$binary" "$config_file"; then
        echo "HAS_IKCONFIG=yes" >> "$metadata_file"
    else
        echo "HAS_IKCONFIG=no" >> "$metadata_file"
    fi

    # ---- Built-in modules ----
    log_info "=== Extracting built-in module info ==="
    local builtin_file="$outdir/builtin_modules.txt"
    if extract_builtin_info "$binary" "$builtin_file"; then
        echo "HAS_BUILTIN_INFO=yes" >> "$metadata_file"
    else
        echo "HAS_BUILTIN_INFO=no" >> "$metadata_file"
    fi

    # ---- String extraction (for signature matching) ----
    log_info "=== Extracting strings ==="
    extract_strings "$binary" "$outdir/strings.txt" 8

    # ---- Summary ----
    log_info "=== Metadata extraction complete ==="
    log_info "Results written to: $outdir/"

    # Print metadata to stdout as well
    cat "$metadata_file"
}

main "$@"
