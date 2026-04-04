#!/usr/bin/env bash
#
# detect-format.sh
#
# Auto-detect kernel binary format and extract/normalize to a usable form
# for analysis. Supports: ELF vmlinux, raw decompressed blobs, bzImage,
# zImage, uImage, gzip/bzip2/xz/lz4/zstd compressed kernels.
#
# Usage:
#   detect-format.sh <input-binary> <output-dir>
#
# Output:
#   Writes the normalized binary to <output-dir>/vmlinux (or vmlinux.bin for raw)
#   Prints metadata to stdout as KEY=VALUE pairs:
#     FORMAT=<detected format>
#     OUTPUT=<path to normalized binary>
#     IS_ELF=<yes|no>
#     COMPRESSION=<none|gzip|bzip2|xz|lz4|lzma|zstd>
#
# Exit codes:
#   0 = success
#   1 = unrecognized format / extraction failed
#   2 = missing dependencies
#

set -euo pipefail

log_info()  { echo "[detect-format] $*" >&2; }
log_warn()  { echo "[detect-format][WARN] $*" >&2; }
log_error() { echo "[detect-format][ERROR] $*" >&2; }

# Check required tools
check_deps() {
    local missing=()
    for cmd in file hexdump strings; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 2
    fi
}

# Read N bytes from file at offset as hex
read_hex() {
    local file="$1" offset="$2" count="$3"
    hexdump -v -s "$offset" -n "$count" -e '1/1 "%02x"' "$file" 2>/dev/null || true
}

# Detect if file is an ELF binary
is_elf() {
    local magic
    magic=$(read_hex "$1" 0 4)
    [[ "$magic" == "7f454c46" ]]
}

# Detect ELF architecture from e_machine field
detect_elf_arch() {
    local file="$1"
    # ELF e_ident[5] = endianness: 1=little, 2=big
    local ei_data
    ei_data=$(read_hex "$file" 5 1)

    # e_machine is at offset 18 (2 bytes)
    local em_byte1 em_byte2 e_machine
    em_byte1=$(read_hex "$file" 18 1)
    em_byte2=$(read_hex "$file" 19 1)

    if [[ "$ei_data" == "01" ]]; then
        # Little endian
        e_machine=$(( 16#${em_byte2}${em_byte1} ))
    else
        # Big endian
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
        *)   echo "unknown_${e_machine}" ;;
    esac
}

# Detect gzip compressed data
is_gzip() {
    local magic
    magic=$(read_hex "$1" 0 2)
    [[ "$magic" == "1f8b" ]]
}

# Detect bzip2 compressed data
is_bzip2() {
    local magic
    magic=$(read_hex "$1" 0 3)
    [[ "$magic" == "425a68" ]]  # "BZh"
}

# Detect XZ compressed data
is_xz() {
    local magic
    magic=$(read_hex "$1" 0 6)
    [[ "$magic" == "fd377a585a00" ]]
}

# Detect LZ4 compressed data
is_lz4() {
    local magic
    magic=$(read_hex "$1" 0 4)
    [[ "$magic" == "04224d18" ]]
}

# Detect LZMA compressed data (crude check)
is_lzma() {
    local magic
    magic=$(read_hex "$1" 0 3)
    # LZMA streams typically start with 0x5d 0x00 0x00
    [[ "$magic" == "5d0000" ]]
}

# Detect Zstandard compressed data
is_zstd() {
    local magic
    magic=$(read_hex "$1" 0 4)
    [[ "$magic" == "28b52ffd" ]]
}

# Detect U-Boot uImage header
is_uimage() {
    local magic
    magic=$(read_hex "$1" 0 4)
    [[ "$magic" == "27051956" ]]
}

# Detect ARM zImage magic (at offset 0x24)
is_arm_zimage() {
    local magic
    magic=$(read_hex "$1" 36 4)  # offset 0x24 = 36
    [[ "$magic" == "18286f01" ]] || [[ "$magic" == "016f2818" ]]
}

# Detect x86 bzImage (boot sector signature at 0x1FE + "HdrS" at 0x202)
is_bzimage() {
    local sig header
    sig=$(read_hex "$1" 510 2)
    header=$(read_hex "$1" 514 4)
    # Boot signature 0x55AA (little-endian: 55aa) and "HdrS" = 48647253
    [[ "$sig" == "55aa" ]] && [[ "$header" == "48647253" ]]
}

# Find compressed kernel payload inside bzImage/zImage
# Searches for compression magic bytes within the image
find_compressed_payload() {
    local file="$1"
    local filesize
    filesize=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)

    # Search for gzip magic (most common)
    local offset
    offset=$(grep -aboP '\x1f\x8b\x08' "$file" 2>/dev/null | head -1 | cut -d: -f1 || true)
    if [[ -n "$offset" ]]; then
        echo "gzip:$offset"
        return 0
    fi

    # Search for XZ magic
    offset=$(grep -aboP '\xfd7zXZ\x00' "$file" 2>/dev/null | head -1 | cut -d: -f1 || true)
    if [[ -n "$offset" ]]; then
        echo "xz:$offset"
        return 0
    fi

    # Search for bzip2 magic
    offset=$(grep -aboP 'BZh' "$file" 2>/dev/null | head -1 | cut -d: -f1 || true)
    if [[ -n "$offset" ]]; then
        echo "bzip2:$offset"
        return 0
    fi

    # Search for LZ4 magic
    offset=$(grep -aboP '\x04\x22\x4d\x18' "$file" 2>/dev/null | head -1 | cut -d: -f1 || true)
    if [[ -n "$offset" ]]; then
        echo "lz4:$offset"
        return 0
    fi

    # Search for LZMA magic
    offset=$(grep -aboP '\x5d\x00\x00' "$file" 2>/dev/null | head -1 | cut -d: -f1 || true)
    if [[ -n "$offset" ]]; then
        echo "lzma:$offset"
        return 0
    fi

    # Search for Zstandard magic
    offset=$(grep -aboP '\x28\xb5\x2f\xfd' "$file" 2>/dev/null | head -1 | cut -d: -f1 || true)
    if [[ -n "$offset" ]]; then
        echo "zstd:$offset"
        return 0
    fi

    return 1
}

# Decompress a payload from a file at a given offset
decompress_payload() {
    local file="$1" compression="$2" offset="$3" output="$4"

    log_info "Extracting ${compression} payload at offset ${offset}"

    case "$compression" in
        gzip)
            if ! command -v gunzip &>/dev/null; then
                log_error "gunzip not found, cannot decompress gzip payload"
                return 1
            fi
            dd if="$file" bs=1 skip="$offset" 2>/dev/null | gunzip -c > "$output" 2>/dev/null
            ;;
        bzip2)
            if ! command -v bunzip2 &>/dev/null; then
                log_error "bunzip2 not found, cannot decompress bzip2 payload"
                return 1
            fi
            dd if="$file" bs=1 skip="$offset" 2>/dev/null | bunzip2 -c > "$output" 2>/dev/null
            ;;
        xz)
            if ! command -v unxz &>/dev/null; then
                log_error "unxz not found, cannot decompress xz payload"
                return 1
            fi
            dd if="$file" bs=1 skip="$offset" 2>/dev/null | unxz -c > "$output" 2>/dev/null
            ;;
        lz4)
            if ! command -v lz4 &>/dev/null; then
                log_error "lz4 not found, cannot decompress lz4 payload"
                return 1
            fi
            dd if="$file" bs=1 skip="$offset" 2>/dev/null | lz4 -dc > "$output" 2>/dev/null
            ;;
        lzma)
            if ! command -v unlzma &>/dev/null; then
                log_error "unlzma not found, cannot decompress lzma payload"
                return 1
            fi
            dd if="$file" bs=1 skip="$offset" 2>/dev/null | unlzma -c > "$output" 2>/dev/null
            ;;
        zstd)
            if ! command -v zstd &>/dev/null; then
                log_error "zstd not found, cannot decompress zstd payload"
                return 1
            fi
            dd if="$file" bs=1 skip="$offset" 2>/dev/null | zstd -dc > "$output" 2>/dev/null
            ;;
        *)
            log_error "Unknown compression: $compression"
            return 1
            ;;
    esac

    # Verify we got something useful
    local outsize
    outsize=$(stat -c%s "$output" 2>/dev/null || stat -f%z "$output" 2>/dev/null)
    if [[ "$outsize" -lt 1000000 ]]; then
        log_warn "Decompressed output is suspiciously small (${outsize} bytes)"
        return 1
    fi

    return 0
}

# Extract kernel from uImage format
extract_uimage() {
    local file="$1" output="$2"

    # uImage header is 64 bytes
    # Byte 9 = compression type: 0=none, 1=gzip, 2=bzip2, 3=lzma, 4=lz4
    local comp_type
    comp_type=$(read_hex "$file" 9 1)

    log_info "uImage compression type: $comp_type"

    case "$comp_type" in
        00)
            # No compression, just strip 64-byte header
            dd if="$file" bs=64 skip=1 of="$output" 2>/dev/null
            ;;
        01)
            dd if="$file" bs=64 skip=1 2>/dev/null | gunzip -c > "$output" 2>/dev/null
            ;;
        02)
            dd if="$file" bs=64 skip=1 2>/dev/null | bunzip2 -c > "$output" 2>/dev/null
            ;;
        03)
            dd if="$file" bs=64 skip=1 2>/dev/null | unlzma -c > "$output" 2>/dev/null
            ;;
        04)
            dd if="$file" bs=64 skip=1 2>/dev/null | lz4 -dc > "$output" 2>/dev/null
            ;;
        *)
            log_error "Unknown uImage compression type: $comp_type"
            return 1
            ;;
    esac
}

# Check if a binary looks like a Linux kernel (contains version string)
verify_kernel_binary() {
    local file="$1"
    # Note: use grep without -q and redirect to /dev/null to avoid SIGPIPE
    # issues with pipefail (grep -q closes pipe early -> strings gets SIGPIPE)
    if strings "$file" 2>/dev/null | grep "Linux version [0-9]" >/dev/null 2>&1; then
        return 0
    fi
    return 1
}

# =========================================================================
# Main detection logic
# =========================================================================

main() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: $0 <input-binary> <output-dir>" >&2
        exit 1
    fi

    local input="$1"
    local outdir="$2"

    if [[ ! -f "$input" ]]; then
        log_error "Input file not found: $input"
        exit 1
    fi

    check_deps
    mkdir -p "$outdir"

    local format="unknown"
    local compression="none"
    local output=""
    local is_elf="no"

    # ---- Step 1: Identify the format ----

    if is_elf "$input"; then
        format="elf_vmlinux"
        is_elf="yes"
        compression="none"

        # Check if it actually looks like a kernel
        if verify_kernel_binary "$input"; then
            log_info "Detected: ELF vmlinux (Linux kernel)"
        else
            log_warn "File is ELF but doesn't contain Linux version string"
            log_warn "Proceeding anyway -- it may be a stripped kernel"
        fi

        # Copy to output
        output="$outdir/vmlinux"
        cp "$input" "$output"

        local arch
        arch=$(detect_elf_arch "$input")
        echo "ARCH=$arch"

    elif is_uimage "$input"; then
        format="uimage"
        log_info "Detected: U-Boot uImage"

        output="$outdir/vmlinux.bin"
        if ! extract_uimage "$input" "$output"; then
            log_error "Failed to extract kernel from uImage"
            exit 1
        fi

        # Check if the result is an ELF
        if is_elf "$output"; then
            is_elf="yes"
            mv "$output" "$outdir/vmlinux"
            output="$outdir/vmlinux"
            local arch
            arch=$(detect_elf_arch "$output")
            echo "ARCH=$arch"
        fi

    elif is_bzimage "$input"; then
        format="bzimage"
        log_info "Detected: x86 bzImage"
        echo "ARCH=x86"

        # Try to find and extract the compressed payload
        local payload_info
        if payload_info=$(find_compressed_payload "$input"); then
            compression="${payload_info%%:*}"
            local offset="${payload_info#*:}"

            output="$outdir/vmlinux.bin"
            if ! decompress_payload "$input" "$compression" "$offset" "$output"; then
                log_error "Failed to decompress bzImage payload"
                log_info "Hint: try using 'extract-vmlinux' from the kernel source tree:"
                log_info "  scripts/extract-vmlinux $input > $outdir/vmlinux"
                exit 1
            fi

            # Check if the result is an ELF
            if is_elf "$output"; then
                is_elf="yes"
                mv "$output" "$outdir/vmlinux"
                output="$outdir/vmlinux"
            fi
        else
            log_error "Could not find compressed payload in bzImage"
            log_info "Hint: try using 'extract-vmlinux' from the kernel source tree"
            exit 1
        fi

    elif is_arm_zimage "$input"; then
        format="zimage"
        log_info "Detected: ARM zImage"
        echo "ARCH=arm"

        local payload_info
        if payload_info=$(find_compressed_payload "$input"); then
            compression="${payload_info%%:*}"
            local offset="${payload_info#*:}"

            output="$outdir/vmlinux.bin"
            if ! decompress_payload "$input" "$compression" "$offset" "$output"; then
                log_error "Failed to decompress zImage payload"
                exit 1
            fi

            if is_elf "$output"; then
                is_elf="yes"
                mv "$output" "$outdir/vmlinux"
                output="$outdir/vmlinux"
            fi
        else
            log_error "Could not find compressed payload in zImage"
            exit 1
        fi

    elif is_gzip "$input"; then
        format="compressed"
        compression="gzip"
        log_info "Detected: gzip compressed file"
        output="$outdir/vmlinux.bin"
        decompress_payload "$input" "gzip" 0 "$output" || exit 1

        if is_elf "$output"; then
            is_elf="yes"
            mv "$output" "$outdir/vmlinux"
            output="$outdir/vmlinux"
            local arch
            arch=$(detect_elf_arch "$output")
            echo "ARCH=$arch"
        fi

    elif is_xz "$input"; then
        format="compressed"
        compression="xz"
        log_info "Detected: xz compressed file"
        output="$outdir/vmlinux.bin"
        decompress_payload "$input" "xz" 0 "$output" || exit 1

        if is_elf "$output"; then
            is_elf="yes"
            mv "$output" "$outdir/vmlinux"
            output="$outdir/vmlinux"
            local arch
            arch=$(detect_elf_arch "$output")
            echo "ARCH=$arch"
        fi

    elif is_bzip2 "$input"; then
        format="compressed"
        compression="bzip2"
        log_info "Detected: bzip2 compressed file"
        output="$outdir/vmlinux.bin"
        decompress_payload "$input" "bzip2" 0 "$output" || exit 1

        if is_elf "$output"; then
            is_elf="yes"
            mv "$output" "$outdir/vmlinux"
            output="$outdir/vmlinux"
            local arch
            arch=$(detect_elf_arch "$output")
            echo "ARCH=$arch"
        fi

    elif is_lz4 "$input"; then
        format="compressed"
        compression="lz4"
        log_info "Detected: lz4 compressed file"
        output="$outdir/vmlinux.bin"
        decompress_payload "$input" "lz4" 0 "$output" || exit 1

        if is_elf "$output"; then
            is_elf="yes"
            mv "$output" "$outdir/vmlinux"
            output="$outdir/vmlinux"
            local arch
            arch=$(detect_elf_arch "$output")
            echo "ARCH=$arch"
        fi

    elif is_zstd "$input"; then
        format="compressed"
        compression="zstd"
        log_info "Detected: zstd compressed file"
        output="$outdir/vmlinux.bin"
        decompress_payload "$input" "zstd" 0 "$output" || exit 1

        if is_elf "$output"; then
            is_elf="yes"
            mv "$output" "$outdir/vmlinux"
            output="$outdir/vmlinux"
            local arch
            arch=$(detect_elf_arch "$output")
            echo "ARCH=$arch"
        fi

    else
        # Last resort: treat as raw binary blob
        # Check if it at least looks like a kernel
        if verify_kernel_binary "$input"; then
            format="raw_blob"
            compression="none"
            log_info "Detected: raw binary blob (contains Linux version string)"
            log_warn "No ELF headers found -- you may need to specify architecture manually"
            output="$outdir/vmlinux.bin"
            cp "$input" "$output"
        else
            # Try to find a compressed payload inside (firmware blob?)
            log_info "Attempting to find compressed kernel inside blob..."
            local payload_info
            if payload_info=$(find_compressed_payload "$input"); then
                compression="${payload_info%%:*}"
                local offset="${payload_info#*:}"
                format="firmware_blob"

                output="$outdir/vmlinux.bin"
                if decompress_payload "$input" "$compression" "$offset" "$output"; then
                    if verify_kernel_binary "$output"; then
                        log_info "Successfully extracted kernel from firmware blob"
                        if is_elf "$output"; then
                            is_elf="yes"
                            mv "$output" "$outdir/vmlinux"
                            output="$outdir/vmlinux"
                            local arch
                            arch=$(detect_elf_arch "$output")
                            echo "ARCH=$arch"
                        fi
                    else
                        log_error "Extracted data does not appear to be a Linux kernel"
                        rm -f "$output"
                        exit 1
                    fi
                else
                    log_error "Failed to decompress embedded payload"
                    exit 1
                fi
            else
                log_error "Unrecognized format: cannot identify kernel binary"
                log_info ""
                log_info "Supported input formats:"
                log_info "  - ELF vmlinux (uncompressed kernel with symbols)"
                log_info "  - bzImage / zImage (compressed kernel images)"
                log_info "  - uImage (U-Boot wrapped kernel)"
                log_info "  - gzip / bzip2 / xz / lz4 / zstd compressed kernel"
                log_info "  - Raw decompressed kernel blob"
                log_info ""
                log_info "If you have a full firmware image, try extracting the kernel first:"
                log_info "  binwalk -e <firmware>"
                log_info "  # or use EMBA: https://github.com/e-m-b-a/emba"
                log_info "  # or use extract-vmlinux: scripts/extract-vmlinux <image>"
                exit 1
            fi
        fi
    fi

    # ---- Step 2: Verify the output ----

    if [[ ! -f "$output" ]]; then
        log_error "No output file produced"
        exit 1
    fi

    local outsize
    outsize=$(stat -c%s "$output" 2>/dev/null || stat -f%z "$output" 2>/dev/null)
    log_info "Output: $output ($outsize bytes)"

    # ---- Step 3: Emit metadata ----

    echo "FORMAT=$format"
    echo "OUTPUT=$output"
    echo "IS_ELF=$is_elf"
    echo "COMPRESSION=$compression"
}

main "$@"
