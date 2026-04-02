#!/usr/bin/env bash
#
# kernel-backport-checker.sh
#
# Determines how many CVEs affect a given Linux kernel version, filters by
# kernel .config, then checks which CVEs have been fixed via backport commits
# in a git repository.
#
# Workflow:
#   1. Detect kernel version from source tree (e.g., 6.1.1)
#   2. Scan NVD JSON feeds for ALL CVEs affecting that kernel version (CPE match)
#   3. Filter out CVEs not applicable to the kernel .config
#   4. Check git repos (upstream + stable/vendor) for backported fixes
#   5. Output CSV: each CVE marked as FIXED or UNFIXED
#
# Usage:
#   ./kernel-backport-checker.sh -s <kernel-source-dir> -d <upstream-linux-git-dir> \
#       -e <kev-data> -f <nvd-json-data-feeds> -k <kernel-config> -o <output-dir> \
#       [-b <stable-vendor-git-dir>]
#

set -euo pipefail

VERSION="3.2.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- Global variables ----
KEV_FILE=""
KERNEL_DIR=""
STABLE_DIR=""         # Optional: stable/vendor git repo with backport commits
KERNEL_CONFIG=""
KERNEL_SRC=""
NVD_FEEDS_DIR=""
OUTPUT_DIR=""
KERNEL_VERSION=""
JOBS=0   # 0 = auto-detect (nproc/2, min 1)

# ---- Working file paths (set in main) ----
AFFECTED_CVES_FILE=""
NVD_FIX_REFS_FILE=""
GIT_HASH_INDEX=""
BACKPORTED_CVES_FILE=""
KEV_INDEX=""
RESULTS_FILE=""

# =============================================================================
# Utility
# =============================================================================

log_info()  { echo "[INFO] $*"; }
log_warn()  { echo "[WARN] $*" >&2; }
log_error() { echo "[ERROR] $*" >&2; }

usage() {
    cat << EOF
Kernel Backport Checker v${VERSION}

Determines how many CVEs affect a given Linux kernel version, filters by
kernel .config, then checks which have been fixed via backport commits.

Usage:
    $0 [OPTIONS]

Required Options:
    -s <path>    Kernel source directory (must contain Makefile)
                 Provides: kernel version, Makefiles for CONFIG mapping
    -d <path>    Upstream Linux kernel git directory (e.g., torvalds/linux.git clone)
                 Used for: fix commit hash lookup, diff extraction
    -e <path>    CISA KEV data directory or JSON file
    -f <path>    NVD JSON data feeds directory (fkie-cad/nvd-json-data-feeds)
    -k <path>    Kernel .config file
    -o <path>    Output directory for results

Optional:
    -b <path>    Stable/vendor git repository with backport commits
                 Used for: CVE-mentioning commit search, backport diff extraction
                 If omitted, only the upstream repo (-d) is searched for backports
    -j <N>       Number of parallel jobs (default: nproc/2, min 1)
    -h           Show this help

Example:
    $0 -s linux-6.1.1 -d linux -e kev-data -f nvd-json-data-feeds -k 6.1-config -o output
    $0 -s linux-6.1.1 -d linux -b linux-stable -e kev-data -f nvd-json-data-feeds -k 6.1-config -o output
    $0 -s linux-6.1.1 -d linux -b linux-stable -e kev-data -f nvd-json-data-feeds -k 6.1-config -o output -j 8

Output:
    <output-dir>/backport-report.csv

Dependencies:
    bash 4+, jq, git

EOF
    exit 1
}

# =============================================================================
# Dependency checks
# =============================================================================

check_dependencies() {
    local missing=0

    if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
        log_error "Bash 4+ required (found ${BASH_VERSION})"
        missing=1
    fi

    if ! command -v jq &>/dev/null; then
        log_error "jq is required. Install: apt install jq / yum install jq"
        missing=1
    fi

    if ! command -v git &>/dev/null; then
        log_error "git is required."
        missing=1
    fi

    if [[ "$missing" -eq 1 ]]; then
        exit 1
    fi
}

# =============================================================================
# Argument parsing
# =============================================================================

parse_args() {
    while getopts "e:d:b:k:f:o:s:j:h" opt; do
        case $opt in
            e) KEV_FILE="$OPTARG" ;;
            d) KERNEL_DIR="$OPTARG" ;;
            b) STABLE_DIR="$OPTARG" ;;
            k) KERNEL_CONFIG="$OPTARG" ;;
            s) KERNEL_SRC="$OPTARG" ;;
            f) NVD_FEEDS_DIR="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            j) JOBS="$OPTARG" ;;
            h) usage ;;
            *) usage ;;
        esac
    done

    # Resolve parallel jobs
    local ncpus
    ncpus=$(nproc 2>/dev/null || echo 4)
    if [[ "$JOBS" -le 0 ]]; then
        JOBS=$(( ncpus / 2 ))
        [[ "$JOBS" -lt 1 ]] && JOBS=1
    fi

    if [[ -z "$KEV_FILE" || -z "$KERNEL_DIR" || -z "$KERNEL_SRC" || -z "$KERNEL_CONFIG" || -z "$NVD_FEEDS_DIR" || -z "$OUTPUT_DIR" ]]; then
        log_error "All required options (-s, -d, -e, -f, -k, -o) must be specified"
        usage
    fi

    # Resolve KEV file
    if [[ -d "$KEV_FILE" ]]; then
        if [[ -f "$KEV_FILE/known_exploited_vulnerabilities.json" ]]; then
            KEV_FILE="$KEV_FILE/known_exploited_vulnerabilities.json"
        else
            log_error "KEV directory does not contain known_exploited_vulnerabilities.json"
            exit 1
        fi
    fi

    # Validate inputs
    if [[ ! -f "$KEV_FILE" ]]; then log_error "KEV file not found: $KEV_FILE"; exit 1; fi
    if [[ ! -d "$KERNEL_DIR/.git" ]]; then log_error "Not a git repository: $KERNEL_DIR"; exit 1; fi
    if [[ -n "$STABLE_DIR" && ! -d "$STABLE_DIR/.git" ]]; then log_error "Not a git repository: $STABLE_DIR"; exit 1; fi
    if [[ ! -d "$NVD_FEEDS_DIR" ]]; then log_error "NVD feeds directory not found: $NVD_FEEDS_DIR"; exit 1; fi

    # Validate kernel source directory
    if [[ ! -d "$KERNEL_SRC" ]]; then
        log_error "Kernel source directory not found: $KERNEL_SRC"
        exit 1
    fi
    if [[ ! -f "$KERNEL_SRC/Makefile" ]]; then
        log_error "No Makefile found in kernel source: $KERNEL_SRC"
        exit 1
    fi

    # Validate kernel config
    if [[ ! -f "$KERNEL_CONFIG" ]]; then
        log_error "Kernel config file not found: $KERNEL_CONFIG"
        exit 1
    fi

    mkdir -p "$OUTPUT_DIR"

    # Set working file paths
    AFFECTED_CVES_FILE="$OUTPUT_DIR/.affected_cves.tsv"
    NVD_FIX_REFS_FILE="$OUTPUT_DIR/.nvd_fix_refs.tsv"
    GIT_HASH_INDEX="$OUTPUT_DIR/.git_hash_index.txt"
    BACKPORTED_CVES_FILE="$OUTPUT_DIR/.backported_cves.txt"
    KEV_INDEX="$OUTPUT_DIR/.kev_index.txt"
    RESULTS_FILE="$OUTPUT_DIR/.results.tsv"
}

# =============================================================================
# Detect kernel version from source tree
# =============================================================================

detect_kernel_version() {
    log_info "Detecting kernel version..."

    local makefile="$KERNEL_SRC/Makefile"
    if [[ ! -f "$makefile" ]]; then
        log_error "Cannot find Makefile in kernel source: $KERNEL_SRC"
        exit 1
    fi

    local ver patchlevel sublevel
    ver=$(grep -m1 '^VERSION = ' "$makefile" | awk '{print $3}')
    patchlevel=$(grep -m1 '^PATCHLEVEL = ' "$makefile" | awk '{print $3}')
    sublevel=$(grep -m1 '^SUBLEVEL = ' "$makefile" | awk '{print $3}')

    if [[ -z "$ver" || -z "$patchlevel" ]]; then
        log_error "Failed to parse kernel version from $makefile"
        exit 1
    fi

    KERNEL_VERSION="${ver}.${patchlevel}"
    if [[ -n "$sublevel" && "$sublevel" != "0" ]]; then KERNEL_VERSION="${KERNEL_VERSION}.${sublevel}"; fi

    log_info "Kernel version: $KERNEL_VERSION"
}

# =============================================================================
# Scan NVD feeds to find ALL CVEs affecting our kernel version
# Uses bulk extraction with find+xargs+jq and awk version filtering
# =============================================================================

scan_nvd_for_kernel_cves() {
    local cache_file="$OUTPUT_DIR/.nvd_kernel_cves_${KERNEL_VERSION}.tsv"

    if [[ -f "$cache_file" ]]; then
        log_info "Using cached NVD scan: $cache_file"
        log_info "  (Delete $cache_file to force rescan)"
        AFFECTED_CVES_FILE="$cache_file"
        local count
        count=$(wc -l < "$cache_file")
        log_info "  Cached: $count CVEs affecting kernel $KERNEL_VERSION"
        return
    fi

    log_info "Scanning NVD feeds for CVEs affecting Linux kernel $KERNEL_VERSION..."

    # Phase 1: Find all JSON files with actual Linux kernel CPEs
    # Match "cpe:2.3:o:linux:linux_kernel" to exclude non-kernel products
    # that merely run ON the Linux kernel (e.g., Novell Open Enterprise Server)
    log_info "  Phase 1: Finding kernel CVE files..."
    local kernel_cve_list="$OUTPUT_DIR/.kernel_cve_files.txt"
    find "$NVD_FEEDS_DIR" -name "*.json" -path "*/CVE-*" \
        -exec grep -l "cpe:2.3:o:linux:linux_kernel" {} + 2>/dev/null > "$kernel_cve_list" || true

    local total_files
    total_files=$(wc -l < "$kernel_cve_list")
    log_info "  Found $total_files CVE files with Linux kernel CPEs"

    # Phase 2: Bulk extract version ranges with CVE details
    # Handles two CPE formats:
    #   a) Wildcard range: cpe:2.3:o:linux:linux_kernel:*:... with versionStart/End fields
    #   b) Exact version:  cpe:2.3:o:linux:linux_kernel:2.6.17:... (no range fields)
    # Phase 2 MUST use -P1 (sequential) to prevent output line interleaving
    # when multiple jq processes write large @tsv lines simultaneously.
    # Interleaving causes false CVE matches (e.g. CVE-2009-1389 matching 6.1.1).
    # Parallelism is applied in other phases (fix refs, diffs, process_results).
    log_info "  Phase 2: Extracting version ranges (sequential to ensure accuracy)..."
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
        # Extract version from CPE for exact-version entries
        (.criteria | split(":") | .[5]) as $cpe_ver |
        if $cpe_ver == "*" then
            # Wildcard range: use versionStart/End fields
            [$id, $cvss[0], $cvss[1],
             (.versionStartIncluding // ""), (.versionStartExcluding // ""),
             (.versionEndIncluding // ""), (.versionEndExcluding // ""),
             "", $desc] | @tsv
        else
            # Exact version: put exact version in field 8
            [$id, $cvss[0], $cvss[1],
             "", "", "", "",
             $cpe_ver, $desc] | @tsv
        end
    ' 2>/dev/null > "$raw_ranges" || true

    local range_count
    range_count=$(wc -l < "$raw_ranges")
    log_info "  Extracted $range_count version entries"

    # Phase 3: Filter by kernel version using awk, deduplicate by CVE-ID
    # Fields: 1=CVE-ID, 2=CVSS, 3=Severity, 4=startIncl, 5=startExcl,
    #         6=endIncl, 7=endExcl, 8=exactVer, 9=Description
    log_info "  Phase 3: Filtering for version $KERNEL_VERSION..."

    awk -F'\t' -v kver="$KERNEL_VERSION" '
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
                # Exact version match: only matches if version equals kver
                if (ver_cmp(kver, exact) == 0) ok = 1
            } else if (si == "" && se == "" && ei == "" && ee == "") {
                # No range and no exact version: skip (malformed entry)
                ok = 0
            } else {
                # Range-based match
                ok = 1
                if (si != "" && ver_cmp(kver, si) < 0) ok = 0
                if (se != "" && ver_cmp(kver, se) <= 0) ok = 0
                if (ei != "" && ver_cmp(kver, ei) > 0) ok = 0
                if (ee != "" && ver_cmp(kver, ee) >= 0) ok = 0
            }

            if (ok && !seen[$1]++) {
                # Output: CVE-ID \t CVSS-Score \t Severity \t Description
                print $1 "\t" $2 "\t" $3 "\t" $9
            }
        }
    ' "$raw_ranges" > "$cache_file"

    rm -f "$kernel_cve_list" "$raw_ranges"

    AFFECTED_CVES_FILE="$cache_file"
    local matched
    matched=$(wc -l < "$cache_file")
    log_info "NVD scan complete: $matched CVEs affect kernel $KERNEL_VERSION"
}

# =============================================================================
# Extract upstream fix commit hashes from NVD references
# Maps CVE-ID -> git.kernel.org commit hashes (for config mapping + backport detection)
# =============================================================================

extract_nvd_fix_refs() {
    local cache_file="$OUTPUT_DIR/.nvd_fix_refs_${KERNEL_VERSION}.tsv"

    if [[ -f "$cache_file" ]]; then
        log_info "Using cached NVD fix refs: $cache_file"
        NVD_FIX_REFS_FILE="$cache_file"
        local count
        count=$(awk -F'\t' '{print $1}' "$cache_file" | sort -u | wc -l)
        log_info "  Cached: fix refs for $count CVEs"
        return
    fi

    log_info "Extracting upstream fix commit hashes from NVD references (jobs=$JOBS)..."

    local nvd_dir="$NVD_FEEDS_DIR"

    # Use xargs -P for parallel jq calls (one per CVE JSON file)
    # Each worker derives the JSON path and extracts git.kernel.org refs
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
             # Match all known kernel commit URL formats:
             # 1. git.kernel.org/stable/c/HASH
             # 2. git.kernel.org/.../commit/?id=HASH or ?h=branch&id=HASH
             # 3. github.com/torvalds/linux/commit/HASH
             # 4. kernel.dance/HASH
             # 5. Old cgit format: git.kernel.org/?p=...;h=HASH or %3Bh=HASH
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
# Build git hash index (all commit hashes in the local repo)
# Used for detecting backported commits by matching upstream fix hashes
# =============================================================================

build_git_hash_index() {
    log_info "Building git hash index..."

    # Include hashes from upstream repo
    git -C "$KERNEL_DIR" rev-list --all 2>/dev/null | cut -c1-12 > "$GIT_HASH_INDEX.tmp"

    # Also include hashes from stable/vendor repo if provided
    if [[ -n "$STABLE_DIR" ]]; then
        git -C "$STABLE_DIR" rev-list --all 2>/dev/null | cut -c1-12 >> "$GIT_HASH_INDEX.tmp"
    fi

    sort -u "$GIT_HASH_INDEX.tmp" > "$GIT_HASH_INDEX"
    rm -f "$GIT_HASH_INDEX.tmp"

    local count
    count=$(wc -l < "$GIT_HASH_INDEX")
    log_info "Git hash index built: $count commits"
}

# =============================================================================
# Load kernel .config
# =============================================================================

declare -A ENABLED_CONFIGS

load_kernel_config() {
    log_info "Loading kernel config: $KERNEL_CONFIG"

    local count=0
    while IFS='=' read -r key value; do
        ENABLED_CONFIGS["$key"]=1
        ((count++)) || true
    done < <(grep -E '^CONFIG_[A-Za-z0-9_]+=(y|m)$' "$KERNEL_CONFIG")

    log_info "Loaded $count enabled CONFIG options"
}

# =============================================================================
# Build CONFIG mapping at runtime from kernel source Makefiles/Kbuild files
# Generates both file-level and directory-level mappings
# =============================================================================

declare -A FILE_CONFIG_MAP    # file_path -> CONFIG_XXX
declare -A DIR_CONFIG_MAP     # directory_path -> CONFIG_XXX

build_config_mapping() {
    if [[ -z "$KERNEL_SRC" ]]; then
        log_warn "No kernel source tree - CONFIG mapping disabled"
        return
    fi

    log_info "Building CONFIG mapping from kernel Makefiles..."

    local cache_file="$OUTPUT_DIR/.config_mapping.tsv"

    # Generate mapping by scanning all Makefile/Kbuild files
    # Uses awk for fast bulk extraction with line-continuation handling
    # MUST use -P1 (sequential) to prevent output line interleaving
    # when multiple awk processes write simultaneously
    local srcroot="$KERNEL_SRC"
    # Ensure exactly one trailing slash for consistent path stripping
    srcroot="${srcroot%/}/"
    find "$KERNEL_SRC" \( -name "Makefile" -o -name "Kbuild" \) -print0 | \
      xargs -0 -P1 -n50 awk -v srcroot="$srcroot" '
        FILENAME != prev_file {
            prev_file = FILENAME
            dir = FILENAME
            sub(/\/[^\/]+$/, "", dir)   # remove filename
            sub(srcroot, "", dir)        # make relative (with trailing slash)
            # Handle root-level Makefile where dir == srcroot without trailing slash
            if (dir == substr(srcroot, 1, length(srcroot)-1)) dir = ""
            buf = ""
        }
        /\\$/ { buf = buf $0; next }
        { line = buf $0; buf = "" }
        line ~ /obj-\$\(CONFIG_[A-Za-z0-9_]+\)/ {
            match(line, /CONFIG_[A-Za-z0-9_]+/)
            config = substr(line, RSTART, RLENGTH)
            n = split(line, parts, /[[:space:]+=]+/)
            for (i = 1; i <= n; i++) {
                if (parts[i] ~ /\.o$/) {
                    base = parts[i]
                    sub(/\.o$/, ".c", base)
                    if (dir == "") print base "\t" config
                    else print dir "/" base "\t" config
                } else if (parts[i] ~ /\/$/) {
                    subdir = parts[i]
                    sub(/\/$/, "", subdir)
                    if (dir == "") print subdir "\t" config
                    else print dir "/" subdir "\t" config
                }
            }
        }
        line ~ /obj-y[[:space:]]*[\+:]?=/ {
            n = split(line, parts, /[[:space:]+=]+/)
            for (i = 1; i <= n; i++) {
                if (parts[i] ~ /\.o$/) {
                    base = parts[i]
                    sub(/\.o$/, ".c", base)
                    if (dir == "") print base "\tALWAYS_BUILT"
                    else print dir "/" base "\tALWAYS_BUILT"
                }
            }
        }
      ' 2>/dev/null > "$cache_file"

    # Load into associative arrays
    local file_count=0
    local dir_count=0
    while IFS=$'\t' read -r path config; do
        [[ -z "$path" || -z "$config" ]] && continue
        if [[ "$path" == *.c ]]; then
            FILE_CONFIG_MAP["$path"]="$config"
            ((file_count++)) || true
        else
            DIR_CONFIG_MAP["$path"]="$config"
            ((dir_count++)) || true
        fi
    done < "$cache_file"

    rm -f "$cache_file"

    log_info "Built CONFIG mapping: $file_count file mappings, $dir_count directory mappings"
}

# =============================================================================
# Extract backported CVEs from git
# =============================================================================

extract_backported_cves() {
    log_info "Extracting backported CVE fixes from git..."

    local record_sep="---COMMIT_RECORD---"

    # Search upstream repo for CVE mentions
    git -C "$KERNEL_DIR" log --all --grep="CVE-" \
        --pretty=format:"${record_sep}%H|%ci|%an|%s%n%b" > "$BACKPORTED_CVES_FILE.raw" 2>/dev/null || {
        log_error "Failed to read git log from $KERNEL_DIR"
        exit 1
    }

    # Also search stable/vendor repo if provided
    if [[ -n "$STABLE_DIR" ]]; then
        log_info "Searching stable/vendor repo for CVE mentions: $STABLE_DIR"
        git -C "$STABLE_DIR" log --all --grep="CVE-" \
            --pretty=format:"${record_sep}%H|%ci|%an|%s%n%b" >> "$BACKPORTED_CVES_FILE.raw" 2>/dev/null || {
            log_warn "Failed to read git log from $STABLE_DIR (continuing with upstream only)"
        }
    fi

    # Use awk to extract CVE-ID|hash|date|author|subject per CVE per commit
    awk -v RS="---COMMIT_RECORD---" '
    NF > 0 {
        split($0, lines, "\n")
        header = lines[1]
        n = split(header, parts, "|")
        if (n < 4) next
        hash = parts[1]
        date = parts[2]
        author = parts[3]
        subject = parts[4]
        full_text = $0
        delete seen
        while (match(full_text, /CVE-[0-9][0-9][0-9][0-9]-[0-9]+/)) {
            cve = substr(full_text, RSTART, RLENGTH)
            if (!(cve in seen)) {
                seen[cve] = 1
                printf "%s|%s|%s|%s|%s\n", cve, hash, date, author, subject
            }
            full_text = substr(full_text, RSTART + RLENGTH)
        }
    }' "$BACKPORTED_CVES_FILE.raw" > "$BACKPORTED_CVES_FILE"

    rm -f "$BACKPORTED_CVES_FILE.raw"

    local total_pairs unique_cves
    total_pairs=$(wc -l < "$BACKPORTED_CVES_FILE")
    unique_cves=$(awk -F'|' '{print $1}' "$BACKPORTED_CVES_FILE" | sort -u | wc -l)

    log_info "Found $total_pairs commit-CVE pairs ($unique_cves unique CVEs in git)"
}

# =============================================================================
# Build CISA KEV index
# =============================================================================

build_kev_index() {
    log_info "Building CISA KEV index..."
    jq -r '.vulnerabilities[].cveID' "$KEV_FILE" 2>/dev/null | sort -u > "$KEV_INDEX"
    local count
    count=$(wc -l < "$KEV_INDEX")
    log_info "KEV index built: $count CVEs"
}

# =============================================================================
# Map a source file to its CONFIG option
# Uses the pre-built FILE_CONFIG_MAP and DIR_CONFIG_MAP from build_config_mapping()
# =============================================================================

map_file_to_config() {
    local file_path="$1"

    # 1. Exact file match (highest priority, most specific)
    if [[ -n "${FILE_CONFIG_MAP[$file_path]+_}" ]]; then
        echo "${FILE_CONFIG_MAP[$file_path]}"
        return 0
    fi

    # 2. Directory match: walk up the directory tree, prefer longest match
    local dir="$file_path"
    while true; do
        dir=$(dirname "$dir")
        if [[ "$dir" == "." || -z "$dir" ]]; then
            break
        fi
        if [[ -n "${DIR_CONFIG_MAP[$dir]+_}" ]]; then
            echo "${DIR_CONFIG_MAP[$dir]}"
            return 0
        fi
    done

    echo "UNKNOWN"
}

# =============================================================================
# Process: config mapping for ALL CVEs, backport detection, filtering
#
# Logic order:
#   1. For EACH CVE: use NVD fix commit refs -> get changed files -> CONFIG mapping
#   2. If ALL affected CONFIGs are disabled -> NOT_APPLICABLE
#   3. Check backport: verify fix is actually present in target kernel source
#      by checking if distinctive "added lines" from the fix commit exist in
#      the target source files
#   4. Result: FIXED / UNFIXED / NOT_APPLICABLE
# =============================================================================

process_results() {
    log_info "Processing results..."

    # ---- Step 1: Build CVE -> upstream fix commit hashes mapping ----
    declare -A CVE_FIX_HASHES  # CVE-ID -> space-separated upstream hashes
    while IFS=$'\t' read -r cve_id hash; do
        [[ -z "$cve_id" || -z "$hash" ]] && continue
        if [[ -z "${CVE_FIX_HASHES[$cve_id]+_}" ]]; then
            CVE_FIX_HASHES["$cve_id"]="$hash"
        else
            CVE_FIX_HASHES["$cve_id"]+=" $hash"
        fi
    done < "$NVD_FIX_REFS_FILE"

    # ---- Step 2: Find which upstream fix hashes exist in any repo ----
    log_info "  Matching fix commits against git repos..."

    local fix_hashes_sorted="$OUTPUT_DIR/.fix_hashes_sorted.txt"
    awk -F'\t' '{print substr($2,1,12) "\t" $1 "\t" $2}' "$NVD_FIX_REFS_FILE" | \
        sort -t$'\t' -k1,1 > "$fix_hashes_sorted"

    declare -A HASH_IN_REPO
    while IFS=$'\t' read -r short cve_id full_hash; do
        HASH_IN_REPO["$full_hash"]=1
    done < <(join -t$'\t' -1 1 -2 1 "$fix_hashes_sorted" "$GIT_HASH_INDEX" 2>/dev/null)

    local matched_hashes=${#HASH_IN_REPO[@]}
    log_info "  Found $matched_hashes fix commits in git repos"
    rm -f "$fix_hashes_sorted"

    # ---- Step 3: Extract changed files + full diffs from all fix commits ----
    log_info "  Extracting changed files and diffs from fix commits (jobs=$JOBS)..."
    local commit_files_dir="$OUTPUT_DIR/.commit_files"
    local commit_diffs_dir="$OUTPUT_DIR/.commit_diffs"
    mkdir -p "$commit_files_dir" "$commit_diffs_dir"

    # Collect all hashes needing extraction
    local all_hashes_file="$OUTPUT_DIR/.all_hashes_needed.txt"
    {
        for full_hash in "${!HASH_IN_REPO[@]}"; do
            echo "$full_hash"
        done
        awk -F'|' '{print $2}' "$BACKPORTED_CVES_FILE" | sort -u
    } | sort -u > "$all_hashes_file"

    local kernel_dir="$KERNEL_DIR"
    local stable_dir="${STABLE_DIR:-}"
    # Parallel extraction of changed files AND full diffs
    # Try upstream repo first, fall back to stable repo if hash not found
    cat "$all_hashes_file" | xargs -P"$JOBS" -I{} bash -c '
        full_hash="{}"
        short="${full_hash:0:12}"
        files_out="'"$commit_files_dir"'/${full_hash}"
        diff_out="'"$commit_diffs_dir"'/${full_hash}"
        if [[ ! -f "$files_out" ]]; then
            git -C "'"$kernel_dir"'" diff-tree --no-commit-id -r --name-only "$short" \
                > "$files_out" 2>/dev/null || true
            # If upstream repo did not have this commit, try stable repo
            if [[ ! -s "$files_out" && -n "'"$stable_dir"'" ]]; then
                git -C "'"$stable_dir"'" diff-tree --no-commit-id -r --name-only "$short" \
                    > "$files_out" 2>/dev/null || true
            fi
        fi
        if [[ ! -f "$diff_out" ]]; then
            git -C "'"$kernel_dir"'" diff "${short}^..${short}" \
                > "$diff_out" 2>/dev/null || true
            # If upstream repo did not have this commit, try stable repo
            if [[ ! -s "$diff_out" && -n "'"$stable_dir"'" ]]; then
                git -C "'"$stable_dir"'" diff "${short}^..${short}" \
                    > "$diff_out" 2>/dev/null || true
            fi
        fi
    ' || true

    rm -f "$all_hashes_file"

    # ---- Step 4: Load CVE-ID based backport mentions from git ----
    declare -A CVE_BACKPORT_HASHES
    while IFS='|' read -r cve_id hash _rest; do
        [[ -z "$cve_id" ]] && continue
        if [[ -z "${CVE_BACKPORT_HASHES[$cve_id]+_}" ]]; then
            CVE_BACKPORT_HASHES["$cve_id"]="$hash"
        else
            CVE_BACKPORT_HASHES["$cve_id"]+=" $hash"
        fi
    done < "$BACKPORTED_CVES_FILE"

    # ---- Step 5: Load KEV ----
    declare -A KEV_CACHE
    while IFS= read -r kev_cve; do
        if [[ -n "$kev_cve" ]]; then KEV_CACHE["$kev_cve"]=1; fi
    done < "$KEV_INDEX"

    # ---- Step 6: CONFIG mapping cache ----
    declare -A CONFIG_CACHE

    map_hashes_to_config() {
        local hashes="$1"
        has_enabled=0; has_disabled=0; has_unknown=0

        for hash in $hashes; do
            local files_file="$commit_files_dir/$hash"
            [[ ! -s "$files_file" ]] && continue

            while IFS= read -r file; do
                [[ -z "$file" ]] && continue
                local config
                if [[ -n "${CONFIG_CACHE[$file]+_}" ]]; then
                    config="${CONFIG_CACHE[$file]}"
                else
                    config=$(map_file_to_config "$file")
                    CONFIG_CACHE["$file"]="$config"
                fi
                if [[ "$config" != "UNKNOWN" && "$config" != "ALWAYS_BUILT" ]]; then
                    seen_configs["$config"]=1
                fi
                if [[ "$config" == "UNKNOWN" ]]; then
                    has_unknown=1
                elif [[ "$config" == "ALWAYS_BUILT" ]]; then
                    has_enabled=1
                elif [[ -n "${ENABLED_CONFIGS[$config]+_}" ]]; then
                    has_enabled=1
                else
                    has_disabled=1
                fi
            done < "$files_file"
        done
    }

    # ---- Step 7: Helper - check if a fix commit is applied in target kernel ----
    # Strategy: extract distinctive "added lines" AND "removed lines" from the
    # fix commit diff. Added lines = fix code, removed lines = vulnerable code.
    # Accumulate match evidence across ALL changed files, then decide verdict.
    #
    # Returns verdict via echo: FIXED, UNFIXED, LIKELY_FIXED, INCONCLUSIVE
    check_fix_applied() {
        local commit_hash="$1"
        local short="${commit_hash:0:12}"

        # Get changed files
        local files_file="$commit_files_dir/$commit_hash"
        if [[ ! -s "$files_file" ]]; then
            echo "INCONCLUSIVE"
            return
        fi

        # Use pre-computed diff (avoids git call in hot path)
        local diff_file="$commit_diffs_dir/$commit_hash"
        if [[ ! -s "$diff_file" ]]; then
            echo "INCONCLUSIVE"
            return
        fi

        # Awk filter for extracting distinctive lines (shared between added/removed)
        # Excludes common boilerplate patterns that appear across many kernel
        # functions and would produce false positive fingerprint matches.
        local awk_filter='
            length(line) < 8 { next }
            line == "{" || line == "}" { next }
            substr(line,1,2) == "/*" || substr(line,1,1) == "*" { next }
            substr(line,1,8) == "#include" { next }
            line == "break;" || line == "continue;" { next }
            substr(line,1,6) == "return" { next }
            line == "else" || line == "default:" { next }
            line == "NULL" { next }
            substr(line,1,5) == "goto " { next }
            line ~ /^(int|long|bool|void|unsigned|struct|enum|const|static) [a-z_]+;$/ { next }
            line ~ /^(int|long|bool) [a-z_]+ = 0;$/ { next }
            line ~ /^(int|long) (ret|err|rc|res|status);$/ { next }
            line ~ /^(int|long) (ret|err|rc|res|status) = 0;$/ { next }
            line ~ /^if \(!(err|ret|rc|res|ptr|dev|priv|data|ctx|info|buf|skb|hdr|req|rsp|msg|cmd|cfg|reg|val|tmp|node|entry|item|obj|page|inode|dentry|sb)\)$/ { next }
            line ~ /^if \((err|ret|rc|res) < 0\)$/ { next }
            line ~ /^if \((err|ret|rc)\)$/ { next }
            line ~ /^mutex_(lock|unlock)\(/ { next }
            line ~ /^spin_(lock|unlock)/ { next }
            line ~ /^rcu_read_(lock|unlock)\(\)/ { next }
            { print line }
        '

        # Accumulate match evidence across ALL changed files
        local total_added=0 total_removed=0
        local added_matched=0 removed_matched=0
        local any_file_checked=0
        local removed_contiguous=0
        # Store all removed lines for contiguous check later
        local all_removed_lines=""
        local contiguous_checked=0

        while IFS= read -r target_file; do
            [[ -z "$target_file" ]] && continue
            [[ "$target_file" =~ \.(c|h|S)$ ]] || continue

            local full_path="$KERNEL_SRC/$target_file"
            [[ -f "$full_path" ]] || continue

            # Extract added lines (fix code) for this file
            local added_lines
            added_lines=$(awk -v fname="$target_file" '
                    /^diff --git/ { in_file = index($0, fname) > 0 }
                    substr($0,1,3) == "+++" { next }
                    in_file && substr($0,1,1) == "+" {
                        line = substr($0, 2)
                        gsub(/^[[:space:]]+/, "", line)
                        gsub(/[[:space:]]+$/, "", line)
                        '"$awk_filter"'
                    }
                ' "$diff_file" | sort -u | head -10)

            # Extract removed lines (vulnerable code) for this file
            local removed_lines
            removed_lines=$(awk -v fname="$target_file" '
                    /^diff --git/ { in_file = index($0, fname) > 0 }
                    substr($0,1,3) == "---" { next }
                    in_file && substr($0,1,1) == "-" {
                        line = substr($0, 2)
                        gsub(/^[[:space:]]+/, "", line)
                        gsub(/[[:space:]]+$/, "", line)
                        '"$awk_filter"'
                    }
                ' "$diff_file" | sort -u | head -10)

            local file_added=0 file_removed=0
            [[ -n "$added_lines" ]] && file_added=$(echo "$added_lines" | wc -l)
            [[ -n "$removed_lines" ]] && file_removed=$(echo "$removed_lines" | wc -l)

            [[ "$file_added" -eq 0 && "$file_removed" -eq 0 ]] && continue
            ((any_file_checked++)) || true

            # Build set of added lines for moved-line detection
            declare -A added_set=()
            if [[ -n "$added_lines" ]]; then
                while IFS= read -r fp; do
                    [[ -n "$fp" ]] && added_set["$fp"]=1
                done <<< "$added_lines"
            fi

            # Identify moved lines (appear in both added and removed)
            # Moved lines are code that was relocated within the file, not
            # truly added/removed. Exclude from removed counting to prevent
            # inflated removed_ratio that blocks FIXED classification.
            local file_moved=0
            if [[ "$file_removed" -gt 0 && "$file_added" -gt 0 ]]; then
                while IFS= read -r fp; do
                    [[ -z "$fp" ]] && continue
                    [[ -n "${added_set[$fp]+_}" ]] && ((file_moved++)) || true
                done <<< "$removed_lines"
            fi

            total_added=$((total_added + file_added))
            total_removed=$((total_removed + file_removed - file_moved))

            # Count added line matches
            # Use whole-line matching to avoid substring false positives
            # (e.g., "kfree(ptr)" matching "kfree(ptr->member)").
            # For long lines (>=40 chars), use substring matching as they
            # are distinctive enough and may have minor formatting differences.
            if [[ "$file_added" -gt 0 ]]; then
                declare -A seen_added=()
                while IFS= read -r fp; do
                    [[ -z "$fp" || -n "${seen_added[$fp]+_}" ]] && continue
                    seen_added["$fp"]=1
                    if [[ "${#fp}" -lt 40 ]]; then
                        awk -v pat="$fp" '{
                            line = $0; gsub(/^[[:space:]]+/, "", line); gsub(/[[:space:]]+$/, "", line)
                            if (line == pat) { found=1; exit }
                        } END { exit !found }' "$full_path" 2>/dev/null && ((added_matched++)) || true
                    else
                        grep -qF -- "$fp" "$full_path" 2>/dev/null && ((added_matched++)) || true
                    fi
                done <<< "$added_lines"
                unset seen_added
            fi

            # Count removed line matches
            # Skip moved lines (also in added_lines) - finding them in source
            # doesn't indicate vulnerability is present, just that code was moved.
            # For short removed lines (<30 chars), use whole-line matching to
            # avoid substring false positives (e.g., "sb->s_flags" matching
            # inside "sbi->sb->s_flags")
            if [[ "$file_removed" -gt 0 ]]; then
                declare -A seen_removed=()
                while IFS= read -r fp; do
                    [[ -z "$fp" || -n "${seen_removed[$fp]+_}" ]] && continue
                    seen_removed["$fp"]=1
                    # Skip moved lines
                    [[ -n "${added_set[$fp]+_}" ]] && continue
                    if [[ "${#fp}" -lt 30 ]]; then
                        # Whole-line match: trim leading/trailing whitespace from
                        # each source line before comparing
                        awk -v pat="$fp" '{
                            line = $0; gsub(/^[[:space:]]+/, "", line); gsub(/[[:space:]]+$/, "", line)
                            if (line == pat) { found=1; exit }
                        } END { exit !found }' "$full_path" 2>/dev/null && ((removed_matched++)) || true
                    else
                        grep -qF -- "$fp" "$full_path" 2>/dev/null && ((removed_matched++)) || true
                    fi
                done <<< "$removed_lines"
                unset seen_removed

                # Contiguous block check for this file's removed lines
                # Skip moved lines (also in added_lines) for contiguous check
                if [[ "$contiguous_checked" -eq 0 && "$file_removed" -ge 1 ]]; then
                    local r_ratio_file=0
                    local effective_file_removed=$((file_removed - file_moved))
                    # Only check contiguous if this file has high removed match
                    local file_r_matched=0
                    while IFS= read -r fp; do
                        [[ -z "$fp" ]] && continue
                        # Skip moved lines
                        [[ -n "${added_set[$fp]+_}" ]] && continue
                        if [[ "${#fp}" -lt 30 ]]; then
                            awk -v pat="$fp" '{
                                line = $0; gsub(/^[[:space:]]+/, "", line); gsub(/[[:space:]]+$/, "", line)
                                if (line == pat) { found=1; exit }
                            } END { exit !found }' "$full_path" 2>/dev/null && ((file_r_matched++)) || true
                        else
                            grep -qF -- "$fp" "$full_path" 2>/dev/null && ((file_r_matched++)) || true
                        fi
                    done <<< "$removed_lines"
                    [[ "$effective_file_removed" -gt 0 ]] && r_ratio_file=$(( file_r_matched * 100 / effective_file_removed ))

                    if [[ "$r_ratio_file" -ge 70 ]]; then
                        contiguous_checked=1
                        if [[ "$file_removed" -ge 2 ]]; then
                            local line1 line2
                            line1=$(echo "$removed_lines" | head -1)
                            line2=$(echo "$removed_lines" | sed -n '2p')
                            if [[ -n "$line1" && -n "$line2" ]]; then
                                local ln_nums
                                ln_nums=$(grep -nF -- "$line1" "$full_path" 2>/dev/null | cut -d: -f1 || true)
                                for ln in $ln_nums; do
                                    local start=$(( ln > 1 ? ln - 1 : 1 ))
                                    local end=$(( ln + 5 ))
                                    if sed -n "${start},${end}p" "$full_path" 2>/dev/null | grep -qF -- "$line2"; then
                                        removed_contiguous=1
                                        break
                                    fi
                                done
                            fi
                        elif [[ "$file_removed" -eq 1 ]]; then
                            removed_contiguous=1
                        fi
                    fi
                fi
            fi
            unset added_set

        done < "$files_file"

        # No files checked -> INCONCLUSIVE
        [[ "$any_file_checked" -eq 0 ]] && { echo "INCONCLUSIVE"; return; }

        # Clamp total_removed to 0 minimum (moved-line subtraction can make it negative)
        [[ "$total_removed" -lt 0 ]] && total_removed=0

        # Calculate aggregate ratios
        local added_ratio=0 removed_ratio=0
        [[ "$total_added" -gt 0 ]] && added_ratio=$(( (added_matched * 100) / total_added ))
        [[ "$total_removed" -gt 0 ]] && removed_ratio=$(( (removed_matched * 100) / total_removed ))
        [[ "$added_ratio" -gt 100 ]] && added_ratio=100
        [[ "$removed_ratio" -gt 100 ]] && removed_ratio=100

        # ---- Phase 1: Fingerprint-based verdict ----
        local verdict="INCONCLUSIVE"

        if [[ "$total_removed" -gt 0 && "$removed_ratio" -ge 70 && "$removed_contiguous" -eq 1 ]]; then
            if [[ "$total_added" -gt 0 && "$added_ratio" -ge 80 ]]; then
                # Both fix code AND vulnerable code pattern present. This
                # happens when the same code pattern exists in multiple
                # functions and the fix only changes some occurrences.
                # Fix code is strongly present, so not truly UNFIXED.
                verdict="LIKELY_FIXED"
            else
                verdict="UNFIXED"
            fi
        elif [[ "$total_added" -gt 0 && "$added_ratio" -ge 50 ]]; then
            if [[ "$total_removed" -ge 2 && "$total_added" -ge 3 && "$removed_ratio" -lt 15 && "$added_ratio" -ge 70 ]]; then
                # Fix code strongly present (≥70% added lines match) + most
                # vulnerable code gone (≥2 removed, <15% match) -> FIXED
                # Requires both high added match and very low removed match
                # to avoid false positives from coincidental substring matches.
                verdict="FIXED"
            elif [[ "$total_removed" -gt 0 && "$removed_ratio" -lt 50 ]]; then
                # Fix code present but removed signal weak (1 line or 30-50%):
                # ambiguous, could be partial fix or coincidental matches
                verdict="LIKELY_FIXED"
            elif [[ "$total_removed" -eq 0 ]]; then
                # Pure-addition fix: no removed lines to confirm vulnerability was
                # present. Added lines may coincidentally match existing code.
                # Without removed-line evidence, classify as INCONCLUSIVE -
                # not enough signal for even LIKELY_FIXED.
                verdict="INCONCLUSIVE"
            elif [[ "$removed_ratio" -ge 70 ]]; then
                # Removed code >=70% present but fix code also present (>=50%).
                # Since we're inside added_ratio >= 50 branch, the fix code IS
                # present. The vulnerable pattern likely exists in other
                # functions. Classify as LIKELY_FIXED not UNFIXED.
                verdict="LIKELY_FIXED"
            else
                # Remaining cases (50%<=removed<70%):
                # ambiguous signal, needs review
                verdict="LIKELY_FIXED"
            fi
        elif [[ "$total_added" -gt 0 && "$added_ratio" -ge 40 ]]; then
            if [[ "$total_removed" -gt 0 && "$removed_ratio" -ge 50 ]]; then
                # Partial fix match + vulnerable code substantially present -> UNFIXED
                verdict="UNFIXED"
            elif [[ "$total_removed" -gt 0 ]]; then
                verdict="LIKELY_FIXED"
            else
                # Pure addition with weak match (40-49%) -> INCONCLUSIVE
                verdict="INCONCLUSIVE"
            fi
        elif [[ "$total_added" -eq 0 && "$total_removed" -gt 0 && "$removed_matched" -eq 0 ]]; then
            # Removal-only fix: no added fingerprint lines (e.g., comment-only
            # additions filtered out) but all removed (vulnerable) lines are
            # gone from the source. Strong signal the fix was applied.
            if [[ "$total_removed" -ge 2 ]]; then
                verdict="FIXED"
            else
                verdict="LIKELY_FIXED"
            fi
        elif [[ "$total_removed" -gt 0 && "$removed_ratio" -ge 50 ]]; then
            if [[ "$removed_contiguous" -eq 1 ]]; then
                verdict="UNFIXED"
            else
                verdict="UNFIXED"
            fi
        elif [[ "$total_added" -gt 0 && "$total_added" -le 2 && "$added_matched" -gt 0 ]]; then
            # Very few distinctive lines (1-2) matched. Too weak for
            # LIKELY_FIXED - single-line matches are often coincidental.
            verdict="INCONCLUSIVE"
        elif [[ "$total_added" -ge 3 && "$added_matched" -eq 0 ]]; then
            verdict="UNFIXED"
        fi

        # ---- Phase 2: Context-aware confirmation ----
        # Use context adjacency to upgrade/downgrade verdicts.
        # Only runs for LIKELY_FIXED and INCONCLUSIVE. Context adjacency is
        # unreliable for overriding UNFIXED verdicts (83% false positive rate
        # in testing) because context lines and fix lines repeat across
        # functions in large kernel source files.
        if [[ "$verdict" == "LIKELY_FIXED" || "$verdict" == "INCONCLUSIVE" ]]; then
            local ctx_found=0 ctx_fixed=0 ctx_unfixed=0

            while IFS= read -r target_file; do
                [[ -z "$target_file" || ! "$target_file" =~ \.(c|h|S)$ ]] && continue
                local full_path="$KERNEL_SRC/$target_file"
                [[ -f "$full_path" ]] || continue

                # Check context+ADDED pairs: was the fix inserted near its context?
                # Extracts both context_before+added AND context_after+added pairs
                while IFS=$'\t' read -r ctx_line add_line; do
                    [[ -z "$ctx_line" || -z "$add_line" ]] && continue
                    ((ctx_found++)) || true
                    local ctx_lns
                    ctx_lns=$(grep -nF -- "$ctx_line" "$full_path" 2>/dev/null | cut -d: -f1 || true)
                    [[ -z "$ctx_lns" ]] && continue
                    local found_near=0
                    for cln in $ctx_lns; do
                        local cs=$((cln > 3 ? cln - 3 : 1)) ce=$((cln + 3))
                        if sed -n "${cs},${ce}p" "$full_path" 2>/dev/null | grep -qF -- "$add_line"; then
                            found_near=1; break
                        fi
                    done
                    if [[ "$found_near" -eq 1 ]]; then
                        ((ctx_fixed++)) || true
                    else
                        ((ctx_unfixed++)) || true
                    fi
                done < <(awk -v fname="$target_file" '
                    /^diff --git/ { in_file = index($0, fname) > 0 }
                    in_file && substr($0,1,1) == " " {
                        ctx = $0; sub(/^[ \t]+/, "", ctx); sub(/[ \t]+$/, "", ctx)
                        # context_after: pair previous added line with this context
                        if (last_add != "" && length(ctx) >= 8 && ctx !~ /^[\/\*]/) {
                            printf "%s\t%s\n", ctx, last_add
                        }
                        last_add = ""
                    }
                    in_file && substr($0,1,1) == "+" && substr($0,1,3) != "+++" {
                        add = substr($0, 2); sub(/^[ \t]+/, "", add); sub(/[ \t]+$/, "", add)
                        # context_before: pair previous context with this added line
                        if (length(ctx) >= 8 && length(add) >= 4 && ctx !~ /^[\/\*]/ && add != "{" && add != "}") {
                            printf "%s\t%s\n", ctx, add
                            ctx = ""
                        }
                        if (length(add) >= 4 && add != "{" && add != "}") last_add = add
                    }
                ' "$diff_file")

                # Check context+REMOVED pairs: is vulnerable code still near its context?
                while IFS=$'\t' read -r ctx_line rm_line; do
                    [[ -z "$ctx_line" || -z "$rm_line" ]] && continue
                    ((ctx_found++)) || true
                    local ctx_lns
                    ctx_lns=$(grep -nF -- "$ctx_line" "$full_path" 2>/dev/null | cut -d: -f1 || true)
                    [[ -z "$ctx_lns" ]] && continue
                    local found_near=0
                    for cln in $ctx_lns; do
                        local cs=$cln ce=$((cln + 3))
                        if sed -n "${cs},${ce}p" "$full_path" 2>/dev/null | grep -qF -- "$rm_line"; then
                            found_near=1; break
                        fi
                    done
                    if [[ "$found_near" -eq 1 ]]; then
                        # Vulnerable code still present near context -> unfixed signal
                        ((ctx_unfixed++)) || true
                    else
                        # Vulnerable code gone from context -> fixed signal
                        ((ctx_fixed++)) || true
                    fi
                done < <(awk -v fname="$target_file" '
                    /^diff --git/ { in_file = index($0, fname) > 0 }
                    in_file && substr($0,1,1) == " " {
                        ctx = $0; sub(/^[ \t]+/, "", ctx); sub(/[ \t]+$/, "", ctx)
                    }
                    in_file && substr($0,1,1) == "-" && substr($0,1,3) != "---" {
                        rm = substr($0, 2); sub(/^[ \t]+/, "", rm); sub(/[ \t]+$/, "", rm)
                        if (length(ctx) >= 8 && length(rm) >= 4 && ctx !~ /^[\/\*]/ && rm != "{" && rm != "}") {
                            printf "%s\t%s\n", ctx, rm
                            ctx = ""
                        }
                    }
                ' "$diff_file")
            done < "$files_file"

            if [[ "$ctx_found" -gt 0 ]]; then
                if [[ "$ctx_fixed" -gt "$ctx_unfixed" ]]; then
                    # Context majority says fix applied
                    if [[ "$verdict" == "INCONCLUSIVE" ]]; then
                        verdict="LIKELY_FIXED"
                    fi
                    # LIKELY_FIXED stays LIKELY_FIXED - context adjacency alone
                    # is not reliable enough to upgrade to FIXED. Substring
                    # matching produces too many false context matches in large
                    # kernel source files.
                elif [[ "$ctx_unfixed" -gt "$ctx_fixed" ]]; then
                    # Context majority says fix NOT applied
                    if [[ "$verdict" == "LIKELY_FIXED" ]]; then
                        if [[ "$ctx_unfixed" -ge $(( ctx_fixed * 2 + 1 )) && "$total_added" -le 2 ]]; then
                            # Strong unfixed signal + weak added match -> UNFIXED
                            verdict="UNFIXED"
                        fi
                    elif [[ "$verdict" == "INCONCLUSIVE" ]]; then
                        verdict="UNFIXED"
                    fi
                    # UNFIXED stays UNFIXED (confirmed by context)
                fi
                # Equal context signals -> don't change verdict
            fi
        fi

        echo "$verdict"
    }

    # ---- Step 8: Export lookup tables to flat files for parallel workers ----
    log_info "  Exporting lookup tables for parallel processing..."

    local lookup_dir="$OUTPUT_DIR/.lookups"
    mkdir -p "$lookup_dir"

    # CVE -> fix hashes (tab-separated: CVE<TAB>hash1 hash2 ...)
    for cve in "${!CVE_FIX_HASHES[@]}"; do
        printf '%s\t%s\n' "$cve" "${CVE_FIX_HASHES[$cve]}"
    done > "$lookup_dir/cve_fix_hashes.txt"

    # CVE -> backport hashes
    for cve in "${!CVE_BACKPORT_HASHES[@]}"; do
        printf '%s\t%s\n' "$cve" "${CVE_BACKPORT_HASHES[$cve]}"
    done > "$lookup_dir/cve_backport_hashes.txt"

    # Hash -> in_repo flag (sorted for grep -F)
    printf '%s\n' "${!HASH_IN_REPO[@]}" | sort > "$lookup_dir/hashes_in_repo.txt"

    # KEV set (sorted for grep -F)
    printf '%s\n' "${!KEV_CACHE[@]}" | sort > "$lookup_dir/kev_set.txt"

    # Enabled configs (sorted for grep)
    printf '%s\n' "${!ENABLED_CONFIGS[@]}" | sort > "$lookup_dir/enabled_configs.txt"

    # Config maps: file->config and dir->config (TSV)
    for f in "${!FILE_CONFIG_MAP[@]}"; do
        printf '%s\t%s\n' "$f" "${FILE_CONFIG_MAP[$f]}"
    done | sort > "$lookup_dir/file_config_map.txt"

    for d in "${!DIR_CONFIG_MAP[@]}"; do
        printf '%s\t%s\n' "$d" "${DIR_CONFIG_MAP[$d]}"
    done | sort > "$lookup_dir/dir_config_map.txt"

    # ---- Step 9: Write worker script to temp file ----
    # Using a temp script avoids all quoting issues with inline bash -c
    local worker_script="$OUTPUT_DIR/.worker.sh"
    cat > "$worker_script" << 'WORKER_EOF'
#!/usr/bin/env bash
set -euo pipefail

chunk_file="$1"
results_dir="$2"
lookup_dir="$3"
commit_files_dir="$4"
commit_diffs_dir="$5"
kernel_src="$6"

chunk_id=$(basename "$chunk_file")
out="$results_dir/${chunk_id}.tsv"
> "$out"

# Load lookup tables
declare -A cve_fix_hashes cve_backport_hashes hash_in_repo kev_cache
declare -A enabled_configs file_config_map dir_config_map

while IFS=$'\t' read -r cve rest; do
    cve_fix_hashes["$cve"]="$rest"
done < "$lookup_dir/cve_fix_hashes.txt"

while IFS=$'\t' read -r cve rest; do
    cve_backport_hashes["$cve"]="$rest"
done < "$lookup_dir/cve_backport_hashes.txt"

while IFS= read -r h; do
    [[ -n "$h" ]] && hash_in_repo["$h"]=1
done < "$lookup_dir/hashes_in_repo.txt"

while IFS= read -r c; do
    [[ -n "$c" ]] && kev_cache["$c"]=1
done < "$lookup_dir/kev_set.txt"

while IFS= read -r c; do
    [[ -n "$c" ]] && enabled_configs["$c"]=1
done < "$lookup_dir/enabled_configs.txt"

while IFS=$'\t' read -r f c; do
    file_config_map["$f"]="$c"
done < "$lookup_dir/file_config_map.txt"

while IFS=$'\t' read -r d c; do
    dir_config_map["$d"]="$c"
done < "$lookup_dir/dir_config_map.txt"

map_file_to_config_w() {
    local fp="$1"
    if [[ -n "${file_config_map[$fp]+_}" ]]; then
        echo "${file_config_map[$fp]}"; return
    fi
    local dir="$fp"
    while true; do
        dir=$(dirname "$dir")
        [[ "$dir" == "." || -z "$dir" ]] && break
        if [[ -n "${dir_config_map[$dir]+_}" ]]; then
            echo "${dir_config_map[$dir]}"; return
        fi
    done
    echo "UNKNOWN"
}

check_fix_applied_w() {
    local hash="$1"
    local files_file="$commit_files_dir/$hash"
    local diff_file="$commit_diffs_dir/$hash"
    if [[ ! -s "$files_file" || ! -s "$diff_file" ]]; then
        echo "INCONCLUSIVE"
        return
    fi

    # Accumulate match evidence across ALL changed files
    local total_added=0 total_removed=0
    local added_matched=0 removed_matched=0
    local any_file_checked=0
    local removed_contiguous=0
    local contiguous_checked=0

    while IFS= read -r tfile; do
        [[ -z "$tfile" || ! "$tfile" =~ \.(c|h|S)$ ]] && continue
        local fpath="$kernel_src/$tfile"
        [[ -f "$fpath" ]] || continue

        # Extract added lines (fix code) for this file
        local added_lines
        added_lines=$(awk -v fname="$tfile" '
            /^diff --git/ { in_file = index($0, fname) > 0 }
            substr($0,1,3) == "+++" { next }
            in_file && substr($0,1,1) == "+" {
                line = substr($0, 2)
                gsub(/^[[:space:]]+/, "", line); gsub(/[[:space:]]+$/, "", line)
                if (length(line) < 8) next
                if (line == "{" || line == "}") next
                if (substr(line,1,2) == "/*" || substr(line,1,1) == "*") next
                if (substr(line,1,8) == "#include") next
                if (line == "break;" || line == "continue;") next
                if (substr(line,1,6) == "return") next
                if (line == "else" || line == "default:") next
                if (line == "NULL") next
                if (substr(line,1,5) == "goto ") next
                if (line ~ /^(int|long|bool|void|unsigned|struct|enum|const|static) [a-z_]+;$/) next
                if (line ~ /^(int|long|bool) [a-z_]+ = 0;$/) next
                if (line ~ /^(int|long) (ret|err|rc|res|status);$/) next
                if (line ~ /^(int|long) (ret|err|rc|res|status) = 0;$/) next
                if (line ~ /^if \(!(err|ret|rc|res|ptr|dev|priv|data|ctx|info|buf|skb|hdr|req|rsp|msg|cmd|cfg|reg|val|tmp|node|entry|item|obj|page|inode|dentry|sb)\)$/) next
                if (line ~ /^if \((err|ret|rc|res) < 0\)$/) next
                if (line ~ /^if \((err|ret|rc)\)$/) next
                if (line ~ /^mutex_(lock|unlock)\(/) next
                if (line ~ /^spin_(lock|unlock)/) next
                if (line ~ /^rcu_read_(lock|unlock)\(\)/) next
                print line
            }' "$diff_file" | sort -u | head -10)

        # Extract removed lines (vulnerable code) for this file
        local removed_lines
        removed_lines=$(awk -v fname="$tfile" '
            /^diff --git/ { in_file = index($0, fname) > 0 }
            substr($0,1,3) == "---" { next }
            in_file && substr($0,1,1) == "-" {
                line = substr($0, 2)
                gsub(/^[[:space:]]+/, "", line); gsub(/[[:space:]]+$/, "", line)
                if (length(line) < 8) next
                if (line == "{" || line == "}") next
                if (substr(line,1,2) == "/*" || substr(line,1,1) == "*") next
                if (substr(line,1,8) == "#include") next
                if (line == "break;" || line == "continue;") next
                if (substr(line,1,6) == "return") next
                if (line == "else" || line == "default:") next
                if (line == "NULL") next
                if (substr(line,1,5) == "goto ") next
                if (line ~ /^(int|long|bool|void|unsigned|struct|enum|const|static) [a-z_]+;$/) next
                if (line ~ /^(int|long|bool) [a-z_]+ = 0;$/) next
                if (line ~ /^(int|long) (ret|err|rc|res|status);$/) next
                if (line ~ /^(int|long) (ret|err|rc|res|status) = 0;$/) next
                if (line ~ /^if \(!(err|ret|rc|res|ptr|dev|priv|data|ctx|info|buf|skb|hdr|req|rsp|msg|cmd|cfg|reg|val|tmp|node|entry|item|obj|page|inode|dentry|sb)\)$/) next
                if (line ~ /^if \((err|ret|rc|res) < 0\)$/) next
                if (line ~ /^if \((err|ret|rc)\)$/) next
                if (line ~ /^mutex_(lock|unlock)\(/) next
                if (line ~ /^spin_(lock|unlock)/) next
                if (line ~ /^rcu_read_(lock|unlock)\(\)/) next
                print line
            }' "$diff_file" | sort -u | head -10)

        local file_added=0 file_removed=0
        [[ -n "$added_lines" ]] && file_added=$(echo "$added_lines" | wc -l)
        [[ -n "$removed_lines" ]] && file_removed=$(echo "$removed_lines" | wc -l)

        [[ "$file_added" -eq 0 && "$file_removed" -eq 0 ]] && continue
        ((any_file_checked++)) || true

        # Build set of added lines for moved-line detection
        declare -A added_set_w=()
        if [[ -n "$added_lines" ]]; then
            while IFS= read -r fp; do
                [[ -n "$fp" ]] && added_set_w["$fp"]=1
            done <<< "$added_lines"
        fi

        # Identify moved lines (appear in both added and removed)
        local file_moved=0
        if [[ "$file_removed" -gt 0 && "$file_added" -gt 0 ]]; then
            while IFS= read -r fp; do
                [[ -z "$fp" ]] && continue
                [[ -n "${added_set_w[$fp]+_}" ]] && ((file_moved++)) || true
            done <<< "$removed_lines"
        fi

        total_added=$((total_added + file_added))
        total_removed=$((total_removed + file_removed - file_moved))

        # Count added line matches
        # Use whole-line matching for short lines (<40 chars) to avoid
        # substring false positives. Long lines use substring matching.
        if [[ "$file_added" -gt 0 ]]; then
            declare -A seen_a=()
            while IFS= read -r fp; do
                [[ -z "$fp" || -n "${seen_a[$fp]+_}" ]] && continue
                seen_a["$fp"]=1
                if [[ "${#fp}" -lt 40 ]]; then
                    awk -v pat="$fp" '{
                        line = $0; gsub(/^[[:space:]]+/, "", line); gsub(/[[:space:]]+$/, "", line)
                        if (line == pat) { found=1; exit }
                    } END { exit !found }' "$fpath" 2>/dev/null && ((added_matched++)) || true
                else
                    grep -qF -- "$fp" "$fpath" 2>/dev/null && ((added_matched++)) || true
                fi
            done <<< "$added_lines"
            unset seen_a
        fi

        # Count removed line matches
        # Skip moved lines (also in added_lines) - finding them in source
        # doesn't indicate vulnerability is present, just that code was moved.
        # For short removed lines (<30 chars), use whole-line matching to
        # avoid substring false positives (e.g., "sb->s_flags" matching
        # inside "sbi->sb->s_flags")
        if [[ "$file_removed" -gt 0 ]]; then
            declare -A seen_r=()
            while IFS= read -r fp; do
                [[ -z "$fp" || -n "${seen_r[$fp]+_}" ]] && continue
                seen_r["$fp"]=1
                # Skip moved lines
                [[ -n "${added_set_w[$fp]+_}" ]] && continue
                if [[ "${#fp}" -lt 30 ]]; then
                    awk -v pat="$fp" '{
                        line = $0; gsub(/^[[:space:]]+/, "", line); gsub(/[[:space:]]+$/, "", line)
                        if (line == pat) { found=1; exit }
                    } END { exit !found }' "$fpath" 2>/dev/null && ((removed_matched++)) || true
                else
                    grep -qF -- "$fp" "$fpath" 2>/dev/null && ((removed_matched++)) || true
                fi
            done <<< "$removed_lines"
            unset seen_r

            # Contiguous block check for this file's removed lines
            # Skip moved lines (also in added_lines) for contiguous check
            if [[ "$contiguous_checked" -eq 0 && "$file_removed" -ge 1 ]]; then
                local effective_file_removed=$((file_removed - file_moved))
                local file_r_matched=0
                while IFS= read -r fp; do
                    [[ -z "$fp" ]] && continue
                    # Skip moved lines
                    [[ -n "${added_set_w[$fp]+_}" ]] && continue
                    if [[ "${#fp}" -lt 30 ]]; then
                        awk -v pat="$fp" '{
                            line = $0; gsub(/^[[:space:]]+/, "", line); gsub(/[[:space:]]+$/, "", line)
                            if (line == pat) { found=1; exit }
                        } END { exit !found }' "$fpath" 2>/dev/null && ((file_r_matched++)) || true
                    else
                        grep -qF -- "$fp" "$fpath" 2>/dev/null && ((file_r_matched++)) || true
                    fi
                done <<< "$removed_lines"
                local r_ratio_file=0
                [[ "$effective_file_removed" -gt 0 ]] && r_ratio_file=$(( file_r_matched * 100 / effective_file_removed ))

                if [[ "$r_ratio_file" -ge 70 ]]; then
                    contiguous_checked=1
                    if [[ "$file_removed" -ge 2 ]]; then
                        local line1 line2
                        line1=$(echo "$removed_lines" | head -1)
                        line2=$(echo "$removed_lines" | sed -n '2p')
                        if [[ -n "$line1" && -n "$line2" ]]; then
                            local ln_nums
                            ln_nums=$(grep -nF -- "$line1" "$fpath" 2>/dev/null | cut -d: -f1 || true)
                            for ln in $ln_nums; do
                                local s=$(( ln > 1 ? ln - 1 : 1 ))
                                local e=$(( ln + 5 ))
                                if sed -n "${s},${e}p" "$fpath" 2>/dev/null | grep -qF -- "$line2"; then
                                    removed_contiguous=1
                                    break
                                fi
                            done
                        fi
                    elif [[ "$file_removed" -eq 1 ]]; then
                        removed_contiguous=1
                    fi
                fi
            fi
        fi
        unset added_set_w

    done < "$files_file"

    [[ "$any_file_checked" -eq 0 ]] && { echo "INCONCLUSIVE"; return; }

    # Clamp total_removed to 0 minimum (moved-line subtraction can make it negative)
    [[ "$total_removed" -lt 0 ]] && total_removed=0

    # Calculate aggregate ratios
    local added_ratio=0 removed_ratio=0
    [[ "$total_added" -gt 0 ]] && added_ratio=$(( (added_matched * 100) / total_added ))
    [[ "$total_removed" -gt 0 ]] && removed_ratio=$(( (removed_matched * 100) / total_removed ))
    [[ "$added_ratio" -gt 100 ]] && added_ratio=100
    [[ "$removed_ratio" -gt 100 ]] && removed_ratio=100

    # ---- Phase 1: Fingerprint-based verdict ----
    local verdict="INCONCLUSIVE"

    if [[ "$total_removed" -gt 0 && "$removed_ratio" -ge 70 && "$removed_contiguous" -eq 1 ]]; then
        if [[ "$total_added" -gt 0 && "$added_ratio" -ge 80 ]]; then
            # Both fix code AND vulnerable code pattern present. This
            # happens when the same code pattern exists in multiple
            # functions and the fix only changes some occurrences.
            verdict="LIKELY_FIXED"
        else
            verdict="UNFIXED"
        fi
    elif [[ "$total_added" -gt 0 && "$added_ratio" -ge 50 ]]; then
        if [[ "$total_removed" -ge 2 && "$total_added" -ge 3 && "$removed_ratio" -lt 15 && "$added_ratio" -ge 70 ]]; then
            verdict="FIXED"
        elif [[ "$total_removed" -gt 0 && "$removed_ratio" -lt 50 ]]; then
            verdict="LIKELY_FIXED"
        elif [[ "$total_removed" -eq 0 ]]; then
            # Pure addition: no removed-line evidence -> INCONCLUSIVE
            verdict="INCONCLUSIVE"
        elif [[ "$removed_ratio" -ge 70 ]]; then
            if [[ "$added_ratio" -ge 80 ]]; then
                verdict="LIKELY_FIXED"
            else
                verdict="UNFIXED"
            fi
        else
            verdict="LIKELY_FIXED"
        fi
    elif [[ "$total_added" -gt 0 && "$added_ratio" -ge 40 ]]; then
        if [[ "$total_removed" -gt 0 && "$removed_ratio" -ge 50 ]]; then
            verdict="UNFIXED"
        elif [[ "$total_removed" -gt 0 ]]; then
            verdict="LIKELY_FIXED"
        else
            verdict="INCONCLUSIVE"
        fi
    elif [[ "$total_added" -eq 0 && "$total_removed" -gt 0 && "$removed_matched" -eq 0 ]]; then
        # Removal-only fix: no added fingerprint lines (e.g., comment-only
        # additions filtered out) but all removed (vulnerable) lines are
        # gone from the source. Strong signal the fix was applied.
        if [[ "$total_removed" -ge 2 ]]; then
            verdict="FIXED"
        else
            verdict="LIKELY_FIXED"
        fi
    elif [[ "$total_removed" -gt 0 && "$removed_ratio" -ge 50 ]]; then
        if [[ "$removed_contiguous" -eq 1 ]]; then
            verdict="UNFIXED"
        else
            verdict="UNFIXED"
        fi
    elif [[ "$total_added" -gt 0 && "$total_added" -le 2 && "$added_matched" -gt 0 ]]; then
        # Very few distinctive lines (1-2) matched - too weak for LIKELY_FIXED
        verdict="INCONCLUSIVE"
    elif [[ "$total_added" -ge 3 && "$added_matched" -eq 0 ]]; then
        verdict="UNFIXED"
    fi

    # ---- Phase 2: Context-aware confirmation ----
    # Use context adjacency to upgrade/downgrade verdicts.
    # Only runs for LIKELY_FIXED and INCONCLUSIVE. Context adjacency is
    # unreliable for overriding UNFIXED verdicts.
    if [[ "$verdict" == "LIKELY_FIXED" || "$verdict" == "INCONCLUSIVE" ]]; then
        local ctx_found=0 ctx_fixed=0 ctx_unfixed=0

        while IFS= read -r tfile; do
            [[ -z "$tfile" || ! "$tfile" =~ \.(c|h|S)$ ]] && continue
            local fpath="$kernel_src/$tfile"
            [[ -f "$fpath" ]] || continue

            # Check context+ADDED pairs (context_before AND context_after)
            while IFS=$'\t' read -r ctx_line add_line; do
                [[ -z "$ctx_line" || -z "$add_line" ]] && continue
                ((ctx_found++)) || true
                local ctx_lns
                ctx_lns=$(grep -nF -- "$ctx_line" "$fpath" 2>/dev/null | cut -d: -f1 || true)
                [[ -z "$ctx_lns" ]] && continue
                local found_near=0
                for cln in $ctx_lns; do
                    local cs=$((cln > 3 ? cln - 3 : 1)) ce=$((cln + 3))
                    if sed -n "${cs},${ce}p" "$fpath" 2>/dev/null | grep -qF -- "$add_line"; then
                        found_near=1; break
                    fi
                done
                if [[ "$found_near" -eq 1 ]]; then
                    ((ctx_fixed++)) || true
                else
                    ((ctx_unfixed++)) || true
                fi
            done < <(awk -v fname="$tfile" '
                /^diff --git/ { in_file = index($0, fname) > 0 }
                in_file && substr($0,1,1) == " " {
                    ctx = $0; sub(/^[ \t]+/, "", ctx); sub(/[ \t]+$/, "", ctx)
                    if (last_add != "" && length(ctx) >= 8 && ctx !~ /^[\/\*]/) {
                        printf "%s\t%s\n", ctx, last_add
                    }
                    last_add = ""
                }
                in_file && substr($0,1,1) == "+" && substr($0,1,3) != "+++" {
                    add = substr($0, 2); sub(/^[ \t]+/, "", add); sub(/[ \t]+$/, "", add)
                    if (length(ctx) >= 8 && length(add) >= 4 && ctx !~ /^[\/\*]/ && add != "{" && add != "}") {
                        printf "%s\t%s\n", ctx, add
                        ctx = ""
                    }
                    if (length(add) >= 4 && add != "{" && add != "}") last_add = add
                }
            ' "$diff_file")

            # Check context+REMOVED pairs: is vulnerable code still near its context?
            while IFS=$'\t' read -r ctx_line rm_line; do
                [[ -z "$ctx_line" || -z "$rm_line" ]] && continue
                ((ctx_found++)) || true
                local ctx_lns
                ctx_lns=$(grep -nF -- "$ctx_line" "$fpath" 2>/dev/null | cut -d: -f1 || true)
                [[ -z "$ctx_lns" ]] && continue
                local found_near=0
                for cln in $ctx_lns; do
                    local cs=$cln ce=$((cln + 3))
                    if sed -n "${cs},${ce}p" "$fpath" 2>/dev/null | grep -qF -- "$rm_line"; then
                        found_near=1; break
                    fi
                done
                if [[ "$found_near" -eq 1 ]]; then
                    ((ctx_unfixed++)) || true
                else
                    ((ctx_fixed++)) || true
                fi
            done < <(awk -v fname="$tfile" '
                /^diff --git/ { in_file = index($0, fname) > 0 }
                in_file && substr($0,1,1) == " " {
                    ctx = $0; sub(/^[ \t]+/, "", ctx); sub(/[ \t]+$/, "", ctx)
                }
                in_file && substr($0,1,1) == "-" && substr($0,1,3) != "---" {
                    rm = substr($0, 2); sub(/^[ \t]+/, "", rm); sub(/[ \t]+$/, "", rm)
                    if (length(ctx) >= 8 && length(rm) >= 4 && ctx !~ /^[\/\*]/ && rm != "{" && rm != "}") {
                        printf "%s\t%s\n", ctx, rm
                        ctx = ""
                    }
                }
            ' "$diff_file")
        done < "$files_file"

        if [[ "$ctx_found" -gt 0 ]]; then
            if [[ "$ctx_fixed" -gt "$ctx_unfixed" ]]; then
                if [[ "$verdict" == "INCONCLUSIVE" ]]; then
                    verdict="LIKELY_FIXED"
                fi
                # LIKELY_FIXED stays LIKELY_FIXED - context adjacency alone
                # is not reliable enough to upgrade to FIXED.
            elif [[ "$ctx_unfixed" -gt "$ctx_fixed" ]]; then
                if [[ "$verdict" == "LIKELY_FIXED" ]]; then
                    if [[ "$ctx_unfixed" -ge $(( ctx_fixed * 2 + 1 )) && "$total_added" -le 2 ]]; then verdict="UNFIXED"; fi
                elif [[ "$verdict" == "INCONCLUSIVE" ]]; then verdict="UNFIXED"; fi
            fi
        fi
    fi

    echo "$verdict"
}

declare -A config_cache=()

while IFS=$'\t' read -r cve_id cvss_score severity description; do
    [[ -z "$cve_id" ]] && continue

    local_in_kev="No"
    [[ -n "${kev_cache[$cve_id]+_}" ]] && local_in_kev="Yes"

    declare -A seen_configs=()
    has_enabled=0; has_disabled=0; has_unknown=0
    all_hashes=""
    [[ -n "${cve_fix_hashes[$cve_id]+_}" ]] && all_hashes="${cve_fix_hashes[$cve_id]}"
    [[ -n "${cve_backport_hashes[$cve_id]+_}" ]] && all_hashes+=" ${cve_backport_hashes[$cve_id]}"

    for h in $all_hashes; do
        files_file="$commit_files_dir/$h"
        [[ -s "$files_file" ]] || continue
        while IFS= read -r file; do
            [[ -z "$file" ]] && continue
            cfg=""
            if [[ -n "${config_cache[$file]+_}" ]]; then
                cfg="${config_cache[$file]}"
            else
                cfg=$(map_file_to_config_w "$file")
                config_cache["$file"]="$cfg"
            fi
            [[ "$cfg" != "UNKNOWN" && "$cfg" != "ALWAYS_BUILT" ]] && seen_configs["$cfg"]=1
            if [[ "$cfg" == "UNKNOWN" ]]; then has_unknown=1
            elif [[ "$cfg" == "ALWAYS_BUILT" ]]; then has_enabled=1
            elif [[ -n "${enabled_configs[$cfg]+_}" ]]; then has_enabled=1
            else has_disabled=1; fi
        done < "$files_file"
    done

    config_str="UNKNOWN"
    config_status="UNKNOWN"
    ckeys=("${!seen_configs[@]}")
    [[ ${#ckeys[@]} -gt 0 ]] && config_str=$(IFS=';'; echo "${ckeys[*]}")
    if [[ "$has_enabled" -eq 1 ]]; then config_status="ENABLED"
    elif [[ "$has_disabled" -eq 1 && "$has_unknown" -eq 0 ]]; then config_status="DISABLED"
    elif [[ "$has_unknown" -eq 1 ]]; then config_status="UNKNOWN"; fi

    fix_status="UNFIXED"
    has_fix_info=0
    if [[ "$config_status" == "DISABLED" ]]; then
        fix_status="NOT_APPLICABLE"
    else
        # Collect verdicts from all hashes, then aggregate
        fixed_count=0; unfixed_count=0; likely_count=0; inconc_count=0

        # Try upstream fix hashes first
        if [[ -n "${cve_fix_hashes[$cve_id]+_}" ]]; then
            has_fix_info=1
            for uh in ${cve_fix_hashes[$cve_id]}; do
                if [[ -n "${hash_in_repo[$uh]+_}" ]]; then
                    verdict=$(check_fix_applied_w "$uh")
                    case "$verdict" in
                        FIXED)        ((fixed_count++)) || true ;;
                        UNFIXED)      ((unfixed_count++)) || true ;;
                        LIKELY_FIXED) ((likely_count++)) || true ;;
                        INCONCLUSIVE) ((inconc_count++)) || true ;;
                    esac
                fi
            done
        fi
        # Try backport hashes
        if [[ -n "${cve_backport_hashes[$cve_id]+_}" ]]; then
            has_fix_info=1
            for bh in ${cve_backport_hashes[$cve_id]}; do
                verdict=$(check_fix_applied_w "$bh")
                case "$verdict" in
                    FIXED)        ((fixed_count++)) || true ;;
                    UNFIXED)      ((unfixed_count++)) || true ;;
                    LIKELY_FIXED) ((likely_count++)) || true ;;
                    INCONCLUSIVE) ((inconc_count++)) || true ;;
                esac
            done
        fi

        # Aggregate verdicts across all hashes
        # FIXED requires: at least one FIXED verdict AND zero UNFIXED
        # verdicts AND FIXED must dominate. Any UNFIXED vote vetoes FIXED
        # because different branch backports may produce inconsistent results.
        if [[ "$fixed_count" -gt 0 && "$unfixed_count" -eq 0 && "$fixed_count" -gt "$likely_count" ]]; then
            fix_status="FIXED"
        elif [[ "$fixed_count" -gt 0 && "$unfixed_count" -gt 0 ]]; then
            # Mixed signals: some hashes say FIXED, others UNFIXED.
            # Conservatively report LIKELY_FIXED.
            fix_status="LIKELY_FIXED"
        elif [[ "$likely_count" -gt 0 ]]; then
            fix_status="LIKELY_FIXED"
        elif [[ "$unfixed_count" -gt 0 ]]; then
            fix_status="UNFIXED"
        elif [[ "$inconc_count" -gt 0 ]]; then
            fix_status="INCONCLUSIVE"
        fi

        # No fix info from any source -> INCONCLUSIVE
        if [[ "$has_fix_info" -eq 0 ]]; then
            fix_status="INCONCLUSIVE"
        fi
    fi

    description="${description//$'\t'/ }"
    description="${description//,/;}"
    description="${description//\"/\'}"
    description="${description//$'\n'/ }"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$cve_id" "$severity" "$cvss_score" "$local_in_kev" \
        "$fix_status" "$config_str" "$config_status" "$description" \
        >> "$out"

done < "$chunk_file"
WORKER_EOF
    chmod +x "$worker_script"

    # ---- Step 10: Split CVEs into chunks and process in parallel ----
    local total_cves
    total_cves=$(wc -l < "$AFFECTED_CVES_FILE")
    log_info "  Processing $total_cves affected CVEs (jobs=$JOBS)..."

    local chunk_dir="$OUTPUT_DIR/.chunks"
    local results_dir="$OUTPUT_DIR/.partial_results"
    mkdir -p "$chunk_dir" "$results_dir"

    local chunk_lines=$(( (total_cves + JOBS - 1) / JOBS ))
    split -l "$chunk_lines" "$AFFECTED_CVES_FILE" "$chunk_dir/chunk_"

    # Run worker script on each chunk in parallel
    ls "$chunk_dir"/chunk_* | \
    xargs -P"$JOBS" -I{} bash "$worker_script" \
        "{}" "$results_dir" "$lookup_dir" "$commit_files_dir" "$commit_diffs_dir" "$KERNEL_SRC" \
        || true

    # Merge partial results
    cat "$results_dir"/*.tsv 2>/dev/null > "$RESULTS_FILE" || true

    # Cleanup
    rm -rf "$commit_files_dir" "$commit_diffs_dir" "$chunk_dir" "$results_dir" \
           "$lookup_dir" "$worker_script"
    log_info "  Processing complete."
}

# =============================================================================
# Generate CSV report with summary
# =============================================================================

generate_csv() {
    log_info "Generating CSV report..."

    local output_csv="$OUTPUT_DIR/backport-report.csv"

    # Compute summary
    local total_cves total_fixed total_unfixed total_na
    local total_likely_fixed total_likely_not_fixed total_inconclusive
    local cves_in_kev fixed_in_kev
    local config_enabled config_disabled config_unknown
    local sev_critical sev_high sev_medium sev_low

    total_cves=$(wc -l < "$RESULTS_FILE")
    total_fixed=$(awk -F'\t' '$5 == "FIXED"' "$RESULTS_FILE" | wc -l)
    total_unfixed=$(awk -F'\t' '$5 == "UNFIXED"' "$RESULTS_FILE" | wc -l)
    total_likely_fixed=$(awk -F'\t' '$5 == "LIKELY_FIXED"' "$RESULTS_FILE" | wc -l)
    total_inconclusive=$(awk -F'\t' '$5 == "INCONCLUSIVE"' "$RESULTS_FILE" | wc -l)
    total_na=$(awk -F'\t' '$5 == "NOT_APPLICABLE"' "$RESULTS_FILE" | wc -l)
    cves_in_kev=$(awk -F'\t' '$4 == "Yes"' "$RESULTS_FILE" | wc -l)
    fixed_in_kev=$(awk -F'\t' '$4 == "Yes" && $5 == "FIXED"' "$RESULTS_FILE" | wc -l)
    config_enabled=$(awk -F'\t' '$7 == "ENABLED"' "$RESULTS_FILE" | wc -l)
    config_disabled=$(awk -F'\t' '$7 == "DISABLED"' "$RESULTS_FILE" | wc -l)
    config_unknown=$(awk -F'\t' '$7 == "UNKNOWN"' "$RESULTS_FILE" | wc -l)

    sev_critical=$(awk -F'\t' '$5 != "NOT_APPLICABLE" && $2 == "CRITICAL"' "$RESULTS_FILE" | wc -l)
    sev_high=$(awk -F'\t' '$5 != "NOT_APPLICABLE" && $2 == "HIGH"' "$RESULTS_FILE" | wc -l)
    sev_medium=$(awk -F'\t' '$5 != "NOT_APPLICABLE" && $2 == "MEDIUM"' "$RESULTS_FILE" | wc -l)
    sev_low=$(awk -F'\t' '$5 != "NOT_APPLICABLE" && $2 == "LOW"' "$RESULTS_FILE" | wc -l)

    # Unfixed severity breakdown
    local unfixed_critical unfixed_high unfixed_medium unfixed_low
    unfixed_critical=$(awk -F'\t' '$5 == "UNFIXED" && $2 == "CRITICAL"' "$RESULTS_FILE" | wc -l)
    unfixed_high=$(awk -F'\t' '$5 == "UNFIXED" && $2 == "HIGH"' "$RESULTS_FILE" | wc -l)
    unfixed_medium=$(awk -F'\t' '$5 == "UNFIXED" && $2 == "MEDIUM"' "$RESULTS_FILE" | wc -l)
    unfixed_low=$(awk -F'\t' '$5 == "UNFIXED" && $2 == "LOW"' "$RESULTS_FILE" | wc -l)

    local applicable_cves=$((total_cves - total_na))

    {
        echo "# Kernel Backport Checker Report v${VERSION}"
        echo "# Generated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "# Kernel Version: $KERNEL_VERSION"
        echo "# Kernel Config: $KERNEL_CONFIG"
        echo "# Git Repository: $KERNEL_DIR"
        [[ -n "$STABLE_DIR" ]] && echo "# Stable/Vendor Repo: $STABLE_DIR"
        echo "#"
        echo "# ===== Summary ====="
        echo "# Total CVEs affecting kernel $KERNEL_VERSION: $total_cves"
        echo "# Not applicable (config disabled): $total_na"
        echo "# Applicable CVEs: $applicable_cves"
        echo "#   Fixed via backport: $total_fixed"
        echo "#   Likely fixed (needs review): $total_likely_fixed"
        echo "#   Unfixed (remaining): $total_unfixed"
        echo "#   Inconclusive: $total_inconclusive"
        echo "#"
        echo "# CVEs in CISA KEV: $cves_in_kev (fixed: $fixed_in_kev, unfixed: $((cves_in_kev - fixed_in_kev)))"
        echo "#"
        echo "# Config applicability:"
        echo "#   ENABLED:  $config_enabled"
        echo "#   DISABLED (not applicable): $config_disabled"
        echo "#   UNKNOWN:  $config_unknown"
        echo "#"
        echo "# Severity breakdown (applicable CVEs only):"
        echo "#   CRITICAL: $sev_critical (unfixed: $unfixed_critical)"
        echo "#   HIGH:     $sev_high (unfixed: $unfixed_high)"
        echo "#   MEDIUM:   $sev_medium (unfixed: $unfixed_medium)"
        echo "#   LOW:      $sev_low (unfixed: $unfixed_low)"
        echo "#"
        echo "CVE-ID,Severity,CVSS-Score,In-CISA-KEV,Fix-Status,Affected-Config,Config-Status,Description"

        # Sort: UNFIXED first, then by severity, then convert TSV to CSV using awk
        sort -t$'\t' -k5,5r -k2,2 "$RESULTS_FILE" | \
        awk -F'\t' '{
            # Fields: 1=CVE-ID, 2=Severity, 3=CVSS, 4=KEV, 5=Status, 6=Config, 7=ConfigStatus, 8+=Description
            # Reassemble description (in case of stray tabs)
            desc = $8
            for (i = 9; i <= NF; i++) desc = desc " " $i
            gsub(/"/, "'\''", desc)
            gsub(/,/, ";", desc)
            printf "%s,%s,%s,%s,%s,\"%s\",%s,\"%s\"\n", $1, $2, $3, $4, $5, $6, $7, desc
        }'

    } > "$output_csv"

    # Clean up
    rm -f "$RESULTS_FILE"

    log_info "==========================================="
    log_info "Report: $output_csv"
    log_info "==========================================="
    log_info ""
    log_info "Summary for kernel $KERNEL_VERSION:"
    log_info "  Total CVEs:              $total_cves"
    log_info "  Not applicable:          $total_na"
    log_info "  Applicable:              $applicable_cves"
    log_info "    Fixed via backport:    $total_fixed"
    log_info "    Likely fixed (review): $total_likely_fixed"
    log_info "    Unfixed (remaining):   $total_unfixed"
    log_info "    Inconclusive:          $total_inconclusive"
    log_info ""
    log_info "  CVEs in CISA KEV:        $cves_in_kev (fixed: $fixed_in_kev)"
    log_info ""
    log_info "  Severity (applicable / unfixed):"
    log_info "    CRITICAL:              $sev_critical / $unfixed_critical"
    log_info "    HIGH:                  $sev_high / $unfixed_high"
    log_info "    MEDIUM:                $sev_medium / $unfixed_medium"
    log_info "    LOW:                   $sev_low / $unfixed_low"
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo "========================================"
    echo " Kernel Backport Checker v${VERSION}"
    echo "========================================"
    echo ""

    check_dependencies
    parse_args "$@"

    log_info "Configuration:"
    log_info "  Kernel Source:   $KERNEL_SRC"
    log_info "  Kernel Config:   $KERNEL_CONFIG"
    log_info "  Git Repository:  $KERNEL_DIR"
    [[ -n "$STABLE_DIR" ]] && log_info "  Stable/Vendor:   $STABLE_DIR"
    log_info "  KEV File:        $KEV_FILE"
    log_info "  NVD Feeds:       $NVD_FEEDS_DIR"
    log_info "  Output:          $OUTPUT_DIR"
    log_info "  Parallel Jobs:   $JOBS"
    echo ""

    detect_kernel_version
    load_kernel_config
    build_config_mapping
    scan_nvd_for_kernel_cves
    extract_nvd_fix_refs
    build_git_hash_index
    extract_backported_cves
    build_kev_index
    process_results
    generate_csv

    echo ""
    log_info "Done!"
}

main "$@"