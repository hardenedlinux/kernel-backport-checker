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
#   4. Check git repo for backported fixes (CVE-ID in commit messages)
#   5. Output CSV: each CVE marked as FIXED or UNFIXED
#
# Usage:
#   ./kernel-backport-checker.sh -s <kernel-source-dir> -d <linux-git-dir> \
#       -e <kev-data> -f <nvd-json-data-feeds> -k <kernel-config> -o <output-dir>
#

set -euo pipefail

VERSION="3.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---- Global variables ----
KEV_FILE=""
KERNEL_DIR=""
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
    -d <path>    Linux kernel git directory (with backport commits)
    -e <path>    CISA KEV data directory or JSON file
    -f <path>    NVD JSON data feeds directory (fkie-cad/nvd-json-data-feeds)
    -k <path>    Kernel .config file
    -o <path>    Output directory for results

Optional:
    -j <N>       Number of parallel jobs (default: nproc/2, min 1)
    -h           Show this help

Example:
    $0 -s linux-6.1.1 -d linux -e kev-data -f nvd-json-data-feeds -k 6.1-config -o output
    $0 -s linux-6.1.1 -d linux -e kev-data -f nvd-json-data-feeds -k 6.1-config -o output -j 8

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
    while getopts "e:d:k:f:o:s:j:h" opt; do
        case $opt in
            e) KEV_FILE="$OPTARG" ;;
            d) KERNEL_DIR="$OPTARG" ;;
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

    git -C "$KERNEL_DIR" rev-list --all 2>/dev/null | cut -c1-12 | sort > "$GIT_HASH_INDEX"

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
    find "$KERNEL_SRC" \( -name "Makefile" -o -name "Kbuild" \) -print0 | \
      xargs -0 -P"$JOBS" -n50 awk -v srcroot="$KERNEL_SRC/" '
        FILENAME != prev_file {
            prev_file = FILENAME
            dir = FILENAME
            sub(/\/[^\/]+$/, "", dir)   # remove filename
            sub(srcroot, "", dir)        # make relative
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
                    print dir "/" base "\t" config
                } else if (parts[i] ~ /\/$/) {
                    subdir = parts[i]
                    sub(/\/$/, "", subdir)
                    print dir "/" subdir "\t" config
                }
            }
        }
        line ~ /obj-y[[:space:]]*[\+:]?=/ {
            n = split(line, parts, /[[:space:]+=]+/)
            for (i = 1; i <= n; i++) {
                if (parts[i] ~ /\.o$/) {
                    base = parts[i]
                    sub(/\.o$/, ".c", base)
                    print dir "/" base "\tALWAYS_BUILT"
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

    git -C "$KERNEL_DIR" log --all --grep="CVE-" \
        --pretty=format:"${record_sep}%H|%ci|%an|%s%n%b" > "$BACKPORTED_CVES_FILE.raw" 2>/dev/null || {
        log_error "Failed to read git log from $KERNEL_DIR"
        exit 1
    }

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

    # ---- Step 2: Find which upstream fix hashes exist in upstream repo ----
    log_info "  Matching fix commits against upstream repo..."

    local fix_hashes_sorted="$OUTPUT_DIR/.fix_hashes_sorted.txt"
    awk -F'\t' '{print substr($2,1,12) "\t" $1 "\t" $2}' "$NVD_FIX_REFS_FILE" | \
        sort -t$'\t' -k1,1 > "$fix_hashes_sorted"

    declare -A HASH_IN_REPO
    while IFS=$'\t' read -r short cve_id full_hash; do
        HASH_IN_REPO["$full_hash"]=1
    done < <(join -t$'\t' -1 1 -2 1 "$fix_hashes_sorted" "$GIT_HASH_INDEX" 2>/dev/null)

    local matched_hashes=${#HASH_IN_REPO[@]}
    log_info "  Found $matched_hashes fix commits in upstream repo"
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
    # Parallel extraction of changed files AND full diffs
    cat "$all_hashes_file" | xargs -P"$JOBS" -I{} bash -c '
        full_hash="{}"
        short="${full_hash:0:12}"
        files_out="'"$commit_files_dir"'/${full_hash}"
        diff_out="'"$commit_diffs_dir"'/${full_hash}"
        if [[ ! -f "$files_out" ]]; then
            git -C "'"$kernel_dir"'" diff-tree --no-commit-id -r --name-only "$short" \
                > "$files_out" 2>/dev/null || true
        fi
        if [[ ! -f "$diff_out" ]]; then
            git -C "'"$kernel_dir"'" diff "${short}^..${short}" \
                > "$diff_out" 2>/dev/null || true
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
    # Strategy: extract distinctive "added lines" from the fix commit diff,
    # check each fingerprint against its specific changed file in the target.
    # Uses per-file matching (not global) to avoid overcounting across files.
    check_fix_applied() {
        local commit_hash="$1"
        local short="${commit_hash:0:12}"

        # Get changed files
        local files_file="$commit_files_dir/$commit_hash"
        if [[ ! -s "$files_file" ]]; then
            return 1
        fi

        # Use pre-computed diff (avoids git call in hot path)
        local diff_file="$commit_diffs_dir/$commit_hash"
        if [[ ! -s "$diff_file" ]]; then
            return 1
        fi

        # Process each changed file independently
        local any_file_verified=0
        local any_file_checked=0

        while IFS= read -r target_file; do
            [[ -z "$target_file" ]] && continue
            # Only check source files (.c, .h, .S)
            [[ "$target_file" =~ \.(c|h|S)$ ]] || continue

            local full_path="$KERNEL_SRC/$target_file"
            [[ -f "$full_path" ]] || continue

            # Extract fingerprints only for lines added in this specific file
            local fingerprints
            fingerprints=$(awk -v fname="$target_file" '
                    /^diff --git/ { in_file = index($0, fname) > 0 }
                    substr($0,1,3) == "+++" { next }
                    in_file && substr($0,1,1) == "+" {
                        line = substr($0, 2)
                        # Strip leading/trailing whitespace
                        gsub(/^[[:space:]]+/, "", line)
                        gsub(/[[:space:]]+$/, "", line)
                        if (length(line) < 15) next
                        if (line == "{" || line == "}") next
                        if (substr(line,1,2) == "/*") next
                        if (substr(line,1,1) == "*") next
                        if (substr(line,1,8) == "#include") next
                        if (line == "break;") next
                        if (substr(line,1,6) == "return") next
                        if (substr(line,1,8) == "rcu_read") next
                        if (substr(line,1,9) == "spin_lock" || substr(line,1,11) == "spin_unlock") next
                        if (substr(line,1,10) == "mutex_lock" || substr(line,1,12) == "mutex_unlock") next
                        if (line == "NULL") next
                        print line
                    }
                ' "$diff_file" | head -5)

            [[ -z "$fingerprints" ]] && continue

            ((any_file_checked++)) || true

            # Count how many distinct fingerprints match in this file
            local total_fps matched_fps
            total_fps=$(echo "$fingerprints" | wc -l)
            matched_fps=0
            declare -A seen_fps=()

            while IFS= read -r fp; do
                [[ -z "$fp" ]] && continue
                # Skip if already counted this fingerprint (dedup)
                [[ -n "${seen_fps[$fp]+_}" ]] && continue
                seen_fps["$fp"]=1
                if grep -qF "$fp" "$full_path" 2>/dev/null; then
                    ((matched_fps++)) || true
                fi
            done <<< "$fingerprints"

            # Require majority of DISTINCT fingerprints to match
            local threshold=$(( (total_fps + 1) / 2 ))
            if [[ "$matched_fps" -ge "$threshold" && "$total_fps" -gt 0 ]]; then
                any_file_verified=1
                break
            fi

        done < "$files_file"

        # Fix is applied if at least one changed file has matching fingerprints
        [[ "$any_file_verified" -eq 1 ]] && return 0
        return 1
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
    [[ -s "$files_file" && -s "$diff_file" ]] || return 1

    local verified=0
    while IFS= read -r tfile; do
        [[ -z "$tfile" || ! "$tfile" =~ \.(c|h|S)$ ]] && continue
        local fpath="$kernel_src/$tfile"
        [[ -f "$fpath" ]] || continue

        local fps
        fps=$(awk -v fname="$tfile" '
            /^diff --git/ { in_file = index($0, fname) > 0 }
            substr($0,1,3) == "+++" { next }
            in_file && substr($0,1,1) == "+" {
                line = substr($0, 2)
                gsub(/^[[:space:]]+/, "", line); gsub(/[[:space:]]+$/, "", line)
                if (length(line) < 15) next
                if (line == "{" || line == "}") next
                if (substr(line,1,2) == "/*" || substr(line,1,1) == "*") next
                if (substr(line,1,8) == "#include") next
                if (line == "break;") next
                if (substr(line,1,6) == "return") next
                if (substr(line,1,8) == "rcu_read") next
                if (substr(line,1,9) == "spin_lock" || substr(line,1,11) == "spin_unlock") next
                if (substr(line,1,10) == "mutex_lock" || substr(line,1,12) == "mutex_unlock") next
                print line
            }' "$diff_file" | head -5)

        [[ -z "$fps" ]] && continue

        local total matched
        total=$(echo "$fps" | wc -l)
        matched=0
        declare -A seen_fps=()
        while IFS= read -r fp; do
            [[ -z "$fp" || -n "${seen_fps[$fp]+_}" ]] && continue
            seen_fps["$fp"]=1
            grep -qF "$fp" "$fpath" 2>/dev/null && ((matched++)) || true
        done <<< "$fps"
        unset seen_fps

        local thresh=$(( (total + 1) / 2 ))
        if [[ "$matched" -ge "$thresh" && "$total" -gt 0 ]]; then
            verified=1; break
        fi
    done < "$files_file"

    [[ "$verified" -eq 1 ]] && return 0 || return 1
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
    if [[ "$config_status" == "DISABLED" ]]; then
        fix_status="NOT_APPLICABLE"
    else
        if [[ -n "${cve_fix_hashes[$cve_id]+_}" ]]; then
            for uh in ${cve_fix_hashes[$cve_id]}; do
                if [[ -n "${hash_in_repo[$uh]+_}" ]]; then
                    if check_fix_applied_w "$uh"; then fix_status="FIXED"; break; fi
                fi
            done
        fi
        if [[ "$fix_status" != "FIXED" && -n "${cve_backport_hashes[$cve_id]+_}" ]]; then
            for bh in ${cve_backport_hashes[$cve_id]}; do
                if check_fix_applied_w "$bh"; then fix_status="FIXED"; break; fi
            done
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
    local cves_in_kev fixed_in_kev
    local config_enabled config_disabled config_unknown
    local sev_critical sev_high sev_medium sev_low

    total_cves=$(wc -l < "$RESULTS_FILE")
    total_fixed=$(awk -F'\t' '$5 == "FIXED"' "$RESULTS_FILE" | wc -l)
    total_unfixed=$(awk -F'\t' '$5 == "UNFIXED"' "$RESULTS_FILE" | wc -l)
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

    # Unfixed severity breakdown (excluding NOT_APPLICABLE)
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
        echo "#"
        echo "# ===== Summary ====="
        echo "# Total CVEs affecting kernel $KERNEL_VERSION: $total_cves"
        echo "# Not applicable (config disabled): $total_na"
        echo "# Applicable CVEs: $applicable_cves"
        echo "#   Fixed via backport: $total_fixed"
        echo "#   Unfixed (remaining): $total_unfixed"
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
    log_info "    Unfixed (remaining):   $total_unfixed"
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
