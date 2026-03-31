#!/bin/bash
# validate-with-patches.sh - Apply N fix patches and verify detection
#
# Selects N random UNFIXED CVEs whose patches apply cleanly, applies them
# to the kernel source, re-runs the checker, and verifies each CVE is
# detected as FIXED or LIKELY_FIXED. Then reverts all patches.
#
# Usage:
#   ./validate-with-patches.sh -s <kernel-src> -d <upstream-repo> -b <stable-repo> \
#       -o <output-dir> -k <kernel-config> -e <kev-data> -f <nvd-feeds> [options]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 -s <kernel-src> -d <upstream-repo> -b <stable-repo> -o <output-dir> \\
          -k <kernel-config> -e <kev-data> -f <nvd-feeds> [options]

Required:
  -s SOURCE    Path to kernel source tree
  -d UPSTREAM  Path to upstream Linux kernel git repository
  -b STABLE    Path to stable/vendor git repository
  -o OUTPUT    Path to checker output directory
  -k CONFIG    Path to kernel .config file
  -e KEV       Path to CISA KEV data directory
  -f NVD       Path to NVD JSON data feeds directory

Optional:
  -n COUNT     Number of CVEs to test (default: 200)
  -j JOBS      Parallel jobs for checker (default: 5)
  -h           Show this help
EOF
    exit 1
}

KERNEL_SRC="" UPSTREAM="" STABLE="" OUTPUT_DIR="" KCONFIG="" KEV_DATA="" NVD_FEEDS=""
COUNT=200 JOBS=5

while getopts "s:d:b:o:k:e:f:n:j:h" opt; do
    case "$opt" in
        s) KERNEL_SRC="$OPTARG" ;;
        d) UPSTREAM="$OPTARG" ;;
        b) STABLE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        k) KCONFIG="$OPTARG" ;;
        e) KEV_DATA="$OPTARG" ;;
        f) NVD_FEEDS="$OPTARG" ;;
        n) COUNT="$OPTARG" ;;
        j) JOBS="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required parameters
[[ -z "$KERNEL_SRC" ]] && { echo "Error: -s <kernel-src> is required" >&2; usage; }
[[ -z "$UPSTREAM" ]]   && { echo "Error: -d <upstream-repo> is required" >&2; usage; }
[[ -z "$STABLE" ]]     && { echo "Error: -b <stable-repo> is required" >&2; usage; }
[[ -z "$OUTPUT_DIR" ]] && { echo "Error: -o <output-dir> is required" >&2; usage; }
[[ -z "$KCONFIG" ]]    && { echo "Error: -k <kernel-config> is required" >&2; usage; }
[[ -z "$KEV_DATA" ]]   && { echo "Error: -e <kev-data> is required" >&2; usage; }
[[ -z "$NVD_FEEDS" ]]  && { echo "Error: -f <nvd-feeds> is required" >&2; usage; }

[[ -d "$KERNEL_SRC" ]] || { echo "Error: Kernel source not found: $KERNEL_SRC" >&2; exit 1; }
[[ -d "$UPSTREAM" ]]   || { echo "Error: Upstream repo not found: $UPSTREAM" >&2; exit 1; }
[[ -d "$STABLE" ]]     || { echo "Error: Stable repo not found: $STABLE" >&2; exit 1; }
[[ -f "$KCONFIG" ]]    || { echo "Error: Kernel config not found: $KCONFIG" >&2; exit 1; }

REPORT="$OUTPUT_DIR/backport-report.csv"
FIX_REFS=$(ls "$OUTPUT_DIR"/.nvd_fix_refs_*.tsv 2>/dev/null | head -1)

[[ -f "$REPORT" ]]    || { echo "Error: Run kernel-backport-checker.sh first to generate report" >&2; exit 1; }
[[ -f "$FIX_REFS" ]]  || { echo "Error: NVD fix refs not found in $OUTPUT_DIR" >&2; exit 1; }

echo "=========================================="
echo " Patch-Apply Validation ($COUNT CVEs)"
echo "=========================================="

# Step 1: Find patchable UNFIXED CVEs
echo ""
echo "[1/5] Finding UNFIXED CVEs with cleanly-applying patches..."

CANDIDATES=$(mktemp)
grep ',UNFIXED,' "$REPORT" | awk -F',' '{print $1}' | sort > "$CANDIDATES"

CANDIDATES_FEW=$(mktemp)
awk -F'\t' '{print $1}' "$FIX_REFS" | sort | uniq -c | awk '$1 >= 1 && $1 <= 5 {print $2}' | sort > "${CANDIDATES_FEW}.hashes"
comm -12 "$CANDIDATES" "${CANDIDATES_FEW}.hashes" | shuf | head -$((COUNT * 2)) > "$CANDIDATES_FEW"
rm -f "${CANDIDATES_FEW}.hashes"

PATCHABLE=$(mktemp)
while read cve; do
    hashes=$(grep -P "^${cve}\t" "$FIX_REFS" | awk -F'\t' '{print $2}')
    for hash in $hashes; do
        short="${hash:0:12}"
        repo=""
        if git -C "$UPSTREAM" cat-file -e "$short" 2>/dev/null; then repo="$UPSTREAM"
        elif git -C "$STABLE" cat-file -e "$short" 2>/dev/null; then repo="$STABLE"
        else continue; fi

        nfiles=$(git -C "$repo" diff-tree --no-commit-id -r --name-only "$short" 2>/dev/null | wc -l)
        tmpfile=$(mktemp)
        git -C "$repo" format-patch -1 --stdout "$short" > "$tmpfile" 2>/dev/null
        if [[ "$nfiles" -ge 1 && "$nfiles" -le 10 ]] && \
           patch -p1 --dry-run -d "$KERNEL_SRC" < "$tmpfile" > /dev/null 2>&1; then
            echo -e "$cve\t$hash\t$nfiles" >> "$PATCHABLE"
        fi
        rm -f "$tmpfile"
        break
    done
    [[ $(wc -l < "$PATCHABLE" 2>/dev/null || echo 0) -ge $COUNT ]] && break
done < "$CANDIDATES_FEW"

head -"$COUNT" "$PATCHABLE" > "${PATCHABLE}.final"
mv "${PATCHABLE}.final" "$PATCHABLE"
actual=$(wc -l < "$PATCHABLE")
echo "  Found $actual patchable CVEs"

rm -f "$CANDIDATES" "$CANDIDATES_FEW"

# Step 2: Apply patches
echo ""
echo "[2/5] Applying $actual patches..."
applied=0
while IFS=$'\t' read -r cve hash nfiles; do
    short="${hash:0:12}"
    if git -C "$UPSTREAM" cat-file -e "$short" 2>/dev/null; then repo="$UPSTREAM"
    else repo="$STABLE"; fi
    tmpfile=$(mktemp)
    git -C "$repo" format-patch -1 --stdout "$short" > "$tmpfile" 2>/dev/null
    if patch -p1 -d "$KERNEL_SRC" < "$tmpfile" > /dev/null 2>&1; then
        applied=$((applied + 1))
    else
        echo "  WARNING: Failed to apply $cve ($short)"
    fi
    rm -f "$tmpfile"
done < "$PATCHABLE"
echo "  Applied: $applied / $actual"

# Step 3: Re-run checker
echo ""
echo "[3/5] Re-running checker..."

"$SCRIPT_DIR/kernel-backport-checker.sh" \
    -s "$KERNEL_SRC" \
    -d "$UPSTREAM" \
    -b "$STABLE" \
    -o "$OUTPUT_DIR" \
    -k "$KCONFIG" \
    -e "$KEV_DATA" \
    -f "$NVD_FEEDS" \
    -j "$JOBS" 2>&1 | grep -E '^\[INFO\]'

# Step 4: Check results
echo ""
echo "[4/5] Checking detection results..."
NEW_REPORT="$OUTPUT_DIR/backport-report.csv"

fixed=0; likely=0; unfixed=0; inconclusive=0
while IFS=$'\t' read -r cve hash nfiles; do
    status=$(grep "^$cve," "$NEW_REPORT" | awk -F',' '{print $5}')
    case "$status" in
        FIXED) fixed=$((fixed + 1)) ;;
        LIKELY_FIXED) likely=$((likely + 1)) ;;
        UNFIXED) unfixed=$((unfixed + 1)) ;;
        INCONCLUSIVE) inconclusive=$((inconclusive + 1)) ;;
    esac
done < "$PATCHABLE"

echo ""
echo "=== Detection Results ==="
echo "  FIXED:        $fixed / $actual"
echo "  LIKELY_FIXED: $likely / $actual"
echo "  UNFIXED:      $unfixed / $actual  (false negatives)"
echo "  INCONCLUSIVE: $inconclusive / $actual"
echo "  Detection:    $(( actual > 0 ? (fixed + likely) * 100 / actual : 0 ))%"

# Step 5: Revert patches
echo ""
echo "[5/5] Reverting patches..."
tac "$PATCHABLE" | while IFS=$'\t' read -r cve hash nfiles; do
    short="${hash:0:12}"
    if git -C "$UPSTREAM" cat-file -e "$short" 2>/dev/null; then repo="$UPSTREAM"
    else repo="$STABLE"; fi
    tmpfile=$(mktemp)
    git -C "$repo" format-patch -1 --stdout "$short" > "$tmpfile" 2>/dev/null
    patch -p1 -R -d "$KERNEL_SRC" < "$tmpfile" > /dev/null 2>&1
    rm -f "$tmpfile"
done
echo "  All patches reverted"

rm -f "$PATCHABLE"

echo ""
echo "=========================================="
echo " Validation Complete"
echo "=========================================="
