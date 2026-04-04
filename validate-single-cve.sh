#!/bin/bash
# validate-single-cve.sh - Validate a single CVE verdict against ground truth
#
# Tests whether a CVE's upstream fix patch applies cleanly to the kernel source.
# If the patch applies, the fix is NOT present (ground truth = UNFIXED).
# If the patch fails, the fix is likely present or there's a context conflict.
#
# Output format: CVE_ID|VERDICT|RESULT|HASH
#   RESULT values:
#     CORRECT              - Verdict matches ground truth
#     FP_FIXED             - False positive: checker says FIXED but fix NOT present
#     FP_LIKELY            - Soft false positive: checker says LIKELY_FIXED but fix NOT present
#     PATCH_CONFLICT_FIXED - Patch fails for FIXED verdict (unconfirmed)
#     PATCH_CONFLICT_LIKELY- Patch fails for LIKELY_FIXED verdict (unconfirmed)
#     PATCH_CONFLICT       - Patch fails for UNFIXED verdict (context mismatch)
#     PATCH_CONFLICT_INCONC- Patch fails for INCONCLUSIVE verdict
#     UNTESTABLE           - No fix hash available for testing
#
# Usage:
#   ./validate-single-cve.sh -c <CVE-ID> -s <kernel-src> -d <upstream-repo> \
#       -b <stable-repo> -o <output-dir> [-r <report-csv>]

set -uo pipefail

usage() {
    cat <<EOF
Usage: $0 -c <CVE-ID> -s <kernel-src> -d <upstream-repo> -b <stable-repo> -o <output-dir> [-r <report>]

Required:
  -c CVE       CVE identifier (e.g. CVE-2024-12345)
  -s SOURCE    Path to kernel source tree
  -d UPSTREAM  Path to upstream Linux kernel git repository
  -b STABLE    Path to stable/vendor git repository
  -o OUTPUT    Path to checker output directory (contains .nvd_fix_refs_*.tsv)

Optional:
  -r REPORT    Path to backport-report.csv (default: OUTPUT/backport-report.csv)
  -h           Show this help
EOF
    exit 1
}

CVE="" KERNEL_SRC="" UPSTREAM="" STABLE="" OUTPUT="" REPORT=""

while getopts "c:s:d:b:o:r:h" opt; do
    case "$opt" in
        c) CVE="$OPTARG" ;;
        s) KERNEL_SRC="$OPTARG" ;;
        d) UPSTREAM="$OPTARG" ;;
        b) STABLE="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        r) REPORT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required parameters
[[ -z "$CVE" ]]        && { echo "Error: -c <CVE-ID> is required" >&2; usage; }
[[ -z "$KERNEL_SRC" ]] && { echo "Error: -s <kernel-src> is required" >&2; usage; }
[[ -z "$UPSTREAM" ]]   && { echo "Error: -d <upstream-repo> is required" >&2; usage; }
[[ -z "$STABLE" ]]     && { echo "Error: -b <stable-repo> is required" >&2; usage; }
[[ -z "$OUTPUT" ]]     && { echo "Error: -o <output-dir> is required" >&2; usage; }

REPORT="${REPORT:-$OUTPUT/backport-report.csv}"

[[ -d "$KERNEL_SRC" ]] || { echo "Error: Kernel source not found: $KERNEL_SRC" >&2; exit 1; }
[[ -d "$UPSTREAM" ]]   || { echo "Error: Upstream repo not found: $UPSTREAM" >&2; exit 1; }
[[ -d "$STABLE" ]]     || { echo "Error: Stable repo not found: $STABLE" >&2; exit 1; }
[[ -f "$REPORT" ]]     || { echo "Error: Report not found: $REPORT" >&2; exit 1; }

# Find the fix refs file (version-agnostic)
FIX_REFS=$(ls "$OUTPUT"/.nvd_fix_refs_*.tsv 2>/dev/null | head -1)
[[ -f "$FIX_REFS" ]] || { echo "Error: NVD fix refs not found in $OUTPUT" >&2; exit 1; }

# Cleanup temp files on exit
_tmpfiles=()
cleanup() { rm -f "${_tmpfiles[@]}" 2>/dev/null; }
trap cleanup EXIT

verdict=$(grep "^${CVE}," "$REPORT" | awk -F',' '{print $5}')
hashes=$(awk -F'\t' -v cve="$CVE" '$1 == cve {print $2}' "$FIX_REFS")

if [[ -z "$hashes" ]]; then
    echo "$CVE|$verdict|UNTESTABLE|"
    exit 0
fi

patch_applies=0
applied_hash=""
for hash in $hashes; do
    short="${hash:0:12}"
    repo=""
    if git -C "$UPSTREAM" cat-file -e "$short" 2>/dev/null; then repo="$UPSTREAM"
    elif git -C "$STABLE" cat-file -e "$short" 2>/dev/null; then repo="$STABLE"
    else continue; fi

    tmpfile=$(mktemp)
    _tmpfiles+=("$tmpfile")
    git -C "$repo" format-patch -1 --stdout "$short" > "$tmpfile" 2>/dev/null
    if patch -p1 --dry-run -d "$KERNEL_SRC" < "$tmpfile" > /dev/null 2>&1; then
        patch_applies=1
        applied_hash="$short"
        break
    fi
done

if [[ "$patch_applies" -eq 1 ]]; then
    # Fix NOT present (patch can be applied) -> ground truth is UNFIXED
    case "$verdict" in
        FIXED)        echo "$CVE|$verdict|FP_FIXED|$applied_hash" ;;
        LIKELY_FIXED) echo "$CVE|$verdict|FP_LIKELY|$applied_hash" ;;
        *)            echo "$CVE|$verdict|CORRECT|" ;;
    esac
else
    # Patch doesn't apply cleanly. Two possible reasons:
    #   a) Fix IS present (patch already applied) -> FIXED/LIKELY_FIXED correct
    #   b) Context mismatch between kernel versions -> cannot determine
    # We cannot distinguish (a) from (b), so mark as untestable conflict.
    case "$verdict" in
        FIXED)        echo "$CVE|$verdict|PATCH_CONFLICT_FIXED|" ;;
        LIKELY_FIXED) echo "$CVE|$verdict|PATCH_CONFLICT_LIKELY|" ;;
        UNFIXED)      echo "$CVE|$verdict|PATCH_CONFLICT|" ;;
        INCONCLUSIVE) echo "$CVE|$verdict|PATCH_CONFLICT_INCONC|" ;;
        *)            echo "$CVE|$verdict|PATCH_CONFLICT|" ;;
    esac
fi
