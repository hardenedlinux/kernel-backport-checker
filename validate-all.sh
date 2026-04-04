#!/bin/bash
# validate-all.sh - Validate CVE verdicts in the backport report
#
# Runs validate-single-cve.sh in parallel for applicable CVEs in the
# report, then prints a summary of false positives and false negatives.
#
# Usage:
#   ./validate-all.sh -s <kernel-src> -d <upstream-repo> -b <stable-repo> -o <output-dir> [options]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

usage() {
    cat <<EOF
Usage: $0 -s <kernel-src> -d <upstream-repo> -b <stable-repo> -o <output-dir> [options]

Required:
  -s SOURCE    Path to kernel source tree
  -d UPSTREAM  Path to upstream Linux kernel git repository
  -b STABLE    Path to stable/vendor git repository
  -o OUTPUT    Path to checker output directory

Optional:
  -r REPORT    Path to backport-report.csv (default: OUTPUT/backport-report.csv)
  -j JOBS      Number of parallel workers (default: 4)
  -n COUNT     Validate only COUNT random CVEs (default: all)
  -t VERDICT   Only validate CVEs with this verdict (e.g. LIKELY_FIXED, FIXED)
  -h           Show this help
EOF
    exit 1
}

KERNEL_SRC="" UPSTREAM="" STABLE="" OUTPUT_DIR="" REPORT="" JOBS=4 COUNT=0 FILTER_VERDICT=""

while getopts "s:d:b:o:r:j:n:t:h" opt; do
    case "$opt" in
        s) KERNEL_SRC="$OPTARG" ;;
        d) UPSTREAM="$OPTARG" ;;
        b) STABLE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        r) REPORT="$OPTARG" ;;
        j) JOBS="$OPTARG" ;;
        n) COUNT="$OPTARG" ;;
        t) FILTER_VERDICT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required parameters
[[ -z "$KERNEL_SRC" ]] && { echo "Error: -s <kernel-src> is required" >&2; usage; }
[[ -z "$UPSTREAM" ]]   && { echo "Error: -d <upstream-repo> is required" >&2; usage; }
[[ -z "$STABLE" ]]     && { echo "Error: -b <stable-repo> is required" >&2; usage; }
[[ -z "$OUTPUT_DIR" ]] && { echo "Error: -o <output-dir> is required" >&2; usage; }

REPORT="${REPORT:-$OUTPUT_DIR/backport-report.csv}"

[[ -d "$KERNEL_SRC" ]] || { echo "Error: Kernel source not found: $KERNEL_SRC" >&2; exit 1; }
[[ -d "$UPSTREAM" ]]   || { echo "Error: Upstream repo not found: $UPSTREAM" >&2; exit 1; }
[[ -d "$STABLE" ]]     || { echo "Error: Stable repo not found: $STABLE" >&2; exit 1; }
[[ -f "$REPORT" ]]     || { echo "Error: Report not found: $REPORT" >&2; exit 1; }
[[ -f "$SCRIPT_DIR/validate-single-cve.sh" ]] || { echo "Error: validate-single-cve.sh not found in $SCRIPT_DIR" >&2; exit 1; }

RESULTS_FILE="$OUTPUT_DIR/validation-results.txt"

echo "=========================================="
echo " Kernel Backport Checker - Full Validation"
echo "=========================================="
echo ""
echo "Report:     $REPORT"
echo "Source:     $KERNEL_SRC"
echo "Upstream:   $UPSTREAM"
echo "Stable:     $STABLE"
echo "Jobs:       $JOBS"
[[ -n "$FILTER_VERDICT" ]] && echo "Filter:     $FILTER_VERDICT only"
echo ""

# Get applicable CVEs
CVE_LIST=$(mktemp)
trap 'rm -f "$CVE_LIST"' EXIT

if [[ -n "$FILTER_VERDICT" ]]; then
    # Filter by specific verdict
    grep ",${FILTER_VERDICT}," "$REPORT" | grep "^CVE-" | awk -F',' '{print $1}' | sort > "$CVE_LIST"
else
    # All applicable (exclude NOT_APPLICABLE)
    grep -v ',NOT_APPLICABLE,' "$REPORT" | grep "^CVE-" | awk -F',' '{print $1}' | sort > "$CVE_LIST"
fi

if [[ "$COUNT" -gt 0 ]]; then
    shuf "$CVE_LIST" | head -"$COUNT" | sort > "${CVE_LIST}.tmp"
    mv "${CVE_LIST}.tmp" "$CVE_LIST"
fi

total_cves=$(wc -l < "$CVE_LIST")
echo "Validating $total_cves CVEs..."
echo ""

# Run validation in parallel with per-worker append for safe output
# Each worker produces exactly one line, appended atomically
> "$RESULTS_FILE"

_progress_file=$(mktemp)
echo "0" > "$_progress_file"
trap 'rm -f "$CVE_LIST" "$_progress_file"' EXIT

# Use xargs with append mode - each single-line echo is atomic on Linux
< "$CVE_LIST" xargs -P"$JOBS" -I{} bash -c '
    result=$("'"$SCRIPT_DIR"'/validate-single-cve.sh" \
        -c "{}" -s "'"$KERNEL_SRC"'" -d "'"$UPSTREAM"'" -b "'"$STABLE"'" \
        -o "'"$OUTPUT_DIR"'" -r "'"$REPORT"'" 2>/dev/null)
    if [[ -n "$result" ]]; then
        echo "$result" >> "'"$RESULTS_FILE"'"
        # Progress counter (best effort, not locked)
        n=$(cat "'"$_progress_file"'" 2>/dev/null || echo 0)
        echo $((n + 1)) > "'"$_progress_file"'" 2>/dev/null
        if (( (n + 1) % 100 == 0 )); then
            echo "  Progress: $((n + 1)) / '"$total_cves"'" >&2
        fi
    fi
'

echo ""

# Sort results for deterministic output
sort -o "$RESULTS_FILE" "$RESULTS_FILE"

# Summarize results
echo "=== Results ==="
echo ""
awk -F'|' '{print $3}' "$RESULTS_FILE" | sort | uniq -c | sort -rn
echo ""

# Count each result type using exact field matching to avoid substring issues
correct=$(awk -F'|' '$3 == "CORRECT"' "$RESULTS_FILE" | wc -l)
fp_fixed=$(awk -F'|' '$3 == "FP_FIXED"' "$RESULTS_FILE" | wc -l)
fp_likely=$(awk -F'|' '$3 == "FP_LIKELY"' "$RESULTS_FILE" | wc -l)
patch_conflict=$(awk -F'|' '$3 == "PATCH_CONFLICT"' "$RESULTS_FILE" | wc -l)
patch_conflict_inconc=$(awk -F'|' '$3 == "PATCH_CONFLICT_INCONC"' "$RESULTS_FILE" | wc -l)
patch_conflict_fixed=$(awk -F'|' '$3 == "PATCH_CONFLICT_FIXED"' "$RESULTS_FILE" | wc -l)
patch_conflict_likely=$(awk -F'|' '$3 == "PATCH_CONFLICT_LIKELY"' "$RESULTS_FILE" | wc -l)
untestable=$(awk -F'|' '$3 == "UNTESTABLE"' "$RESULTS_FILE" | wc -l)

total=$(wc -l < "$RESULTS_FILE")
testable=$((correct + fp_fixed + fp_likely))

echo "=== Summary ==="
echo "Total CVEs validated:    $total"
echo "Testable (patch works):  $testable"
if [[ "$testable" -gt 0 ]]; then
    echo "Correct:                 $correct ($(( correct * 100 / testable ))%)"
fi
echo ""
echo "FALSE POSITIVES:"
echo "  FIXED FP:              $fp_fixed"
echo "  LIKELY_FIXED FP:       $fp_likely"

if [[ "$fp_fixed" -gt 0 ]]; then
    echo ""
    echo "=== FIXED False Positives ==="
    awk -F'|' '$3 == "FP_FIXED"' "$RESULTS_FILE" | sort
fi

if [[ "$fp_likely" -gt 0 ]]; then
    likely_total=$(grep -c ',LIKELY_FIXED,' "$REPORT" 2>/dev/null || echo 0)
    echo ""
    echo "=== LIKELY_FIXED False Positives ==="
    awk -F'|' '$3 == "FP_LIKELY"' "$RESULTS_FILE" | sort
    echo ""
    echo "LIKELY_FIXED FP rate:    $fp_likely / $likely_total ($(( likely_total > 0 ? fp_likely * 100 / likely_total : 0 ))%)"
fi

echo ""
echo "PATCH CONFLICTS (untestable - context mismatch between kernel versions):"
echo "  UNFIXED conflicts:     $patch_conflict"
echo "  INCONCLUSIVE conflicts:$patch_conflict_inconc"
echo "  FIXED conflicts:       $patch_conflict_fixed  (verdict unconfirmed)"
echo "  LIKELY_FIXED conflicts:$patch_conflict_likely  (verdict unconfirmed)"
echo ""
echo "Untestable (no hash):    $untestable"
echo ""
echo "Results saved to: $RESULTS_FILE"
