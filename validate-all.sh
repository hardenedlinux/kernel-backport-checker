#!/bin/bash
# validate-all.sh - Validate CVE verdicts in the backport report
#
# Runs validate-single-cve.sh in parallel for every applicable CVE in the
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
  -j JOBS      Number of parallel workers (default: 15)
  -n COUNT     Validate only COUNT random CVEs (default: all)
  -h           Show this help
EOF
    exit 1
}

KERNEL_SRC="" UPSTREAM="" STABLE="" OUTPUT_DIR="" REPORT="" JOBS=15 COUNT=0

while getopts "s:d:b:o:r:j:n:h" opt; do
    case "$opt" in
        s) KERNEL_SRC="$OPTARG" ;;
        d) UPSTREAM="$OPTARG" ;;
        b) STABLE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        r) REPORT="$OPTARG" ;;
        j) JOBS="$OPTARG" ;;
        n) COUNT="$OPTARG" ;;
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
echo ""

# Get applicable CVEs (excluding NOT_APPLICABLE and header lines)
CVE_LIST=$(mktemp)
if [[ "$COUNT" -gt 0 ]]; then
    grep -v ',NOT_APPLICABLE,' "$REPORT" | grep "^CVE-" | awk -F',' '{print $1}' | shuf | head -"$COUNT" | sort > "$CVE_LIST"
    echo "Validating $COUNT random CVEs..."
else
    grep -v ',NOT_APPLICABLE,' "$REPORT" | grep "^CVE-" | awk -F',' '{print $1}' | sort > "$CVE_LIST"
    echo "Validating all $(wc -l < "$CVE_LIST") applicable CVEs..."
fi
echo ""

# Run validation in parallel — pass all required args to each worker
cat "$CVE_LIST" | xargs -P"$JOBS" -I{} \
    bash "$SCRIPT_DIR/validate-single-cve.sh" \
        -c "{}" -s "$KERNEL_SRC" -d "$UPSTREAM" -b "$STABLE" -o "$OUTPUT_DIR" -r "$REPORT" \
    > "$RESULTS_FILE" 2>/dev/null

rm -f "$CVE_LIST"

# Summarize results
echo "=== Results ==="
echo ""
awk -F'|' '{print $3}' "$RESULTS_FILE" | sort | uniq -c | sort -rn
echo ""

correct=$(grep -c '|CORRECT|' "$RESULTS_FILE" 2>/dev/null || true)
fp_fixed=$(grep -c '|FP_FIXED|' "$RESULTS_FILE" 2>/dev/null || true)
fp_likely=$(grep -c '|FP_LIKELY|' "$RESULTS_FILE" 2>/dev/null || true)
patch_conflict=$(grep -c '|PATCH_CONFLICT|' "$RESULTS_FILE" 2>/dev/null || true)
patch_conflict_inconc=$(grep -c '|PATCH_CONFLICT_INCONC|' "$RESULTS_FILE" 2>/dev/null || true)
untestable=$(grep -c '|UNTESTABLE|' "$RESULTS_FILE" 2>/dev/null || true)
correct=${correct:-0}; fp_fixed=${fp_fixed:-0}; fp_likely=${fp_likely:-0}
patch_conflict=${patch_conflict:-0}; patch_conflict_inconc=${patch_conflict_inconc:-0}; untestable=${untestable:-0}
total=$(wc -l < "$RESULTS_FILE")
testable=$((correct + fp_fixed + fp_likely))

echo "=== Summary ==="
echo "Total CVEs:              $total"
echo "Testable:                $testable"
echo "Correct:                 $correct ($(( testable > 0 ? correct * 100 / testable : 0 ))%)"
echo ""
echo "FALSE POSITIVES:"
echo "  FIXED FP:              $fp_fixed"
echo "  LIKELY_FIXED FP:       $fp_likely"

if [[ "$fp_fixed" -gt 0 ]]; then
    echo ""
    echo "=== FIXED False Positives ==="
    grep '|FP_FIXED|' "$RESULTS_FILE" | sort
fi

if [[ "$fp_likely" -gt 0 ]]; then
    likely_total=$(grep -c ',LIKELY_FIXED,' "$REPORT" 2>/dev/null || true)
    likely_total=${likely_total:-0}
    echo ""
    echo "LIKELY_FIXED FP rate:    $fp_likely / $likely_total ($(( likely_total > 0 ? fp_likely * 100 / likely_total : 0 ))%)"
fi

echo ""
echo "PATCH CONFLICTS (not errors - context mismatch between kernel versions):"
echo "  UNFIXED conflicts:     $patch_conflict"
echo "  INCONCLUSIVE conflicts:$patch_conflict_inconc"
echo ""
echo "Untestable (no hash):    $untestable"
echo ""
echo "Results saved to: $RESULTS_FILE"
