#!/bin/bash
# find-patchable-cves.sh - Find UNFIXED CVEs whose patches apply cleanly
#
# Searches for CVEs marked UNFIXED in the report that have upstream fix
# commits whose patches can be cleanly applied to the kernel source.
# Useful for building test sets for patch-apply validation.
#
# Usage:
#   ./find-patchable-cves.sh -s <kernel-src> -d <upstream-repo> -b <stable-repo> -o <output-dir> [options]
#
# Output: TSV to stdout: CVE_ID<tab>HASH<tab>NUM_FILES

set -uo pipefail

usage() {
    cat <<EOF
Usage: $0 -s <kernel-src> -d <upstream-repo> -b <stable-repo> -o <output-dir> [options]

Required:
  -s SOURCE    Path to kernel source tree
  -d UPSTREAM  Path to upstream Linux kernel git repository
  -b STABLE    Path to stable/vendor git repository
  -o OUTPUT    Path to checker output directory

Optional:
  -n COUNT     Max number of patchable CVEs to find (default: 200)
  -h           Show this help

Output (stdout):
  Tab-separated: CVE_ID<tab>COMMIT_HASH<tab>NUM_FILES_CHANGED
EOF
    exit 1
}

KERNEL_SRC="" UPSTREAM="" STABLE="" OUTPUT_DIR="" COUNT=200

while getopts "s:d:b:o:n:h" opt; do
    case "$opt" in
        s) KERNEL_SRC="$OPTARG" ;;
        d) UPSTREAM="$OPTARG" ;;
        b) STABLE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
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

[[ -d "$KERNEL_SRC" ]] || { echo "Error: Kernel source not found: $KERNEL_SRC" >&2; exit 1; }
[[ -d "$UPSTREAM" ]]   || { echo "Error: Upstream repo not found: $UPSTREAM" >&2; exit 1; }
[[ -d "$STABLE" ]]     || { echo "Error: Stable repo not found: $STABLE" >&2; exit 1; }

REPORT="$OUTPUT_DIR/backport-report.csv"
FIX_REFS=$(ls "$OUTPUT_DIR"/.nvd_fix_refs_*.tsv 2>/dev/null | head -1)

[[ -f "$REPORT" ]]   || { echo "Error: Report not found: $REPORT" >&2; exit 1; }
[[ -f "$FIX_REFS" ]] || { echo "Error: Fix refs not found in $OUTPUT_DIR" >&2; exit 1; }

# Get UNFIXED CVEs with 1-5 fix hashes
_tmp_unfixed=$(mktemp)
_tmp_few=$(mktemp)
_tmp_cand=$(mktemp)

grep ',UNFIXED,' "$REPORT" | awk -F',' '{print $1}' | sort > "$_tmp_unfixed"
awk -F'\t' '{print $1}' "$FIX_REFS" | sort | uniq -c | \
    awk '$1 >= 1 && $1 <= 5 {print $2}' | sort > "$_tmp_few"
comm -12 "$_tmp_unfixed" "$_tmp_few" | shuf > "$_tmp_cand"

found=0
while read cve && [[ "$found" -lt "$COUNT" ]]; do
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
            echo -e "$cve\t$hash\t$nfiles"
            found=$((found + 1))
            rm -f "$tmpfile"
            break
        fi
        rm -f "$tmpfile"
    done
done < "$_tmp_cand"

rm -f "$_tmp_unfixed" "$_tmp_few" "$_tmp_cand"
echo "Found $found patchable CVEs" >&2
