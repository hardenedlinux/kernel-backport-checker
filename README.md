# Kernel Backport Checker

A command-line tool that identifies which Linux kernel CVEs have been fixed via backport commits in a git repository, filtered by kernel configuration.

## Background

Linux kernel is a crucial component of modern infrastructure, from servers to embedded devices. However, vulnerability handling involves a complex multi-stage process:

```
Upstream fix → Stable branch backports → Distribution backports → End users
```

### The Problem

1. **Long backport chain**: When a kernel vulnerability is fixed upstream, the fix must be backported through multiple layers:
   - Linux stable branches (e.g., 5.4.y, 6.1.y)
   - GNU/Linux Distribution maintainers (Debian, SuSE, Red Hat, Canonical)
   - High quality backport: PaX/GRsecurity

2. **Embedded industry gap**: Automotive, industrial control systems, and IoT rely heavily on Linux/Android kernels via build systems like **Yocto Project**. These vendors often:
   - Can't easily track which CVEs are actually fixed in their kernel version
   - Use long-term support kernels that may miss critical backports
   - Lack dedicated security teams
   - Don't have processes for security audits

3. **Visibility gap**: It's difficult to determine which CVE fixes from upstream have been backported to a specific kernel version and configuration, leaving embedded vendors unaware of security gaps in their deployments.

### Solution

Kernel Backport Checker automates the detection of:
- Which CVEs affect a specific kernel version
- Which are filtered out by the kernel configuration (disabled features)
- Which have been fixed via backport commits
- Which remain unfixed

## How It Works

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Kernel Source │    │   NVD Feeds     │    │  CISA KEV Data  │
│  (version +    │    │  (CVE database) │    │ (exploited CVEs)│
│   Makefiles)   │    │                 │    │                 │
└────────┬────────┘    └────────┬────────┘    └────────┬────────┘
         │                     │                      │
         ▼                     ▼                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Kernel Backport Checker                      │
├─────────────────────────────────────────────────────────────────┤
│  1. Detect kernel version from Makefile                         │
│  2. Scan NVD for kernel-relevant CVEs (CPE matching)             │
│  3. Filter by .config (disabled features = not applicable)      │
│  4. Extract upstream fix commit hashes from NVD references       │
│     (git.kernel.org, github.com/torvalds, kernel.dance, cgit)   │
│  5. Build CONFIG mapping from kernel Makefiles/Kbuild            │
│  6. Check git log for CVE mentions (upstream + stable repos)     │
│  7. Verify fix: fingerprint + moved-line + context matching      │
└─────────────────────────────────────────────────────────────────┘
         ▲                                    ▲
         │                                    │
┌────────┴────────┐              ┌────────────┴──────────┐
│  Upstream Repo  │              │  Stable/Vendor Repo   │
│  (-d linux.git) │              │  (-b linux-stable)    │
│  Fix hash lookup│              │  Backport commit      │
│  + diff extract │              │  detection + diffs    │
└─────────────────┘              └───────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  backport-report.csv   │
                    │  - FIXED               │
                    │  - LIKELY_FIXED        │
                    │  - UNFIXED             │
                    │  - INCONCLUSIVE        │
                    │  - NOT_APPLICABLE      │
                    └────────────────────────┘
```

### Key Design Decisions

1. **CPE-based CVE matching**: Uses NVD's CPE (Common Platform Enumeration) to precisely match CVEs affecting Linux kernel, avoiding false positives from software running *on* Linux.

2. **CONFIG-based filtering**: Maps source files to kernel configuration options. If all files affected by a CVE are under disabled CONFIGs, the CVE is marked as `NOT_APPLICABLE`.

3. **Dual-signal fix verification**: Extracts both "added lines" (fix code) and "removed lines" (vulnerable code) from upstream fix commits. Checks whether fix code is present in the target source AND whether vulnerable code has been removed, producing nuanced verdicts rather than binary yes/no.

4. **Moved-line detection**: Lines that appear in both the added and removed sets of a diff are identified as moved code (relocated within the file, not truly added/removed). These are excluded from removed-line counting to prevent inflated removed ratios that would incorrectly block FIXED classification.

5. **Contiguous block matching**: When removed (vulnerable) lines match highly in the target source (>=70%), checks whether they appear as a contiguous block (genuine vulnerable code still present, confirming UNFIXED) or scattered across unrelated locations (common pattern reuse).

6. **Parallel processing**: Splits CVE processing across multiple worker processes. Each worker receives a chunk of CVEs plus serialized lookup tables, avoiding shared-state bottlenecks. Uses `xargs -P` for NVD feed scanning, fix ref extraction, and diff extraction.

## Implementation Details

### Core Components

| Component | Description |
|-----------|-------------|
| `detect_kernel_version()` | Parses `Makefile` for VERSION, PATCHLEVEL, SUBLEVEL |
| `scan_nvd_for_kernel_cves()` | 3-phase scan: find kernel CPEs → extract version ranges → filter by version (with caching) |
| `extract_nvd_fix_refs()` | Parses NVD JSON references to find git commit URLs (5 URL formats supported) |
| `build_config_mapping()` | Scans Makefiles/Kbuild to map source files → CONFIG options (file-level + directory-level) |
| `load_kernel_config()` | Loads enabled CONFIG options (`=y` or `=m`) from kernel `.config` |
| `extract_backported_cves()` | Searches git log (upstream + stable) for CVE-ID mentions in commit messages |
| `build_git_hash_index()` | Indexes all commit hashes from upstream + stable repos for fast lookup |
| `process_results()` | Exports lookup tables, splits CVEs into chunks, spawns parallel workers |
| Worker script | Per-chunk processing: CONFIG mapping, fix verification (fingerprint + context), verdict aggregation |
| `check_fix_applied()` | Dual-signal analysis: added/removed line matching with moved-line detection + contiguous block check + context adjacency |
| `generate_csv()` | Produces final CSV report with summary statistics and severity breakdown |

### Algorithm: Fix Verification

```
For each CVE:
  1. Get upstream fix commit hashes from NVD references
  2. Get backport commit hashes from git log (CVE mentions in upstream + stable repos)
  3. Map affected source files to CONFIG options
  4. If ALL CONFIGs disabled → NOT_APPLICABLE
  5. For each fix hash:
     a. Extract changed files from commit
     b. Extract "added lines" (fix code) and "removed lines" (vulnerable code)
        - Filter out trivial/common patterns (min length 8 chars)
        - Filtered patterns: comments, #include, break/continue, return,
          goto, simple variable declarations, common error-check idioms,
          mutex/spin/rcu lock calls, braces, NULL, else, default
        - Up to 10 distinctive lines per file per direction (added/removed)
     c. Detect moved lines (same line in both added and removed sets)
        - Moved lines are excluded from removed-line counting
     d. Check both against target kernel source (per-file matching)
        - Short lines (<40 chars added, <30 chars removed): whole-line matching
        - Longer lines: substring matching (distinctive enough)
     e. Accumulate match evidence across ALL changed files
     f. Compute added_ratio and removed_ratio (0-100%)
     g. Decision matrix (Phase 1 - fingerprint-based):
        - Removed ≥70% + contiguous + added ≥80% → LIKELY_FIXED
        - Removed ≥70% + contiguous + added <80% → UNFIXED
        - Added ≥50% + removed ≥2 + added ≥70% + removed <15% → FIXED
        - Added ≥50% + removed <50% → LIKELY_FIXED
        - Added ≥50% + no removed lines → INCONCLUSIVE (pure-addition)
        - Added ≥40% + removed ≥50% → UNFIXED
        - Added ≥40% + removed <50% → LIKELY_FIXED
        - Added =0 + removed >0 + none matched + removed ≥2 → FIXED (removal-only)
        - Removed ≥50% → UNFIXED
        - Added ≤2 lines matched → INCONCLUSIVE (too weak)
        - Added ≥3 lines, 0% match → UNFIXED (fix absent)
        - Otherwise → INCONCLUSIVE
     h. Context-aware confirmation (Phase 2):
        - Only runs for LIKELY_FIXED and INCONCLUSIVE verdicts
        - Extract unchanged context lines adjacent to added/removed lines
        - Check adjacency in target source (±3 lines)
        - Context majority fixed: INCONCLUSIVE → LIKELY_FIXED
          (LIKELY_FIXED stays LIKELY_FIXED - context alone not reliable
          enough for FIXED upgrade)
        - Context majority unfixed: LIKELY_FIXED → UNFIXED (if strong
          signal + weak added match), INCONCLUSIVE → UNFIXED
  6. Aggregate verdicts across all hashes:
     - FIXED requires: ≥1 FIXED vote, zero UNFIXED votes, FIXED > LIKELY_FIXED
     - Mixed FIXED + UNFIXED → LIKELY_FIXED (conservative)
     - Any LIKELY_FIXED → LIKELY_FIXED
     - Any UNFIXED → UNFIXED
     - All INCONCLUSIVE → INCONCLUSIVE
     - No fix info from any source → INCONCLUSIVE
```

### Verdict Definitions

Each CVE in the output report is assigned one of the following verdicts:

| Verdict | Meaning | Trigger Condition |
|---------|---------|-------------------|
| `FIXED` | The fix has been backported. | Fix code (added lines) strongly present (>=70% match) AND vulnerable code mostly gone (<15% match with >=2 removed lines), OR removal-only fix where all vulnerable code (>=2 removed lines) is gone from source. Requires zero UNFIXED votes across all commit hashes. |
| `LIKELY_FIXED` | The fix is probably backported, but evidence is partial. Needs manual review. | Fix code partially present (40-69% match), OR fix and vulnerable code both present (>=80% added + >=70% removed), OR context-aware matching gives mixed signals, OR mixed FIXED+UNFIXED votes across commit hashes. These CVEs should be reviewed manually to confirm whether the fix was applied in a different form. |
| `UNFIXED` | The vulnerability is still present. | Vulnerable code (removed lines) is still present in the target source (>=70% match confirmed by contiguous block check, or >=50% match), OR fix code is completely absent (0% match on >=3 distinctive lines), OR context-aware matching confirms fix was not inserted at the expected location. |
| `INCONCLUSIVE` | Cannot determine fix status with confidence. | Signals are ambiguous: too few distinctive lines to judge (<=2 matched), pure-addition fix with no removed-line evidence, source file does not exist in target kernel, no extractable commit hash, no fix info from any source, or both fix and context matching produce no usable signal. |
| `NOT_APPLICABLE` | The CVE does not affect this kernel build. | All source files modified by the fix commit are under CONFIG options that are disabled (`=n` or absent) in the kernel `.config`. The vulnerable subsystem is not compiled into the kernel. |

#### Interpreting the verdicts

**For security auditing**, focus on `UNFIXED` CVEs first — these have the highest confidence that the vulnerability is present. Then review `LIKELY_FIXED` CVEs to confirm whether the fix was genuinely applied. `INCONCLUSIVE` CVEs should be reviewed when resources allow.

**`FIXED` vs `LIKELY_FIXED`**: A `FIXED` verdict means the tool found strong evidence: >=70% of distinctive fix lines present with vulnerable code mostly gone (<15% remaining), or all vulnerable code removed in a removal-only fix. Additionally, no commit hash may produce an UNFIXED vote. `LIKELY_FIXED` means partial evidence — the fix may have been applied in a slightly different form (e.g., a vendor-specific adaptation), or only part of a multi-commit fix series has been backported, or different commit hashes produce conflicting signals. These are the primary candidates for manual review.

**`NOT_APPLICABLE` confidence**: This verdict relies on the CONFIG mapping derived from kernel Makefiles. The mapping covers `obj-$(CONFIG_XXX)` patterns and directory-level config guards, but composite objects (e.g., `xxx-objs`) and conditional compilation within source files are not fully captured. Some CVEs may show `UNKNOWN` config status when the mapping cannot determine the relevant CONFIG option.

**`INCONCLUSIVE` causes**: A CVE receives `INCONCLUSIVE` when the tool exhausts all detection methods — fingerprint matching, removed-line analysis, and context-aware matching — without producing a definitive signal. The specific conditions that lead to `INCONCLUSIVE` are:

1. **Zero distinctive lines after filtering** — The fix commit only modifies comments, whitespace, or boilerplate code shorter than 8 characters. After filtering out common patterns (`return`, `break`, `{`, `}`, `#include`, etc.), no fingerprint lines remain to match against.

2. **Source file does not exist in the target kernel** — The fix modifies a file that was added after the target kernel version (e.g., a new driver or subsystem). The tool cannot verify whether the vulnerability exists if the relevant code was never present.

3. **No extractable commit hash** — The NVD entry for the CVE does not reference any git commit URLs, or the referenced commits do not exist in either the upstream or stable repositories provided.

4. **Partial match in the ambiguous zone** — Some fix fingerprint lines match in the target source but not enough for `LIKELY_FIXED` (requires >=40% added ratio). This includes cases where only 1-2 distinctive lines match (regardless of percentage), which could be either a partial backport or a coincidental pattern match. The tool cannot distinguish between these cases.

5. **Conflicting signals across multiple files** — The fix touches multiple files, and fingerprint evidence is contradictory: some files suggest the fix is applied while others suggest it is not. When context-aware matching also produces mixed results (some context+added pairs found adjacent, others not), the tool cannot determine an overall verdict.

6. **Pure-addition fix with no removed lines** — The fix only adds new code without removing any existing code. Without removed-line evidence to confirm the vulnerability was present, added-line matches alone are insufficient (they may coincidentally match existing code).

7. **Context lines not found in target** — The context-aware fallback extracts unchanged lines both before and after each added/removed line in the diff, then checks whether both appear adjacent in the target source (within ±3 lines). If the surrounding code has been significantly refactored between the upstream version and the target kernel, the context lines no longer exist, and adjacency checks fail.

## Usage

### Prerequisites

- Bash 4+
- `jq` - JSON processing
- `git` - Repository access
- Standard POSIX utilities: `awk`, `find`, `xargs`, `sort`, `split`, `grep`, `sed`
- NVD JSON data feeds (fkie-cad/nvd-json-data-feeds format)
- CISA KEV data (known_exploited_vulnerabilities.json)

### Command Line

```bash
./kernel-backport-checker.sh \
    -s <kernel-source-dir> \
    -d <upstream-linux-git-dir> \
    -e <kev-data> \
    -f <nvd-json-data-feeds> \
    -k <kernel-config> \
    -o <output-dir> \
    [-b <stable-vendor-git-dir>] \
    [-j <parallel-jobs>]
```

### Options

| Option | Description | Required |
|--------|-------------|----------|
| `-s` | Kernel source directory (contains Makefile) | Yes |
| `-d` | Upstream Linux kernel git directory (e.g., torvalds/linux.git clone) | Yes |
| `-e` | CISA KEV data directory or JSON file | Yes |
| `-f` | NVD JSON data feeds directory | Yes |
| `-k` | Kernel .config file | Yes |
| `-o` | Output directory for results | Yes |
| `-b` | Stable/vendor git repository with backport commits | No |
| `-j` | Parallel jobs (default: nproc/2) | No |
| `-h` | Show help | No |

### Example

```bash
# With upstream repo only
./kernel-backport-checker.sh \
    -s linux-6.1.1 \
    -d linux \
    -e kev-data \
    -f nvd-json-data-feeds \
    -k 6.1-config \
    -o output

# With separate stable/vendor repo for backport detection
./kernel-backport-checker.sh \
    -s linux-6.1.1 \
    -d linux \
    -b linux-stable \
    -e kev-data \
    -f nvd-json-data-feeds \
    -k 6.1-config \
    -o output \
    -j 8
```

### Output Format

The tool produces `<output-dir>/backport-report.csv` with comment headers containing a summary, followed by CSV data:

```
# Kernel Backport Checker Report v3.2.0
# Generated: 2025-01-15 12:00:00 UTC
# Kernel Version: 6.1.1
# ...
# ===== Summary =====
# Total CVEs affecting kernel 6.1.1: 1234
# Not applicable (config disabled): 200
# Applicable CVEs: 1034
#   Fixed via backport: 400
#   Likely fixed (needs review): 150
#   Unfixed (remaining): 300
#   Inconclusive: 184
# ...
CVE-ID,Severity,CVSS-Score,In-CISA-KEV,Fix-Status,Affected-Config,Config-Status,Description
```

| Column | Description |
|--------|-------------|
| CVE-ID | CVE identifier (e.g., CVE-2024-12345) |
| Severity | CRITICAL, HIGH, MEDIUM, LOW, or N/A |
| CVSS-Score | Numeric CVSS score (v3.1/v3.0/v2) or N/A |
| In-CISA-KEV | Yes/No — whether the CVE is in the CISA Known Exploited Vulnerabilities catalog |
| Fix-Status | FIXED, LIKELY_FIXED, UNFIXED, INCONCLUSIVE, or NOT_APPLICABLE |
| Affected-Config | Semicolon-separated CONFIG options (e.g., CONFIG_EXT4_FS;CONFIG_BLOCK) |
| Config-Status | ENABLED, DISABLED, or UNKNOWN |
| Description | Truncated CVE description (first 200 chars) |

Results are sorted with UNFIXED CVEs first, then by severity.

### Caching

The tool caches intermediate results in the output directory to speed up reruns:
- `.nvd_kernel_cves_<version>.tsv` — NVD CVE scan results
- `.nvd_fix_refs_<version>.tsv` — Extracted fix commit references

Delete these files to force a rescan.

## Use Cases

1. **Security audit**: Identify unfixed CVEs in your kernel version
2. **Compliance**: Generate reports for security compliance requirements, e.g: EU CRA (Cyber Resilience Act), PCI-DSS, etc.
3. **Supply chain**: Verify vendor kernel builds include critical backports
4. **CI/CD integration**: Automated kernel security checking in build pipelines
5. **Embedded vendors**: Track backport status for Yocto/OpenEmbedded builds

## Data Sources

- [**NVD (National Vulnerability Database)**](https://github.com/fkie-cad/nvd-json-data-feeds): CVE database with CPE matching
- [**CISA KEV (Known Exploited Vulnerabilities)**](https://github.com/cisagov/kev-data): Catalog of actively exploited CVEs
- [**Linux vanilla**](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/): upstream/mainline
- [**Stable branch**](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/): Linux stable branch

## Validation Tools

Four scripts are provided to validate the accuracy of the checker's verdicts. Each script requires all paths to be passed explicitly via command-line arguments (no hardcoded defaults).

### validate-single-cve.sh

Validates a single CVE verdict by attempting to apply the upstream fix patch to the kernel source. If the patch applies cleanly, the fix is NOT present (ground truth = UNFIXED).

```bash
./validate-single-cve.sh \
    -c CVE-2024-12345 \
    -s /path/to/linux-6.8.1 \
    -d /path/to/linux \
    -b /path/to/stable \
    -o /path/to/output
```

Output format (pipe-delimited):
```
CVE-2024-12345|UNFIXED|CORRECT|
CVE-2024-67890|FIXED|FP_FIXED|abc123def456
CVE-2024-11111|LIKELY_FIXED|FP_LIKELY|abc123def456
```

| Result | Meaning |
|--------|---------|
| `CORRECT` | Verdict matches ground truth |
| `FP_FIXED` | False positive: checker says FIXED but fix not present |
| `FP_LIKELY` | Soft false positive: checker says LIKELY_FIXED but fix not present |
| `PATCH_CONFLICT` | Patch doesn't apply (fix may be present or context mismatch) |
| `UNTESTABLE` | No fix commit hash available |

### validate-all.sh

Runs `validate-single-cve.sh` in parallel across all applicable CVEs and produces an aggregate summary.

```bash
# Validate all applicable CVEs
./validate-all.sh \
    -s /path/to/linux-6.8.1 \
    -d /path/to/linux \
    -b /path/to/stable \
    -o /path/to/output \
    -j 15

# Validate a random sample of 500 CVEs
./validate-all.sh \
    -s /path/to/linux-6.8.1 \
    -d /path/to/linux \
    -b /path/to/stable \
    -o /path/to/output \
    -n 500 -j 15
```

| Option | Description |
|--------|-------------|
| `-s` | Path to kernel source tree (required) |
| `-d` | Path to upstream Linux git repository (required) |
| `-b` | Path to stable/vendor git repository (required) |
| `-o` | Path to checker output directory (required) |
| `-r` | Path to backport-report.csv (default: `OUTPUT/backport-report.csv`) |
| `-j` | Number of parallel workers (default: 15) |
| `-n` | Validate only N random CVEs (default: all) |

Results are saved to `OUTPUT/validation-results.txt`.

### validate-with-patches.sh

End-to-end detection test: selects N random UNFIXED CVEs whose patches apply cleanly, applies the patches to the kernel source, re-runs the checker, verifies each CVE is detected as FIXED or LIKELY_FIXED, then reverts all patches.

```bash
./validate-with-patches.sh \
    -s /path/to/linux-6.8.1 \
    -d /path/to/linux \
    -b /path/to/stable \
    -o /path/to/output \
    -k /path/to/linux-6.8.1/.config \
    -e /path/to/kev-data \
    -f /path/to/nvd-json-data-feeds \
    -n 200 -j 5
```

| Option | Description |
|--------|-------------|
| `-s` | Path to kernel source tree (required) |
| `-d` | Path to upstream Linux git repository (required) |
| `-b` | Path to stable/vendor git repository (required) |
| `-o` | Path to checker output directory (required) |
| `-k` | Path to kernel .config file (required) |
| `-e` | Path to CISA KEV data directory (required) |
| `-f` | Path to NVD JSON data feeds directory (required) |
| `-n` | Number of CVEs to test (default: 200) |
| `-j` | Parallel jobs for checker (default: 5) |

### find-patchable-cves.sh

Finds UNFIXED CVEs whose upstream fix patches can be cleanly applied to the kernel source. Outputs a TSV list suitable for use with other validation scripts.

```bash
./find-patchable-cves.sh \
    -s /path/to/linux-6.8.1 \
    -d /path/to/linux \
    -b /path/to/stable \
    -o /path/to/output \
    -n 200
```

Output (stdout, tab-separated):
```
CVE-2024-12345	abc123def456...	3
CVE-2024-67890	def789abc012...	1
```

| Column | Description |
|--------|-------------|
| 1 | CVE identifier |
| 2 | Full commit hash of the applicable fix |
| 3 | Number of files changed by the fix |

## Bug report

Feel free to file a PR!
