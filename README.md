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
│  5. Build CONFIG mapping from kernel Makefiles                   │
│  6. Check git log for CVE mentions (backport detection)          │
│  7. Verify fix applied: fingerprint matching from diffs          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                   ┌────────────────────────┐
                   │  backport-report.csv   │
                   │  - FIXED               │
                   │  - UNFIXED             │
                   │  - NOT_APPLICABLE      │
                   └────────────────────────┘
```

### Key Design Decisions

1. **CPE-based CVE matching**: Uses NVD's CPE (Common Platform Enumeration) to precisely match CVEs affecting Linux kernel, avoiding false positives from software running *on* Linux.

2. **CONFIG-based filtering**: Maps source files to kernel configuration options. If all files affected by a CVE are under disabled CONFIGs, the CVE is marked as `NOT_APPLICABLE`.

3. **Fingerprint-based fix verification**: Instead of just checking if a commit exists, the tool extracts distinctive "added lines" from upstream fix commits and verifies they exist in the target source files. This confirms the fix was actually backported, not just referenced.

4. **Parallel processing**: Uses multi-core processing for scanning NVD feeds and processing CVEs for performance.

## Implementation Details

### Core Components

| Component | Description |
|-----------|-------------|
| `detect_kernel_version()` | Parses `Makefile` for VERSION, PATCHLEVEL, SUBLEVEL |
| `scan_nvd_for_kernel_cves()` | 3-phase scan: find kernel CPEs → extract version ranges → filter by version |
| `extract_nvd_fix_refs()` | Parses NVD JSON references to find git commit URLs |
| `build_config_mapping()` | Scans Makefiles/Kbuild to map source files → CONFIG options |
| `extract_backported_cves()` | Searches git log for CVE-ID mentions |
| `check_fix_applied()` | Fingerprint matching: verifies added lines exist in target |
| `process_results()` | Main logic: combines all data, determines FIXED/UNFIXED/NOT_APPLICABLE |
| `generate_csv()` | Produces final report with summary statistics |

### Algorithm: Fix Verification

```
For each CVE:
  1. Get upstream fix commit hashes from NVD references
  2. Get backport commit hashes from git log (CVE mentions)
  3. Map affected source files to CONFIG options
  4. If ALL CONFIGs disabled → NOT_APPLICABLE
  5. For each fix hash:
     a. Extract changed files from commit
     b. Extract "fingerprints" (added lines, length > 15, skip common patterns)
     c. Check if fingerprints exist in target kernel source
     d. If majority match → FIXED
  6. If no fix verified → UNFIXED
```

## Usage

### Prerequisites

- Bash 4+
- `jq` - JSON processing
- `git` - Repository access
- NVD JSON data feeds (fkie-cad/nvd-json-data-feeds format)
- CISA KEV data (known_exploited_vulnerabilities.json)

### Command Line

```bash
./kernel-backport-checker.sh \
    -s <kernel-source-dir> \
    -d <linux-git-dir> \
    -e <kev-data> \
    -f <nvd-json-data-feeds> \
    -k <kernel-config> \
    -o <output-dir> \
    [-j <parallel-jobs>]
```

### Options

| Option | Description | Required |
|--------|-------------|----------|
| `-s` | Kernel source directory (contains Makefile) | Yes |
| `-d` | Linux kernel git directory with backport commits | Yes |
| `-e` | CISA KEV data directory or JSON file | Yes |
| `-f` | NVD JSON data feeds directory | Yes |
| `-k` | Kernel .config file | Yes |
| `-o` | Output directory for results | Yes |
| `-j` | Parallel jobs (default: nproc/2) | No |
| `-h` | Show help | No |

### Example

```bash
./kernel-backport-checker.sh \
    -s linux-6.1.1 \
    -d linux \
    -e kev-data \
    -f nvd-json-data-feeds \
    -k 6.1-config \
    -o output \
    -j 8
```

## Use Cases

1. **Security audit**: Identify unfixed CVEs in your kernel version
2. **Compliance**: Generate reports for security compliance requirements, e.g: EU CRA (Cyber Resilience Act), PCI-DSS, etc.
3. **Supply chain**: Verify vendor kernel builds include critical backports
4. **CI/CD integration**: Automated kernel security checking in build pipelines
5. **Embedded vendors**: Track backport status for Yocto/OpenEmbedded builds

## Data Sources

- [**NVD (National Vulnerability Database)**](https://github.com/fkie-cad/nvd-json-data-feeds): CVE database with CPE matching
- [**CISA KEV (Known Exploited Vulnerabilities)**](https://github.com/cisagov/kev-data): Catalog of actively exploited CVEs

## Limitations

1. Requires git repository with backport commits
2. Relies on NVD reference data (some CVEs may lack fix commit URLs)
3. CONFIG mapping is approximate based on Makefile analysis
4. Fingerprint matching may miss semantically equivalent fixes

## Bug report

Feel free to file a PR!
