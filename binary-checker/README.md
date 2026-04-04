## Binary Checker

The `binary-checker/` directory contains a companion tool that performs CVE backport detection on compiled kernel binaries without requiring source code or a git repository with backport commits. This is useful for analyzing firmware images, embedded devices, or any scenario where only the kernel binary is available.

### How It Works

Instead of analyzing source code diffs, the binary checker:
1. Detects binary format and extracts vmlinux if needed (supports ELF vmlinux, bzImage/zImage, uImage, gzip/bzip2/xz/lz4/zstd compressed kernels, and raw blobs)
2. Extracts metadata: kernel version, architecture, symbols, and embedded config (IKCONFIG)
3. Scans NVD JSON feeds for CVEs affecting the detected kernel version
4. Extracts upstream fix commit hashes from NVD references
5. Generates fix signatures from upstream git diffs (string patterns, symbol changes, function-level comparison)
6. Matches signatures against the kernel binary
7. Outputs a CSV report

### Usage

```bash
cd binary-checker

# Basic usage
./kernel-binary-backport-checker.sh \
    -b /path/to/vmlinux \
    -d /path/to/linux \
    -e /path/to/kev-data \
    -f /path/to/nvd-json-data-feeds \
    -o output

# With kernel .config for CONFIG-based filtering (recommended)
./kernel-binary-backport-checker.sh \
    -b /path/to/vmlinux \
    -d /path/to/linux \
    -e /path/to/kev-data \
    -f /path/to/nvd-json-data-feeds \
    -o output \
    -k /path/to/.config

# With kernel modules directory
./kernel-binary-backport-checker.sh \
    -b /path/to/vmlinux \
    -d /path/to/linux \
    -e /path/to/kev-data \
    -f /path/to/nvd-json-data-feeds \
    -o output \
    -m /lib/modules/6.8.1/

# Raw firmware blob with architecture override
./kernel-binary-backport-checker.sh \
    -b firmware-kernel.bin \
    -d /path/to/linux \
    -e /path/to/kev-data \
    -f /path/to/nvd-json-data-feeds \
    -o output \
    -a arm
```

### Options

| Option | Description | Required |
|--------|-------------|----------|
| `-b` | Kernel binary (vmlinux, bzImage, uImage, or raw blob) | Yes |
| `-d` | Upstream Linux kernel git directory | Yes |
| `-e` | CISA KEV data directory or JSON file | Yes |
| `-f` | NVD JSON data feeds directory | Yes |
| `-o` | Output directory for results | Yes |
| `-k` | Kernel .config file (enables CONFIG-based filtering; highly recommended) | No |
| `-m` | Directory containing kernel modules (.ko/.ko.xz/.ko.zst/.ko.gz files) | No |
| `-a` | Override architecture detection (x86, x86_64, arm, aarch64, mips) | No |
| `-j` | Number of parallel jobs (default: nproc/2) | No |
| `--no-r2` | Disable radare2 usage (string-matching only) | No |

### Dependencies

Required: `bash 4+`, `jq`, `git`, `python3`, `strings`, `file`, `hexdump`

Optional (enables deeper analysis):
- `radare2` (r2) + `r2pipe` (pip) - Function-level binary comparison
- `vmlinux-to-elf` (pip) - Reconstruct ELF from raw kernel blobs with kallsyms

Install optional Python dependencies:
```bash
pip install -r binary-checker/requirements.txt
```

### Output

Produces `<output-dir>/binary-backport-report.csv` with the same format as the source-based checker.

### Project Structure

```
binary-checker/
  kernel-binary-backport-checker.sh   # Main entry point
  bin/
    build-gold-image.sh               # Build reference gold image
    detect-format.sh                   # Binary format detection
    extract-metadata.sh               # Metadata extraction
  lib/
    binary_matcher.py                  # Binary signature matching
    config_resolver.py                 # CONFIG option resolution
    function_differ.py                 # Function-level diff comparison
    signature_db.py                    # Signature database management
    string_signatures.py              # String-based signature generation
  requirements.txt                     # Python dependencies
```
