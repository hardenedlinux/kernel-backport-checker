#!/usr/bin/env python3
"""
config_resolver.py

Resolve CONFIG_* dependencies for CVE fix commits and determine whether
affected code is compiled into the kernel binary.

Config sources (in priority order):
  1. User-provided .config file (-k flag)
  2. Embedded ikconfig extracted from the binary
  3. Inference from built-in module list + symbol table (partial)

CONFIG mapping is built by parsing kernel source Makefiles/Kbuild files
to map source files -> CONFIG_* options (same logic as the source-based
checker).

Usage:
    from lib.config_resolver import ConfigResolver
    resolver = ConfigResolver(kernel_src_dir="/path/to/linux")
    resolver.load_config("/path/to/.config")
    status = resolver.get_config_status_for_files(["drivers/net/foo.c"])
    # -> ("CONFIG_FOO", "ENABLED") or ("CONFIG_BAR", "DISABLED") or ("UNKNOWN", "UNKNOWN")
"""

import os
import re
import subprocess
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path


class ConfigResolver:
    """
    Resolves CONFIG dependencies for kernel source files and determines
    whether they are compiled into the kernel.
    """

    def __init__(self, kernel_src_dir: str, arch: str = ""):
        """
        Args:
            kernel_src_dir: Path to upstream linux kernel git repo
            arch: Target architecture (e.g., "x86_64", "arm64") for filtering
                  files from other arch/ directories
        """
        self.kernel_src_dir = kernel_src_dir
        self._enabled_configs: Set[str] = set()  # CONFIG_XXX that are enabled
        self._file_config_map: Dict[str, str] = {}  # file.c -> CONFIG_XXX
        self._dir_config_map: Dict[str, str] = {}  # dir/ -> CONFIG_XXX
        self._config_loaded = False
        self._mapping_built = False
        self._config_source = "none"  # "user", "ikconfig", "inferred", "none"

        # Arch-to-directory mapping for filtering
        ARCH_DIR_MAP = {
            "x86_64": "arch/x86",
            "x86": "arch/x86",
            "i386": "arch/x86",
            "arm64": "arch/arm64",
            "aarch64": "arch/arm64",
            "arm": "arch/arm",
            "mips": "arch/mips",
            "mips64": "arch/mips",
            "powerpc": "arch/powerpc",
            "ppc64": "arch/powerpc",
            "s390": "arch/s390",
            "riscv": "arch/riscv",
            "loongarch": "arch/loongarch",
        }
        self._target_arch_dir = ARCH_DIR_MAP.get(arch, "")

        # Architecture-specific driver directories.  Arch-specific drivers
        # live under drivers/<arch>/ in addition to arch/<arch>/.
        ARCH_DRIVER_DIR_MAP = {
            "x86_64": "drivers/x86",
            "x86": "drivers/x86",
            "i386": "drivers/x86",
            "s390": "drivers/s390",
        }
        self._target_arch_driver_dir = ARCH_DRIVER_DIR_MAP.get(arch, "")

        self._all_arch_dirs = {
            # Kernel arch directories
            "arch/arm",
            "arch/arm64",
            "arch/mips",
            "arch/powerpc",
            "arch/s390",
            "arch/riscv",
            "arch/loongarch",
            "arch/parisc",
            "arch/sparc",
            "arch/alpha",
            "arch/ia64",
            "arch/m68k",
            "arch/sh",
            "arch/xtensa",
            "arch/um",
            "arch/arc",
            "arch/hexagon",
            "arch/nios2",
            "arch/openrisc",
            "arch/microblaze",
            "arch/csky",
            "arch/x86",
            # Architecture-specific driver directories
            "drivers/s390",
            "drivers/parisc",
            "drivers/x86",
        }

    # =================================================================
    # Config loading
    # =================================================================

    def load_config(self, config_path: str) -> int:
        """
        Load a kernel .config file.

        Args:
            config_path: Path to .config file

        Returns:
            Number of enabled CONFIG options loaded
        """
        self._enabled_configs.clear()
        count = 0

        try:
            with open(config_path, "r") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r"^(CONFIG_[A-Za-z0-9_]+)=(y|m)$", line)
                    if m:
                        self._enabled_configs.add(m.group(1))
                        count += 1
        except IOError as e:
            raise ValueError(f"Cannot read config file: {e}")

        self._config_loaded = True
        self._config_source = "user"
        return count

    def load_ikconfig(self, ikconfig_path: str) -> int:
        """Load config from extracted ikconfig."""
        count = self.load_config(ikconfig_path)
        self._config_source = "ikconfig"
        return count

    def infer_config_from_modules(
        self, builtin_modules_path: str, symbols_path: Optional[str] = None
    ) -> int:
        """
        Infer enabled CONFIG options from built-in module list and symbols.

        Uses two strategies:
        1. Auto-map builtin module names to CONFIGs via the Makefile-based
           file->CONFIG mapping (requires build_config_mapping() first)
        2. Check for known subsystem symbols in the symbol table

        This provides a partial view -- we can determine some configs are
        enabled but cannot conclusively say others are disabled.

        Args:
            builtin_modules_path: Path to builtin_modules.txt
            symbols_path: Optional path to kallsyms.txt

        Returns:
            Number of inferred CONFIG options
        """
        self._enabled_configs.clear()
        count = 0

        # Extract module names from builtin_modules.txt
        module_names: Set[str] = set()
        try:
            with open(builtin_modules_path, "r") as f:
                for line in f:
                    m = re.match(r"_kmod_(\w+?)__", line.strip())
                    if m:
                        module_names.add(m.group(1))
        except IOError:
            pass

        # Strategy 1: Auto-map via Makefile data
        # For each module name, search the file_config_map for a matching .c file
        if self._mapping_built:
            for mod_name in module_names:
                # Search for mod_name.c in file_config_map
                for path, config in self._file_config_map.items():
                    fname = os.path.basename(path).replace(".c", "")
                    if fname == mod_name:
                        if config not in self._enabled_configs:
                            self._enabled_configs.add(config)
                            count += 1
                        break

            # Also check directory-level mappings
            # Module 'acpi' likely maps to 'drivers/acpi/' directory
            for mod_name in module_names:
                for dir_path, config in self._dir_config_map.items():
                    dirname = os.path.basename(dir_path)
                    if dirname == mod_name:
                        if config not in self._enabled_configs:
                            self._enabled_configs.add(config)
                            count += 1
                        break

        # Strategy 2: Always-built core subsystems
        # These are always present in any kernel build
        ALWAYS_ENABLED = {
            "CONFIG_BLOCK",
            "CONFIG_INET",
            "CONFIG_NET",
            "CONFIG_PROC_FS",
            "CONFIG_SYSFS",
            "CONFIG_PRINTK",
        }
        for cfg in ALWAYS_ENABLED:
            if cfg not in self._enabled_configs:
                self._enabled_configs.add(cfg)
                count += 1

        # Strategy 3: Infer from symbol presence
        if symbols_path:
            SYMBOL_CONFIG_MAP = {
                "btrfs_init_fs_info": "CONFIG_BTRFS_FS",
                "ext4_fill_super": "CONFIG_EXT4_FS",
                "xfs_fs_fill_super": "CONFIG_XFS_FS",
                "kvm_init": "CONFIG_KVM",
                "drm_dev_register": "CONFIG_DRM",
                "usb_register_driver": "CONFIG_USB",
                "cfg80211_register_netdevice": "CONFIG_CFG80211",
                "nf_conntrack_init_start": "CONFIG_NF_CONNTRACK",
                "nft_register_chain_type": "CONFIG_NF_TABLES",
                "br_add_bridge": "CONFIG_BRIDGE",
                "scsi_host_alloc": "CONFIG_SCSI",
                "nvme_init_ctrl": "CONFIG_BLK_DEV_NVME",
                "blk_mq_init_queue": "CONFIG_BLOCK",
                "tcp_init": "CONFIG_INET",
                "ipv6_add_addr": "CONFIG_IPV6",
            }
            try:
                symbols = set()
                with open(symbols_path, "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            symbols.add(parts[2])
                        elif len(parts) >= 1:
                            symbols.add(parts[0])

                for sym, cfg in SYMBOL_CONFIG_MAP.items():
                    if sym in symbols and cfg not in self._enabled_configs:
                        self._enabled_configs.add(cfg)
                        count += 1
            except IOError:
                pass

        self._config_loaded = True
        self._config_source = "inferred"
        return count

    def check_files_compiled_in(
        self, affected_files: List[str], symbols: Set[str]
    ) -> bool:
        """
        Check if any of the affected source files have functions compiled
        into the binary, by parsing function definitions from the source
        and checking against the symbol table.

        This handles static/inlined functions that nm misses by going back
        to the source to find all function names defined in the file.

        To reduce false positives from the large merged symbol table
        (1M+ symbols from vmlinux + modules), we:
        1. Filter out very common function names (init, probe, remove, etc.)
        2. Require at least 3 matches or 30% match rate to confirm presence

        Args:
            affected_files: List of source file paths
            symbols: Set of function names from the binary symbol table

        Returns:
            True if sufficient functions from the affected files exist in
            the binary to conclude the code is compiled in
        """
        func_def_re = re.compile(
            r"^[a-zA-Z_][\w\s*]*?\b(\w+)\s*\([^)]*\)\s*\{",
            re.MULTILINE,
        )
        # Language keywords and common false positives
        noise = {
            "if",
            "while",
            "for",
            "switch",
            "return",
            "sizeof",
            "typeof",
            "defined",
            "else",
            "case",
            "do",
            "struct",
            "enum",
            "union",
            "typedef",
            "extern",
            "goto",
            "break",
            "continue",
        }
        # Common kernel function name patterns that appear across many
        # modules and produce symbol collisions in the merged table.
        common_func_names = {
            "init",
            "exit",
            "probe",
            "remove",
            "open",
            "close",
            "release",
            "read",
            "write",
            "ioctl",
            "mmap",
            "poll",
            "start",
            "stop",
            "resume",
            "suspend",
            "shutdown",
            "reset",
            "enable",
            "disable",
            "setup",
            "cleanup",
            "alloc",
            "free",
            "create",
            "destroy",
            "register",
            "unregister",
            "attach",
            "detach",
            "connect",
            "disconnect",
            "send",
            "recv",
            "show",
            "store",
            "get",
            "set",
            "put",
        }

        total_funcs = 0
        match_count = 0

        for af in affected_files:
            full_path = os.path.join(self.kernel_src_dir, af)
            if not os.path.exists(full_path):
                continue
            try:
                with open(full_path, "r", errors="replace") as f:
                    content = f.read()
                for m in func_def_re.finditer(content):
                    name = m.group(1)
                    if name in noise:
                        continue
                    # Skip very common single-word function names
                    if name in common_func_names:
                        continue
                    total_funcs += 1
                    if name in symbols:
                        match_count += 1
            except (IOError, OSError):
                continue

        # Require multiple matches to avoid collisions in the 1M+ symbol table.
        # A single match is likely coincidental; 3+ matches or 30%+ rate is
        # strong evidence the file's code is compiled into the binary.
        if total_funcs == 0:
            return False
        match_rate = match_count / total_funcs
        return match_count >= 3 or (match_count >= 2 and match_rate >= 0.3)

    def is_config_enabled(self, config_name: str) -> Optional[bool]:
        """
        Check if a CONFIG option is enabled.

        Returns:
            True if enabled, False if disabled, None if unknown
            (when using inferred config, disabled is reported as None
            since we can't conclusively determine all disabled options)
        """
        if not self._config_loaded:
            return None

        if config_name in self._enabled_configs:
            return True

        # For user-provided or ikconfig, we have the full picture
        if self._config_source in ("user", "ikconfig"):
            return False

        # For inferred config, we can't be sure something is disabled
        return None

    # =================================================================
    # Makefile-based CONFIG mapping
    # =================================================================

    def build_config_mapping(self, cache_path: Optional[str] = None) -> Tuple[int, int]:
        """
        Build file -> CONFIG mapping by parsing kernel Makefiles/Kbuild files.

        This replicates the logic from the source-based checker.

        Args:
            cache_path: Optional path to cache the mapping TSV

        Returns:
            (file_count, dir_count) tuple
        """
        if not os.path.isdir(self.kernel_src_dir):
            return (0, 0)

        self._file_config_map.clear()
        self._dir_config_map.clear()

        srcroot = self.kernel_src_dir.rstrip("/") + "/"

        # Use the same awk approach as the source-based checker
        try:
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'''
                find "{self.kernel_src_dir}" \\( -name "Makefile" -o -name "Kbuild" \\) -print0 | \\
                xargs -0 -P1 -n50 awk -v srcroot="{srcroot}" '
                    FILENAME != prev_file {{
                        prev_file = FILENAME
                        dir = FILENAME
                        sub(/\\/[^\\/]+$/, "", dir)
                        sub(srcroot, "", dir)
                        if (dir == substr(srcroot, 1, length(srcroot)-1)) dir = ""
                        buf = ""
                    }}
                    /\\\\$/ {{ buf = buf $0; next }}
                    {{ line = buf $0; buf = "" }}
                    line ~ /obj-\\$\\(CONFIG_[A-Za-z0-9_]+\\)/ {{
                        match(line, /CONFIG_[A-Za-z0-9_]+/)
                        config = substr(line, RSTART, RLENGTH)
                        n = split(line, parts, /[[:space:]+=]+/)
                        for (i = 1; i <= n; i++) {{
                            if (parts[i] ~ /\\.o$/) {{
                                base = parts[i]
                                sub(/\\.o$/, ".c", base)
                                if (dir == "") print base "\\t" config
                                else print dir "/" base "\\t" config
                            }} else if (parts[i] ~ /\\/$/) {{
                                subdir = parts[i]
                                sub(/\\/$/, "", subdir)
                                if (dir == "") print subdir "\\t" config
                                else print dir "/" subdir "\\t" config
                            }}
                        }}
                    }}
                    line ~ /obj-y[[:space:]]*[\\+:]?=/ {{
                        n = split(line, parts, /[[:space:]+=]+/)
                        for (i = 1; i <= n; i++) {{
                            if (parts[i] ~ /\\.o$/) {{
                                base = parts[i]
                                sub(/\\.o$/, ".c", base)
                                if (dir == "") print base "\\tALWAYS_BUILT"
                                else print dir "/" base "\\tALWAYS_BUILT"
                            }}
                        }}
                    }}
                ' 2>/dev/null
                ''',
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return (0, 0)

        if result.returncode != 0:
            return (0, 0)

        file_count = 0
        dir_count = 0

        for line in result.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) != 2:
                continue
            path, config = parts[0], parts[1]
            if not path or not config:
                continue

            if path.endswith(".c"):
                self._file_config_map[path] = config
                file_count += 1
            else:
                self._dir_config_map[path] = config
                dir_count += 1

        # Save cache if requested
        if cache_path:
            try:
                with open(cache_path, "w") as f:
                    for path, config in sorted(self._file_config_map.items()):
                        f.write(f"{path}\t{config}\n")
                    for path, config in sorted(self._dir_config_map.items()):
                        f.write(f"{path}\t{config}\n")
            except IOError:
                pass

        self._mapping_built = True
        return (file_count, dir_count)

    def map_file_to_config(self, file_path: str) -> str:
        """
        Map a source file path to its CONFIG dependency.

        Args:
            file_path: Relative path to a kernel source file (e.g., "drivers/net/foo.c")

        Returns:
            CONFIG_XXX name, "ALWAYS_BUILT", or "UNKNOWN"
        """
        # 1. Exact file match
        if file_path in self._file_config_map:
            return self._file_config_map[file_path]

        # 2. Walk up directory tree (longest match first)
        parts = file_path.split("/")
        for i in range(len(parts) - 1, 0, -1):
            dir_path = "/".join(parts[:i])
            if dir_path in self._dir_config_map:
                return self._dir_config_map[dir_path]

        return "UNKNOWN"

    # =================================================================
    # CVE config resolution
    # =================================================================

    def _is_file_for_other_arch(self, file_path: str) -> bool:
        """Check if a file belongs to a different architecture.

        Checks both arch/<name>/ and drivers/<name>/ directories, since
        architecture-specific drivers often live under drivers/<arch>/
        (e.g., drivers/s390/net/, drivers/parisc/).
        """
        if not self._target_arch_dir:
            return False  # No arch set, can't filter

        for arch_dir in self._all_arch_dirs:
            if file_path.startswith(arch_dir + "/") or file_path.startswith(
                arch_dir + " "
            ):
                # File is arch-specific — check if it matches our target
                if file_path.startswith(self._target_arch_dir + "/"):
                    return False  # It's for our arch (arch/<ours>/)
                if self._target_arch_driver_dir and file_path.startswith(
                    self._target_arch_driver_dir + "/"
                ):
                    return False  # It's for our arch (drivers/<ours>/)
                return True  # It's for a different arch

        return False  # Not arch-specific (generic code)

    def get_config_status_for_files(self, affected_files: List[str]) -> Tuple[str, str]:
        """
        Determine the config status for a set of affected files.

        Filters out files from other architectures automatically.

        Args:
            affected_files: List of source file paths affected by a fix

        Returns:
            (config_name, status) where status is one of:
            - "ENABLED": At least one affected file's config is enabled
            - "DISABLED": All affected files' configs are disabled
            - "UNKNOWN": Cannot determine (no mapping or inferred config)
            - "ALWAYS_BUILT": Affected code is always compiled in
            - "NOT_THIS_ARCH": All files are for a different architecture
        """
        if not self._config_loaded or not self._mapping_built:
            return ("UNKNOWN", "UNKNOWN")

        has_enabled = False
        has_disabled = False
        has_unknown = False
        all_other_arch = True
        configs_found = set()

        for f in affected_files:
            # Filter out files for other architectures
            if self._is_file_for_other_arch(f):
                continue

            all_other_arch = False
            config = self.map_file_to_config(f)

            if config == "ALWAYS_BUILT":
                has_enabled = True
                configs_found.add(config)
            elif config == "UNKNOWN":
                has_unknown = True
            else:
                configs_found.add(config)
                status = self.is_config_enabled(config)
                if status is True:
                    has_enabled = True
                elif status is False:
                    has_disabled = True
                else:
                    # None = can't determine (inferred config)
                    has_unknown = True

        # If all files were for other architectures
        if all_other_arch and affected_files:
            return ("N/A", "NOT_THIS_ARCH")

        # Decision logic (same as source-based checker)
        config_str = ", ".join(sorted(configs_found)) if configs_found else "UNKNOWN"

        if has_enabled:
            return (config_str, "ENABLED")
        elif has_disabled and not has_unknown:
            return (config_str, "DISABLED")
        else:
            return (config_str, "UNKNOWN")


def main():
    """CLI interface for testing config resolution."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Resolve CONFIG dependencies for kernel source files"
    )
    parser.add_argument("kernel_src", help="Path to kernel source tree")
    parser.add_argument("--config", help="Path to .config file")
    parser.add_argument("--ikconfig", help="Path to extracted ikconfig")
    parser.add_argument("--builtin-modules", help="Path to builtin_modules.txt")
    parser.add_argument("--symbols", help="Path to kallsyms.txt")
    parser.add_argument("--files", nargs="+", help="Source files to check")
    parser.add_argument("--stats", action="store_true", help="Show mapping statistics")

    args = parser.parse_args()

    resolver = ConfigResolver(args.kernel_src)

    # Load config
    if args.config:
        count = resolver.load_config(args.config)
        print(f"Loaded {count} enabled configs from .config")
    elif args.ikconfig:
        count = resolver.load_ikconfig(args.ikconfig)
        print(f"Loaded {count} enabled configs from ikconfig")
    elif args.builtin_modules:
        count = resolver.infer_config_from_modules(args.builtin_modules, args.symbols)
        print(f"Inferred {count} enabled configs from modules/symbols")

    # Build mapping
    file_count, dir_count = resolver.build_config_mapping()
    print(f"CONFIG mapping: {file_count} files, {dir_count} directories")

    if args.stats:
        print(f"\nConfig source: {resolver._config_source}")
        print(f"Enabled configs: {len(resolver._enabled_configs)}")

    if args.files:
        for f in args.files:
            config = resolver.map_file_to_config(f)
            status = (
                resolver.is_config_enabled(config)
                if config not in ("UNKNOWN", "ALWAYS_BUILT")
                else None
            )
            status_str = (
                "ENABLED"
                if status is True
                else "DISABLED"
                if status is False
                else "UNKNOWN"
            )
            print(f"  {f} -> {config} ({status_str})")


if __name__ == "__main__":
    main()
