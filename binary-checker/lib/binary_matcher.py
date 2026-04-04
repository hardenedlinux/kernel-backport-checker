#!/usr/bin/env python3
"""
binary_matcher.py

Match CVE fix signatures against a kernel binary using multiple analysis
strategies. Uses r2pipe (radare2) for binary analysis when available,
with fallbacks to string-based matching.

Analysis strategies (in order of application):
  1. String matching:   Check if fix-introduced strings exist in binary
  2. Symbol matching:   Check if fix-introduced functions exist (needs kallsyms)
  3. Constant matching: Search for distinctive constants/immediates
  4. Function presence: Check if affected functions exist in binary (applicability)

Verdicts:
  FIXED          - Strong evidence the fix is present
  LIKELY_FIXED   - Moderate evidence the fix is present
  UNFIXED        - Strong evidence the fix is NOT present
  INCONCLUSIVE   - Insufficient evidence to determine
  NOT_APPLICABLE - The affected code is not compiled into this binary

Usage:
    from lib.binary_matcher import BinaryMatcher
    matcher = BinaryMatcher("/path/to/vmlinux", symbols_file="kallsyms.txt")
    result = matcher.match_signature(fix_signature)
"""

import os
import sys
import json
import subprocess
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.string_signatures import FixSignature


@dataclass
class MatchResult:
    """Result of matching a fix signature against a binary."""

    cve_id: str
    commit_hash: str
    verdict: str  # FIXED, LIKELY_FIXED, UNFIXED, INCONCLUSIVE, NOT_APPLICABLE
    confidence: float  # 0.0 - 1.0
    details: Dict = field(default_factory=dict)

    # Per-strategy results
    string_added_matched: int = 0
    string_added_total: int = 0
    string_removed_matched: int = 0
    string_removed_total: int = 0
    symbol_added_matched: int = 0
    symbol_added_total: int = 0
    symbol_modified_present: int = 0
    symbol_modified_total: int = 0
    constant_matched: int = 0
    constant_total: int = 0
    function_present: int = 0
    function_total: int = 0

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "commit_hash": self.commit_hash,
            "verdict": self.verdict,
            "confidence": round(self.confidence, 3),
            "string_match": f"{self.string_added_matched}/{self.string_added_total}",
            "string_removed": f"{self.string_removed_matched}/{self.string_removed_total}",
            "symbol_match": f"{self.symbol_added_matched}/{self.symbol_added_total}",
            "function_present": f"{self.function_present}/{self.function_total}",
            "details": self.details,
        }


class BinaryMatcher:
    """
    Matches CVE fix signatures against a kernel binary.

    Supports multiple analysis backends:
      - Pure string matching (always available)
      - Symbol table matching (if kallsyms/nm output available)
      - r2pipe/radare2 analysis (if r2 installed)
    """

    def __init__(
        self,
        binary_path: str,
        strings_file: Optional[str] = None,
        symbols_file: Optional[str] = None,
        is_elf: bool = True,
        arch: str = "x86_64",
        use_r2: bool = True,
    ):
        """
        Args:
            binary_path: Path to the kernel binary (vmlinux or raw blob)
            strings_file: Pre-extracted strings file (one per line)
            symbols_file: Pre-extracted symbols file (nm/kallsyms format)
            is_elf: Whether the binary is ELF format
            arch: Target architecture
            use_r2: Whether to attempt radare2 analysis
        """
        self.binary_path = binary_path
        self.is_elf = is_elf
        self.arch = arch

        # Load pre-extracted data
        self._strings: Optional[Set[str]] = None
        self._string_freq: Dict[str, int] = {}  # string -> occurrence count
        self._symbols: Optional[Dict[str, str]] = None  # name -> type/address
        self._r2 = None
        self._r2_available = False

        if strings_file and os.path.exists(strings_file):
            self._load_strings(strings_file)

        if symbols_file and os.path.exists(symbols_file):
            self._load_symbols(symbols_file)

        # Try to initialize r2pipe
        if use_r2:
            self._init_r2()

    def _load_strings(self, filepath: str):
        """Load pre-extracted strings from file, tracking frequency."""
        self._strings = set()
        self._string_freq: Dict[str, int] = {}  # string -> occurrence count
        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\n")
                    if line and not line.startswith("#"):
                        self._strings.add(line)
                        self._string_freq[line] = self._string_freq.get(line, 0) + 1
        except IOError:
            self._strings = None
            self._string_freq = {}

    def _load_symbols(self, filepath: str):
        """Load symbol table from nm/kallsyms output."""
        self._symbols = {}
        try:
            with open(filepath, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 3:
                        # nm format: address type name
                        addr, sym_type, name = parts[0], parts[1], parts[2]
                        self._symbols[name] = f"{sym_type}:{addr}"
                    elif len(parts) == 2:
                        # Simple format: type name or name address
                        self._symbols[parts[1]] = parts[0]
                    elif len(parts) == 1:
                        # Just a name
                        self._symbols[parts[0]] = ""
        except IOError:
            self._symbols = None

    def _init_r2(self):
        """Initialize radare2 via r2pipe."""
        try:
            import r2pipe

            flags = ["-2"]  # Close stderr
            if not self.is_elf:
                # For raw blobs, specify architecture
                arch_map = {
                    "x86": ["-a", "x86", "-b", "32"],
                    "x86_64": ["-a", "x86", "-b", "64"],
                    "arm": ["-a", "arm", "-b", "32"],
                    "aarch64": ["-a", "arm", "-b", "64"],
                    "mips": ["-a", "mips", "-b", "32"],
                    "ppc": ["-a", "ppc", "-b", "32"],
                }
                flags.extend(arch_map.get(self.arch, []))

            self._r2 = r2pipe.open(self.binary_path, flags=flags)
            self._r2_available = True
        except (ImportError, Exception):
            self._r2_available = False

    def close(self):
        """Clean up radare2 session."""
        if self._r2 is not None:
            try:
                self._r2.quit()
            except Exception:
                pass
            self._r2 = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # =====================================================================
    # String-based matching
    # =====================================================================

    def _ensure_strings(self):
        """Ensure strings are loaded, extracting from binary if needed."""
        if self._strings is not None:
            return

        self._strings = set()

        # Method 1: Use pre-extracted strings via r2
        if self._r2_available:
            try:
                result = self._r2.cmdj("izj")  # List strings as JSON
                if result:
                    for entry in result:
                        s = entry.get("string", "")
                        if len(s) >= 8:
                            self._strings.add(s)
                    return
            except Exception:
                pass

        # Method 2: Use system `strings` command
        try:
            result = subprocess.run(
                ["strings", "-n", "8", self.binary_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    self._strings.add(line)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def match_string(self, target: str) -> bool:
        """Check if a string exists in the binary."""
        self._ensure_strings()
        if self._strings is None:
            return False

        # Exact match first
        if target in self._strings:
            return True

        # Try substring match for longer strings (compiler may split them)
        # Require >= 30 chars for substring match to reduce false positives
        if len(target) >= 30:
            # Only check if target is contained in a binary string
            # (not the reverse - a short binary string in a long target is not meaningful)
            for s in self._strings:
                if target in s:
                    return True

        return False

    def is_string_unique(self, target: str) -> bool:
        """
        Check if a string is unique enough to be a reliable signal.

        Strings that appear many times in the binary are common patterns
        (error messages, format strings) and are unreliable as fix/vuln indicators.
        """
        if not self._string_freq:
            return True  # No frequency data, assume unique

        # Check exact match frequency
        if target in self._string_freq:
            return self._string_freq[target] <= 2

        # For substring matches, check if the matching string is common
        if len(target) >= 30:
            for s in self._strings or set():
                if target in s and s in self._string_freq:
                    if self._string_freq[s] > 2:
                        return False

        return True

    def match_strings_batch(self, targets: List[str]) -> List[bool]:
        """Check multiple strings efficiently."""
        self._ensure_strings()
        results = []
        for target in targets:
            results.append(self.match_string(target))
        return results

    # =====================================================================
    # Symbol-based matching
    # =====================================================================

    def _ensure_symbols(self):
        """Ensure symbols are loaded."""
        if self._symbols is not None:
            return

        self._symbols = {}

        # Try nm for ELF binaries
        if self.is_elf:
            try:
                result = subprocess.run(
                    ["nm", self.binary_path], capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        parts = line.split()
                        if len(parts) >= 3:
                            self._symbols[parts[2]] = f"{parts[1]}:{parts[0]}"
                    return
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        # Try r2 for function flags
        if self._r2_available:
            try:
                # Quick analysis for function detection
                self._r2.cmd("aaa")
                result = self._r2.cmdj("aflj")
                if result:
                    for func in result:
                        name = func.get("name", "")
                        addr = func.get("offset", 0)
                        self._symbols[name] = f"T:{hex(addr)}"
            except Exception:
                pass

    def has_symbol(self, name: str) -> bool:
        """Check if a symbol exists in the binary."""
        self._ensure_symbols()
        if self._symbols is None:
            return False
        return name in self._symbols

    def has_function(self, name: str) -> bool:
        """Check if a function symbol exists."""
        self._ensure_symbols()
        if self._symbols is None:
            return False

        # Direct match
        if name in self._symbols:
            sym_info = self._symbols[name]
            # In nm output, T/t = text (code), W/w = weak
            if any(sym_info.startswith(f"{t}:") for t in ["T", "t", "W", "w"]):
                return True
            # If no type info, assume it's a function
            if ":" not in sym_info:
                return True
            return True

        # Try with common kernel prefixes/suffixes
        prefixes = ["__", "sys_", "__x64_sys_", "__arm64_sys_"]
        for prefix in prefixes:
            if (prefix + name) in self._symbols:
                return True

        return False

    # =====================================================================
    # Constant/immediate value matching (via r2)
    # =====================================================================

    def search_constant(self, value: int, context_func: Optional[str] = None) -> bool:
        """
        Search for a constant/immediate value in the binary.

        If context_func is provided, only search within that function.
        """
        if not self._r2_available:
            return False

        try:
            if context_func and self.has_function(context_func):
                # Search within function
                self._r2.cmd(f"s sym.{context_func}")
                result = self._r2.cmd(f"/ai {value}")
            else:
                # Global search for the constant
                if -256 <= value <= 256:
                    # Small values are too common, skip
                    return False
                result = self._r2.cmd(f"/x {value:08x}")

            return bool(result and result.strip())
        except Exception:
            return False

    # =====================================================================
    # Binary grep (search raw bytes/patterns)
    # =====================================================================

    def binary_grep(self, pattern: bytes) -> List[int]:
        """Search for a byte pattern in the binary, return offsets."""
        offsets = []
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            start = 0
            while True:
                idx = data.find(pattern, start)
                if idx == -1:
                    break
                offsets.append(idx)
                start = idx + 1
                if len(offsets) > 100:  # Safety limit
                    break
        except IOError:
            pass
        return offsets

    def search_string_in_binary(self, target: str) -> bool:
        """Direct binary search for a string (bypasses string extraction)."""
        return len(self.binary_grep(target.encode("utf-8", errors="replace"))) > 0

    # =====================================================================
    # Main matching logic
    # =====================================================================

    def match_signature(self, sig: FixSignature) -> MatchResult:
        """
        Match a fix signature against the binary and produce a verdict.

        The matching uses a multi-signal approach similar to the source-based
        checker, but adapted for binary analysis:

        1. Check if affected functions exist in the binary (applicability)
        2. Check if fix-introduced strings are present (fix indicator)
        3. Check if vulnerable-code strings are still present (vuln indicator)
        4. Check if new functions from the fix exist (fix indicator)
        5. Combine signals into a verdict
        """
        result = MatchResult(
            cve_id=sig.cve_id,
            commit_hash=sig.commit_hash,
            verdict="INCONCLUSIVE",
            confidence=0.0,
        )

        # -----------------------------------------------------------
        # Step 1: Applicability check via function presence
        # -----------------------------------------------------------
        if self._symbols is not None or self.is_elf:
            self._ensure_symbols()
            if self._symbols:
                # Use modified_functions if available, otherwise fall back to
                # removed_functions (for commits that add/remove entire files)
                check_functions = sig.modified_functions
                if not check_functions and sig.removed_functions:
                    # For whole-file removals, use a sample of removed functions
                    # to check if the affected code is compiled in
                    check_functions = sig.removed_functions[:20]

                if check_functions:
                    result.function_total = len(check_functions)
                    for func_name in check_functions:
                        if self.has_function(func_name):
                            result.function_present += 1

                    if result.function_total > 0 and result.function_present == 0:
                        # None of the affected functions exist in the binary
                        result.verdict = "NOT_APPLICABLE"
                        result.confidence = 0.8
                        result.details["reason"] = (
                            f"None of the {result.function_total} affected functions "
                            f"found in binary: {check_functions[:5]}"
                        )
                        return result

        # -----------------------------------------------------------
        # Step 2: String matching (strongest signal for binary analysis)
        # -----------------------------------------------------------
        self._ensure_strings()

        # Check added strings (fix indicators)
        # Track unique vs non-unique matches separately
        if sig.added_strings:
            result.string_added_total = len(sig.added_strings)
            matched_strings = []
            unique_added_matched = 0
            for s in sig.added_strings:
                if self.match_string(s):
                    result.string_added_matched += 1
                    matched_strings.append(s[:50])
                    if self.is_string_unique(s):
                        unique_added_matched += 1
            if matched_strings:
                result.details["matched_added_strings"] = matched_strings[:5]
            result.details["unique_added_matched"] = unique_added_matched

        # Check removed strings (vulnerability indicators)
        # Only count unique matches - common strings are unreliable vuln signals
        if sig.removed_strings:
            result.string_removed_total = len(sig.removed_strings)
            matched_vuln_strings = []
            unique_removed_matched = 0
            for s in sig.removed_strings:
                if self.match_string(s):
                    result.string_removed_matched += 1
                    matched_vuln_strings.append(s[:50])
                    if self.is_string_unique(s):
                        unique_removed_matched += 1
            if matched_vuln_strings:
                result.details["matched_removed_strings"] = matched_vuln_strings[:5]
            result.details["unique_removed_matched"] = unique_removed_matched

        # -----------------------------------------------------------
        # Step 3: Symbol/function matching
        # -----------------------------------------------------------
        if sig.added_functions:
            self._ensure_symbols()
            result.symbol_added_total = len(sig.added_functions)
            for func_name in sig.added_functions:
                if self.has_function(func_name):
                    result.symbol_added_matched += 1

        if sig.modified_functions:
            result.symbol_modified_total = len(sig.modified_functions)
            # Already checked in step 1

        # -----------------------------------------------------------
        # Step 4: Distinctive line matching (as raw strings in binary)
        # -----------------------------------------------------------
        distinctive_added_found = 0
        distinctive_removed_found = 0

        if sig.distinctive_added_lines:
            for line in sig.distinctive_added_lines:
                # Extract string literals from the line
                string_lits = re.findall(r'"((?:[^"\\]|\\.){8,})"', line)
                for s in string_lits:
                    if self.match_string(s):
                        distinctive_added_found += 1
                        break

        if sig.distinctive_removed_lines:
            for line in sig.distinctive_removed_lines:
                string_lits = re.findall(r'"((?:[^"\\]|\\.){8,})"', line)
                for s in string_lits:
                    if self.match_string(s):
                        distinctive_removed_found += 1
                        break

        # -----------------------------------------------------------
        # Step 5: Verdict computation
        # -----------------------------------------------------------
        result = self._compute_verdict(
            result, sig, distinctive_added_found, distinctive_removed_found
        )

        return result

    def _compute_verdict(
        self,
        result: MatchResult,
        sig: FixSignature,
        distinctive_added_found: int,
        distinctive_removed_found: int,
    ) -> MatchResult:
        """
        Compute the final verdict from collected signals.

        Key principles:
        1. If affected functions ARE present in binary and we find NO fix
           evidence, the fix is absent → UNFIXED
        2. String/symbol matches provide additional confidence in either direction
        3. Truly empty signatures (no data at all) → INCONCLUSIVE
        4. Bulk-commit protections (done upstream in string_signatures.py)
           prevent false matches from subsystem removals
        """

        # Whether the affected functions were confirmed present in binary
        functions_confirmed = result.function_present > 0 and result.function_total > 0

        # Calculate ratios
        added_ratio = 0.0
        removed_ratio = 0.0
        symbol_ratio = 0.0

        if result.string_added_total > 0:
            added_ratio = result.string_added_matched / result.string_added_total

        if result.string_removed_total > 0:
            removed_ratio = result.string_removed_matched / result.string_removed_total

        if result.symbol_added_total > 0:
            symbol_ratio = result.symbol_added_matched / result.symbol_added_total

        # Use unique match counts for more reliable signal assessment
        unique_added = result.details.get(
            "unique_added_matched", result.string_added_matched
        )
        unique_removed = result.details.get(
            "unique_removed_matched", result.string_removed_matched
        )

        total_fix_signals = (
            result.string_added_matched
            + result.symbol_added_matched
            + distinctive_added_found
        )
        total_vuln_signals = result.string_removed_matched + distinctive_removed_found

        # Unique-weighted signals (more conservative)
        unique_fix_signals = (
            unique_added + result.symbol_added_matched + distinctive_added_found
        )
        unique_vuln_signals = unique_removed + distinctive_removed_found

        # Track reasoning
        reasons = []

        # ---- Truly empty signature: no data to work with ----
        if sig.is_empty():
            result.verdict = "INCONCLUSIVE"
            result.confidence = 0.1
            reasons.append(
                "No usable signatures could be extracted from the fix commit"
            )
            result.details["reasons"] = reasons
            result.details["added_ratio"] = round(added_ratio, 3)
            result.details["removed_ratio"] = round(removed_ratio, 3)
            result.details["symbol_ratio"] = round(symbol_ratio, 3)
            result.details["fix_signals"] = total_fix_signals
            result.details["vuln_signals"] = total_vuln_signals
            result.details["unique_fix_signals"] = unique_fix_signals
            result.details["unique_vuln_signals"] = unique_vuln_signals
            result.details["signature_strength"] = sig.strength
            return result

        # ---- Decision matrix ----

        # Case 1: Strong fix evidence (added strings present, vuln strings gone)
        # Require removed_ratio < 0.15 (not 0.3) to match source checker's
        # strictness: vulnerable code must be mostly gone, not just "somewhat."
        # Also require sufficient signature data for a confident FIXED verdict.
        if added_ratio >= 0.7 and removed_ratio < 0.15:
            if result.string_removed_total >= 2 or result.string_added_total >= 3:
                # Dual-signal: strong added evidence + vuln code confirmed gone
                # (or enough added strings to be statistically meaningful)
                result.verdict = "FIXED"
                result.confidence = min(0.9, 0.5 + added_ratio * 0.4)
                reasons.append(
                    f"Added strings: {result.string_added_matched}/{result.string_added_total} ({added_ratio:.0%})"
                )
                if result.string_removed_total > 0:
                    reasons.append(
                        f"Removed strings mostly gone: {result.string_removed_matched}/{result.string_removed_total}"
                    )
            elif result.string_removed_total == 0 and result.string_added_total >= 2:
                # No vulnerable strings to corroborate — downgrade to LIKELY_FIXED
                result.verdict = "LIKELY_FIXED"
                result.confidence = 0.7
                reasons.append(
                    f"Added strings: {result.string_added_matched}/{result.string_added_total} ({added_ratio:.0%})"
                )
                reasons.append(
                    "No removed strings to corroborate (downgraded from FIXED)"
                )
            else:
                # Too little data for FIXED
                result.verdict = "LIKELY_FIXED"
                result.confidence = 0.6
                reasons.append(
                    f"Added strings: {result.string_added_matched}/{result.string_added_total} ({added_ratio:.0%})"
                )
                reasons.append("Insufficient signature data for FIXED verdict")

        # Case 1b: Added strings present but removed strings still substantially present
        # (removed_ratio between 0.15 and 0.3) — ambiguous, not FIXED
        elif added_ratio >= 0.7 and removed_ratio < 0.3:
            result.verdict = "LIKELY_FIXED"
            result.confidence = 0.5
            reasons.append(
                f"Added strings: {result.string_added_matched}/{result.string_added_total} ({added_ratio:.0%})"
            )
            reasons.append(
                f"Removed strings partially present: {result.string_removed_matched}/{result.string_removed_total} ({removed_ratio:.0%})"
            )

        # Case 2: Strong UNFIXED - removed strings present + fix strings absent
        elif removed_ratio >= 0.7 and added_ratio < 0.3 and unique_removed >= 2:
            result.verdict = "UNFIXED"
            result.confidence = min(0.85, 0.4 + removed_ratio * 0.3)
            reasons.append(
                f"Vulnerable strings still present: {result.string_removed_matched}/{result.string_removed_total} ({removed_ratio:.0%})"
            )
            if result.string_added_total > 0:
                reasons.append(
                    f"Fix strings absent: {result.string_added_matched}/{result.string_added_total}"
                )

        # Case 3: New functions exist in binary
        # Function presence alone is weak evidence: many "added" functions
        # are actually pre-existing functions that were refactored (split,
        # renamed) by the fix.  e.g., ftruncate (core syscall),
        # reserve_compress_blocks (split from f2fs_reserve_compress_blocks).
        # Require at least one additional corroborating signal.
        elif symbol_ratio >= 0.5 and result.symbol_added_total >= 1:
            if (
                result.string_added_matched > 0
                or distinctive_added_found > 0
                or unique_fix_signals >= 3
            ):
                # Corroborated by string/distinctive-line evidence
                result.verdict = "LIKELY_FIXED"
                result.confidence = 0.6 + symbol_ratio * 0.2
                reasons.append(
                    f"Fix-introduced functions found: {result.symbol_added_matched}/{result.symbol_added_total}"
                )
                reasons.append("Corroborated by string/line evidence")
            else:
                # Symbol-only evidence — too weak for LIKELY_FIXED
                result.verdict = "INCONCLUSIVE"
                result.confidence = 0.3
                reasons.append(
                    f"Fix-introduced functions found: {result.symbol_added_matched}/{result.symbol_added_total}"
                )
                reasons.append(
                    "Symbol-only evidence is unreliable (function may pre-exist the fix)"
                )

        # Case 4: Both fix and vuln strings present
        elif added_ratio >= 0.5 and removed_ratio >= 0.5:
            result.verdict = "LIKELY_FIXED"
            result.confidence = 0.5
            reasons.append(
                f"Both fix ({added_ratio:.0%}) and vulnerable ({removed_ratio:.0%}) strings found"
            )
            reasons.append("May indicate partial fix or code similarity")

        # Case 5: Moderate fix evidence
        elif added_ratio >= 0.4 or unique_fix_signals >= 3:
            result.verdict = "LIKELY_FIXED"
            result.confidence = 0.4 + added_ratio * 0.3
            reasons.append(
                f"Moderate fix evidence: strings={result.string_added_matched}/{result.string_added_total}, "
                f"symbols={result.symbol_added_matched}/{result.symbol_added_total}"
            )

        # Case 6: Moderate vulnerability evidence with unique matches
        elif removed_ratio >= 0.4 and unique_vuln_signals >= 2:
            result.verdict = "UNFIXED"
            result.confidence = 0.4 + removed_ratio * 0.2
            reasons.append(
                f"Moderate vulnerability evidence: {unique_removed} unique vulnerable strings present"
            )
            if result.string_added_total > 0:
                reasons.append(
                    f"Fix strings absent: {result.string_added_matched}/{result.string_added_total}"
                )

        # Case 7: Fix completely absent with enough signature data
        elif (
            result.string_added_total >= 3
            and result.string_added_matched == 0
            and result.symbol_added_total >= 1
            and result.symbol_added_matched == 0
        ):
            result.verdict = "UNFIXED"
            result.confidence = 0.6
            reasons.append(
                "No fix strings or symbols found despite sufficient signature data"
            )

        # Case 8: Fix signals present
        elif unique_fix_signals > unique_vuln_signals and unique_fix_signals >= 2:
            result.verdict = "LIKELY_FIXED"
            result.confidence = 0.5
            reasons.append(
                f"Fix evidence: {unique_fix_signals} unique fix signals vs {unique_vuln_signals} vuln signals"
            )

        # Case 9: Vuln signals present
        elif unique_vuln_signals > unique_fix_signals and unique_vuln_signals >= 2:
            result.verdict = "UNFIXED"
            result.confidence = 0.5
            reasons.append(
                f"Vuln evidence: {unique_vuln_signals} unique vuln signals vs {unique_fix_signals} fix signals"
            )

        # Case 10: Functions confirmed present but NO fix evidence at all
        # This is the critical path for detection: if we know the affected
        # code is compiled in but find zero evidence of the fix being applied,
        # the fix is absent.
        elif functions_confirmed and total_fix_signals == 0:
            result.verdict = "UNFIXED"
            result.confidence = 0.4
            reasons.append(
                f"Affected functions present in binary ({result.function_present}/{result.function_total})"
            )
            reasons.append(
                "No fix evidence found (no matching strings, symbols, or constants)"
            )

        # Case 11: No function info and no string/symbol signals
        else:
            result.verdict = "INCONCLUSIVE"
            result.confidence = 0.1
            if (
                result.string_added_total == 0
                and result.string_removed_total == 0
                and result.symbol_added_total == 0
                and not functions_confirmed
            ):
                reasons.append(
                    "Fix changes only code logic without distinctive strings or new functions"
                )
                reasons.append(
                    "Cannot confirm if affected code is compiled into binary"
                )
            else:
                reasons.append(
                    f"Insufficient evidence: fix_signals={total_fix_signals}, vuln_signals={total_vuln_signals}"
                )

        result.details["reasons"] = reasons
        result.details["added_ratio"] = round(added_ratio, 3)
        result.details["removed_ratio"] = round(removed_ratio, 3)
        result.details["symbol_ratio"] = round(symbol_ratio, 3)
        result.details["fix_signals"] = total_fix_signals
        result.details["vuln_signals"] = total_vuln_signals
        result.details["unique_fix_signals"] = unique_fix_signals
        result.details["unique_vuln_signals"] = unique_vuln_signals
        result.details["functions_confirmed"] = functions_confirmed
        result.details["signature_strength"] = sig.strength

        return result

    # =====================================================================
    # Batch matching
    # =====================================================================

    def match_cve(self, signatures: List[FixSignature]) -> MatchResult:
        """
        Match all signatures for a single CVE and produce an aggregate verdict.

        When a CVE has multiple fix commits, each is evaluated independently
        and results are combined using the same priority logic as the
        source-based checker.
        """
        if not signatures:
            return MatchResult(
                cve_id="",
                commit_hash="",
                verdict="INCONCLUSIVE",
                confidence=0.0,
                details={"reason": "No signatures available"},
            )

        cve_id = signatures[0].cve_id
        per_commit_results = []

        for sig in signatures:
            result = self.match_signature(sig)
            per_commit_results.append(result)

        # Aggregate verdicts
        return self._aggregate_verdicts(cve_id, per_commit_results)

    def _aggregate_verdicts(
        self, cve_id: str, results: List[MatchResult]
    ) -> MatchResult:
        """
        Aggregate per-commit verdicts into a final CVE verdict.

        Priority logic (matches source-based checker):
          - FIXED wins if: >=1 FIXED, 0 UNFIXED, FIXED count > LIKELY count
          - Mixed FIXED + UNFIXED -> LIKELY_FIXED
          - Any LIKELY_FIXED -> LIKELY_FIXED
          - Any UNFIXED (no FIXED) -> UNFIXED
          - Only INCONCLUSIVE -> INCONCLUSIVE
          - Any NOT_APPLICABLE: excluded from verdict (unless all are N/A)
        """
        if not results:
            return MatchResult(
                cve_id=cve_id, commit_hash="", verdict="INCONCLUSIVE", confidence=0.0
            )

        # Count verdicts (excluding NOT_APPLICABLE and INCONCLUSIVE for decisions)
        verdicts = {
            "FIXED": 0,
            "LIKELY_FIXED": 0,
            "UNFIXED": 0,
            "INCONCLUSIVE": 0,
            "NOT_APPLICABLE": 0,
        }
        applicable_results = []

        for r in results:
            verdicts[r.verdict] += 1
            if r.verdict != "NOT_APPLICABLE":
                applicable_results.append(r)

        # If all NOT_APPLICABLE
        if not applicable_results:
            return MatchResult(
                cve_id=cve_id,
                commit_hash=results[0].commit_hash,
                verdict="NOT_APPLICABLE",
                confidence=0.8,
                details={
                    "reason": "All fix commits affect code not present in binary",
                    "per_commit": [r.to_dict() for r in results],
                },
            )

        # Count definitive (non-INCONCLUSIVE) verdicts
        definitive_count = (
            verdicts["FIXED"] + verdicts["LIKELY_FIXED"] + verdicts["UNFIXED"]
        )

        # Determine aggregate verdict
        final_verdict = "INCONCLUSIVE"
        final_confidence = 0.0

        if verdicts["FIXED"] > 0 and verdicts["UNFIXED"] == 0:
            if verdicts["FIXED"] > verdicts["LIKELY_FIXED"]:
                final_verdict = "FIXED"
                final_confidence = max(
                    r.confidence for r in applicable_results if r.verdict == "FIXED"
                )
            else:
                final_verdict = "LIKELY_FIXED"
                final_confidence = max(r.confidence for r in applicable_results)

        elif verdicts["FIXED"] > 0 and verdicts["UNFIXED"] > 0:
            final_verdict = "LIKELY_FIXED"
            final_confidence = 0.4  # Mixed signals

        elif verdicts["LIKELY_FIXED"] > 0:
            final_verdict = "LIKELY_FIXED"
            final_confidence = max(
                r.confidence for r in applicable_results if r.verdict == "LIKELY_FIXED"
            )

        elif verdicts["UNFIXED"] > 0:
            final_verdict = "UNFIXED"
            final_confidence = max(
                r.confidence for r in applicable_results if r.verdict == "UNFIXED"
            )

        else:
            final_verdict = "INCONCLUSIVE"
            final_confidence = max(r.confidence for r in applicable_results)

        # Use the best result's commit hash as representative
        best_result = max(applicable_results, key=lambda r: r.confidence)

        return MatchResult(
            cve_id=cve_id,
            commit_hash=best_result.commit_hash,
            verdict=final_verdict,
            confidence=final_confidence,
            details={
                "aggregate": True,
                "total_commits": len(results),
                "verdict_counts": {k: v for k, v in verdicts.items() if v > 0},
                "per_commit": [r.to_dict() for r in results],
            },
            string_added_matched=sum(
                r.string_added_matched for r in applicable_results
            ),
            string_added_total=sum(r.string_added_total for r in applicable_results),
            string_removed_matched=sum(
                r.string_removed_matched for r in applicable_results
            ),
            string_removed_total=sum(
                r.string_removed_total for r in applicable_results
            ),
            symbol_added_matched=sum(
                r.symbol_added_matched for r in applicable_results
            ),
            symbol_added_total=sum(r.symbol_added_total for r in applicable_results),
        )


# ---- CLI interface ----


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Match CVE fix signatures against a kernel binary"
    )
    parser.add_argument("binary", help="Path to kernel binary (vmlinux)")
    parser.add_argument("--strings-file", help="Pre-extracted strings file")
    parser.add_argument("--symbols-file", help="Pre-extracted symbols file")
    parser.add_argument("--sig-db", help="Signature database directory")
    parser.add_argument("--cve", help="Match a specific CVE")
    parser.add_argument("--commit", help="Match a specific commit hash")
    parser.add_argument(
        "--git-repo", help="Git repo for on-the-fly signature extraction"
    )
    parser.add_argument("--arch", default="x86_64", help="Target architecture")
    parser.add_argument("--no-r2", action="store_true", help="Disable radare2")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    # Determine if ELF
    is_elf = False
    try:
        with open(args.binary, "rb") as f:
            magic = f.read(4)
        is_elf = magic == b"\x7fELF"
    except IOError:
        pass

    with BinaryMatcher(
        args.binary,
        strings_file=args.strings_file,
        symbols_file=args.symbols_file,
        is_elf=is_elf,
        arch=args.arch,
        use_r2=not args.no_r2,
    ) as matcher:
        if args.commit and args.git_repo:
            # Match a single commit
            from lib.string_signatures import extract_signatures_from_commit

            sig = extract_signatures_from_commit(
                args.git_repo, args.commit, args.cve or ""
            )
            if sig is None:
                print(f"ERROR: Could not extract signature for {args.commit}")
                sys.exit(1)
            result = matcher.match_signature(sig)
            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                print(f"CVE: {result.cve_id or 'N/A'}")
                print(f"Commit: {result.commit_hash}")
                print(f"Verdict: {result.verdict}")
                print(f"Confidence: {result.confidence:.1%}")
                print(
                    f"String match: {result.string_added_matched}/{result.string_added_total} added, "
                    f"{result.string_removed_matched}/{result.string_removed_total} removed"
                )
                print(
                    f"Symbol match: {result.symbol_added_matched}/{result.symbol_added_total}"
                )
                for reason in result.details.get("reasons", []):
                    print(f"  - {reason}")

        elif args.cve and args.sig_db:
            # Match a CVE from the signature database
            from lib.signature_db import SignatureDatabase

            db = SignatureDatabase(args.sig_db)
            sigs = db.get_signatures_for_cve(args.cve)
            if not sigs:
                print(f"No signatures in database for {args.cve}")
                sys.exit(1)
            result = matcher.match_cve(sigs)
            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                print(f"CVE: {result.cve_id}")
                print(f"Verdict: {result.verdict}")
                print(f"Confidence: {result.confidence:.1%}")
                if "verdict_counts" in result.details:
                    print(f"Per-commit verdicts: {result.details['verdict_counts']}")

        else:
            print("Specify --commit with --git-repo, or --cve with --sig-db")
            sys.exit(1)


if __name__ == "__main__":
    main()
