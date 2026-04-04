#!/usr/bin/env python3
"""
string_signatures.py

Extract string-based and constant-based fix signatures from upstream git diffs.
These signatures represent the "fingerprint" of a CVE fix that can be matched
against a kernel binary without needing source code.

Signature types extracted:
  1. New string literals (printk messages, error strings, WARN/BUG messages)
  2. New constants / magic numbers (error codes, flag values, ioctl numbers)
  3. New function names (functions added by the fix)
  4. Changed function names (renames)
  5. New error return codes (-EINVAL, -ENOMEM, etc.)

Usage:
    from lib.string_signatures import extract_signatures_from_diff
    sigs = extract_signatures_from_diff(diff_text, commit_hash)
"""

import re
import json
import sys
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict


# Common kernel error codes and their numeric values
KERNEL_ERROR_CODES = {
    "EPERM": 1,
    "ENOENT": 2,
    "ESRCH": 3,
    "EINTR": 4,
    "EIO": 5,
    "ENXIO": 6,
    "E2BIG": 7,
    "ENOEXEC": 8,
    "EBADF": 9,
    "ECHILD": 10,
    "EAGAIN": 11,
    "ENOMEM": 12,
    "EACCES": 13,
    "EFAULT": 14,
    "ENOTBLK": 15,
    "EBUSY": 16,
    "EEXIST": 17,
    "EXDEV": 18,
    "ENODEV": 19,
    "ENOTDIR": 20,
    "EISDIR": 21,
    "EINVAL": 22,
    "ENFILE": 23,
    "EMFILE": 24,
    "ENOTTY": 25,
    "ETXTBSY": 26,
    "EFBIG": 27,
    "ENOSPC": 28,
    "ESPIPE": 29,
    "EROFS": 30,
    "EMLINK": 31,
    "EPIPE": 32,
    "EDOM": 33,
    "ERANGE": 34,
    "EDEADLK": 35,
    "ENAMETOOLONG": 36,
    "ENOLCK": 37,
    "ENOSYS": 38,
    "ENOTEMPTY": 39,
    "ELOOP": 40,
    "ENOMSG": 42,
    "EIDRM": 43,
    "ENODATA": 61,
    "ETIME": 62,
    "ENOSR": 63,
    "ENONET": 64,
    "ENOLINK": 67,
    "EPROTO": 71,
    "EOVERFLOW": 75,
    "EILSEQ": 84,
    "ENOTSOCK": 88,
    "EMSGSIZE": 90,
    "EPROTOTYPE": 91,
    "ENOPROTOOPT": 92,
    "EPROTONOSUPPORT": 93,
    "EOPNOTSUPP": 95,
    "EAFNOSUPPORT": 97,
    "EADDRINUSE": 98,
    "EADDRNOTAVAIL": 99,
    "ENETDOWN": 100,
    "ENETUNREACH": 101,
    "ECONNABORTED": 103,
    "ECONNRESET": 104,
    "ENOBUFS": 105,
    "EISCONN": 106,
    "ENOTCONN": 107,
    "ETIMEDOUT": 110,
    "ECONNREFUSED": 111,
    "EHOSTUNREACH": 113,
    "EALREADY": 114,
    "EINPROGRESS": 115,
}

# Boilerplate patterns to exclude (same philosophy as source-based checker)
BOILERPLATE_STRINGS = {
    "return",
    "break",
    "continue",
    "goto",
    "else",
    "NULL",
    "true",
    "false",
    "err",
    "ret",
    "rc",
    "error",
}

# Minimum string length to consider as a signature
MIN_STRING_LENGTH = 10

# Maximum thresholds for bulk commits (subsystem removals/additions)
# Commits exceeding these are likely not targeted fixes
MAX_AFFECTED_FILES = 50
MAX_REMOVED_FUNCTIONS = 100
MAX_REMOVED_STRINGS = 200

# Patterns that indicate a kernel log/print message
LOG_PATTERNS = [
    r'pr_(?:err|warn|info|debug|notice|crit|alert|emerg)\s*\(\s*"([^"]+)"',
    r'dev_(?:err|warn|info|dbg|notice|crit|alert|emerg)\s*\([^,]+,\s*"([^"]+)"',
    r'printk\s*\(\s*(?:KERN_\w+\s+)?"([^"]+)"',
    r'WARN(?:_ONCE)?\s*\([^,]*,\s*"([^"]+)"',
    r"BUG_ON\s*\(",
    r'panic\s*\(\s*"([^"]+)"',
    r'net_(?:err|warn|info|dbg)_ratelimited\s*\(\s*"([^"]+)"',
]

# Patterns for function definitions
FUNC_DEF_PATTERNS = [
    # Standard C function definitions
    r"^(?:static\s+)?(?:inline\s+)?(?:__(?:init|exit|cold|hot|always_inline|noinline)\s+)*"
    r"(?:void|int|long|unsigned|bool|ssize_t|size_t|u[0-9]+|s[0-9]+|__[a-z0-9]+|struct\s+\w+\s*\*?)\s+"
    r"(\w+)\s*\(",
    # SYSCALL definitions
    r"SYSCALL_DEFINE\d+\s*\(\s*(\w+)",
]

# Patterns for constant definitions
CONST_PATTERNS = [
    r"#define\s+(\w+)\s+(0x[0-9a-fA-F]+|\d+)",
    r"enum\s*\{[^}]*\b(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+)",
]


@dataclass
class FixSignature:
    """Represents the binary-matchable signature of a CVE fix."""

    commit_hash: str
    cve_id: str = ""
    # Strings added by the fix (log messages, error strings)
    added_strings: List[str] = field(default_factory=list)
    # Strings removed by the fix (vulnerable code indicators)
    removed_strings: List[str] = field(default_factory=list)
    # New function names introduced
    added_functions: List[str] = field(default_factory=list)
    # Functions removed/renamed
    removed_functions: List[str] = field(default_factory=list)
    # New constants (name, value) pairs
    added_constants: List[Tuple[str, str]] = field(default_factory=list)
    # Error codes used in the fix (as negative decimal values)
    error_codes: List[int] = field(default_factory=list)
    # Files affected by the fix
    affected_files: List[str] = field(default_factory=list)
    # Functions modified by the fix (existing functions that were changed)
    modified_functions: List[str] = field(default_factory=list)
    # Raw added lines (distinctive ones, for binary string matching)
    distinctive_added_lines: List[str] = field(default_factory=list)
    # Raw removed lines
    distinctive_removed_lines: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        d = asdict(self)
        # Convert tuples back for JSON serialization
        d["added_constants"] = [[k, v] for k, v in self.added_constants]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "FixSignature":
        """Deserialize from dictionary."""
        d["added_constants"] = [tuple(x) for x in d.get("added_constants", [])]
        return cls(**d)

    def is_empty(self) -> bool:
        """Check if this signature has any useful data."""
        return (
            not self.added_strings
            and not self.removed_strings
            and not self.added_functions
            and not self.removed_functions
            and not self.added_constants
            and not self.modified_functions
            and not self.distinctive_added_lines
        )

    @property
    def strength(self) -> str:
        """Assess how strong this signature is for binary matching."""
        score = 0
        # Strings are the strongest signal in binary matching
        score += len(self.added_strings) * 3
        score += len(self.removed_strings) * 2
        # Function names are strong if symbols are available
        score += len(self.added_functions) * 3
        score += len(self.modified_functions) * 1
        # Constants help but can have false positives
        score += len(self.added_constants) * 1
        # Distinctive lines are moderate strength
        score += len(self.distinctive_added_lines) * 1

        if score >= 10:
            return "strong"
        elif score >= 4:
            return "moderate"
        elif score >= 1:
            return "weak"
        else:
            return "none"


def _is_filename_string(s: str) -> bool:
    """Check if a string looks like a source/header filename.

    These filenames are always present in the compiled binary because gcc
    embeds __FILE__ in WARN(), BUG_ON(), pr_err() etc. via macro expansion.
    Finding them in the binary proves nothing about whether a fix was applied.
    """
    # Pure filename: "foo.c", "bar.h", "baz.S", "path/to/file.c"
    if re.match(r"^[\w/._-]+\.[chS]$", s):
        return True
    # Filename with line info: "foo.c:123"
    if re.match(r"^[\w/._-]+\.[chS]:\d+$", s):
        return True
    return False


def _extract_strings_from_line(line: str) -> List[str]:
    """Extract string literals from a C source line."""
    strings = []
    # Match quoted strings, handling escaped quotes
    for match in re.finditer(r'"((?:[^"\\]|\\.)*)"', line):
        s = match.group(1)
        # Unescape
        s = s.replace("\\n", "\n").replace("\\t", "\t").replace('\\"', '"')
        # Remove format specifiers for matching (they compile to the literal)
        # But keep them for now -- the string with %d/%s etc. will still be
        # present in the binary as-is
        if len(s) >= MIN_STRING_LENGTH and s.lower() not in BOILERPLATE_STRINGS:
            # Skip filename strings — they are always present in the binary
            # via __FILE__ macro expansion and are not fix indicators
            if _is_filename_string(s):
                continue
            strings.append(s)
    return strings


def _extract_function_name(line: str) -> Optional[str]:
    """Extract function name from a function definition line."""
    for pattern in FUNC_DEF_PATTERNS:
        match = re.search(pattern, line)
        if match:
            name = match.group(1)
            # Filter out common false positives
            if name not in (
                "if",
                "for",
                "while",
                "switch",
                "return",
                "sizeof",
                "typeof",
                "offsetof",
                "__builtin_expect",
            ):
                return name
    return None


def _extract_constants(line: str) -> List[Tuple[str, str]]:
    """Extract constant definitions from a line."""
    constants = []
    for pattern in CONST_PATTERNS:
        for match in re.finditer(pattern, line):
            name = match.group(1)
            value = match.group(2)
            constants.append((name, value))
    return constants


def _extract_error_codes(line: str) -> List[int]:
    """Extract kernel error return codes from a line."""
    codes = []
    # Match patterns like "return -EINVAL;" or "err = -ENOMEM;"
    for match in re.finditer(r"-\b(E[A-Z]+)\b", line):
        ename = match.group(1)
        if ename in KERNEL_ERROR_CODES:
            codes.append(-KERNEL_ERROR_CODES[ename])
    return codes


def _is_boilerplate(line: str) -> bool:
    """Check if a line is boilerplate code that shouldn't be used as a signature."""
    stripped = line.strip()

    # Too short
    if len(stripped) < 8:
        return True

    # Pure braces, comments
    if stripped in ("{", "}", "};", "/*", "*/", "*/;"):
        return True

    # Common includes
    if stripped.startswith("#include"):
        return True

    # Common trivial statements
    trivial_patterns = [
        r"^\s*break\s*;",
        r"^\s*continue\s*;",
        r"^\s*return\s*;",
        r"^\s*return\s+0\s*;",
        r"^\s*return\s+ret\s*;",
        r"^\s*return\s+err\s*;",
        r"^\s*return\s+rc\s*;",
        r"^\s*return\s+-\d+\s*;",
        r"^\s*else\s*$",
        r"^\s*else\s*\{",
        r"^\s*\}\s*else\s*\{",
        r"^\s*goto\s+\w+\s*;",
        r"^\s*int\s+ret\s*[;=]",
        r"^\s*int\s+err\s*[;=]",
        r"^\s*int\s+rc\s*[;=]",
        r"^\s*if\s*\(\s*!\w+\s*\)",
        r"^\s*if\s*\(\s*\w+\s*==\s*NULL\s*\)",
        r"^\s*if\s*\(\s*ret\s*[<!=]",
        r"^\s*if\s*\(\s*err\s*[<!=]",
        r"^\s*mutex_lock\s*\(",
        r"^\s*mutex_unlock\s*\(",
        r"^\s*spin_lock\s*\(",
        r"^\s*spin_unlock\s*\(",
        r"^\s*rcu_read_lock\s*\(",
        r"^\s*rcu_read_unlock\s*\(",
        r"^\s*kfree\s*\(\w+\)\s*;",
        r"^\s*\*\s*$",
        r"^\s*\*\s+\w",
    ]

    for pattern in trivial_patterns:
        if re.match(pattern, stripped):
            return True

    return False


def _extract_modified_function_from_hunk_header(header: str) -> Optional[str]:
    """Extract the function name from a diff hunk header (@@ ... @@ function_name)."""
    match = re.search(r"@@.*@@\s+(?:static\s+)?(?:\w+\s+)*(\w+)\s*\(", header)
    if match:
        name = match.group(1)
        if name not in ("if", "for", "while", "switch"):
            return name
    return None


def extract_signatures_from_diff(
    diff_text: str, commit_hash: str, cve_id: str = ""
) -> FixSignature:
    """
    Extract binary-matchable signatures from a git diff.

    Args:
        diff_text: The unified diff output from git show/diff
        commit_hash: The commit hash this diff belongs to
        cve_id: Optional CVE identifier

    Returns:
        FixSignature with all extracted signatures
    """
    sig = FixSignature(commit_hash=commit_hash, cve_id=cve_id)

    current_file = None
    modified_funcs: Set[str] = set()
    added_lines: List[str] = []
    removed_lines: List[str] = []
    # Track string literals found in context (unchanged) lines.
    # Strings present in context existed before the fix and finding them
    # in the binary proves nothing about whether the fix was applied.
    context_strings: Set[str] = set()

    for line in diff_text.splitlines():
        # Track current file
        if line.startswith("diff --git"):
            match = re.search(r" b/(.+)$", line)
            if match:
                current_file = match.group(1)
                if current_file not in sig.affected_files:
                    sig.affected_files.append(current_file)
            continue

        # Track modified functions from hunk headers
        if line.startswith("@@"):
            func_name = _extract_modified_function_from_hunk_header(line)
            if func_name:
                modified_funcs.add(func_name)
            continue

        # Collect strings from context (unchanged) lines
        if line and line[0] == " ":
            for s in _extract_strings_from_line(line):
                context_strings.add(s)
            continue

        # Process added lines
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]  # Strip the leading '+'

            # Extract string literals
            for s in _extract_strings_from_line(content):
                if s not in sig.added_strings:
                    sig.added_strings.append(s)

            # Extract function definitions (new functions)
            func_name = _extract_function_name(content)
            if func_name and func_name not in sig.added_functions:
                sig.added_functions.append(func_name)

            # Extract constants
            for const in _extract_constants(content):
                if const not in sig.added_constants:
                    sig.added_constants.append(const)

            # Extract error codes
            for code in _extract_error_codes(content):
                if code not in sig.error_codes:
                    sig.error_codes.append(code)

            # Track distinctive added lines
            if not _is_boilerplate(content) and len(content.strip()) >= 10:
                added_lines.append(content.strip())

        # Process removed lines
        elif line.startswith("-") and not line.startswith("---"):
            content = line[1:]

            # Extract string literals that were removed
            for s in _extract_strings_from_line(content):
                if s not in sig.removed_strings:
                    sig.removed_strings.append(s)

            # Extract removed function definitions
            func_name = _extract_function_name(content)
            if func_name and func_name not in sig.removed_functions:
                sig.removed_functions.append(func_name)

            # Track distinctive removed lines
            if not _is_boilerplate(content) and len(content.strip()) >= 10:
                removed_lines.append(content.strip())

    sig.modified_functions = sorted(modified_funcs)

    # Filter out pre-existing strings: if a string appears in both added
    # lines and context (unchanged) lines, it existed before the fix.
    # Finding it in the binary does not indicate the fix was applied.
    if context_strings:
        sig.added_strings = [s for s in sig.added_strings if s not in context_strings]
        sig.removed_strings = [
            s for s in sig.removed_strings if s not in context_strings
        ]

    # Filter distinctive lines: remove duplicates between added and removed
    # (these are just moved lines, not actual changes)
    added_set = set(added_lines)
    removed_set = set(removed_lines)
    moved = added_set & removed_set

    sig.distinctive_added_lines = [l for l in added_lines if l not in moved]
    sig.distinctive_removed_lines = [l for l in removed_lines if l not in moved]

    # Also detect function renames: if a function was removed and a similar one added
    for rfunc in sig.removed_functions[:]:
        for afunc in sig.added_functions[:]:
            # Simple heuristic: if they share a common prefix/suffix
            if rfunc != afunc and (
                rfunc in afunc
                or afunc in rfunc
                or _common_prefix_len(rfunc, afunc) > len(rfunc) // 2
            ):
                # This is likely a rename, not a true add/remove
                pass  # Keep both for now, binary matcher can use either

    # Filter out bulk commits (subsystem removals/additions) that produce
    # massive signature data with no discriminative value.
    # These commits modify 50+ files or remove 100+ functions/200+ strings
    # and are likely not targeted security fixes.
    if (
        len(sig.affected_files) > MAX_AFFECTED_FILES
        or len(sig.removed_functions) > MAX_REMOVED_FUNCTIONS
        or len(sig.removed_strings) > MAX_REMOVED_STRINGS
    ):
        # Keep only the metadata (affected files, modified functions) but
        # clear the bulk data that causes false positives
        sig.removed_strings = []
        sig.removed_functions = []
        sig.distinctive_removed_lines = []
        # Also cap added data from bulk commits
        if len(sig.added_strings) > MAX_REMOVED_STRINGS:
            sig.added_strings = []
            sig.added_functions = []
            sig.distinctive_added_lines = []

    return sig


def _common_prefix_len(a: str, b: str) -> int:
    """Return the length of the common prefix of two strings."""
    i = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            break
        i += 1
    return i


def extract_signatures_from_commit(
    git_repo_path: str, commit_hash: str, cve_id: str = ""
) -> Optional[FixSignature]:
    """
    Extract signatures directly from a git repository commit.

    Args:
        git_repo_path: Path to the git repository
        commit_hash: Commit hash to analyze
        cve_id: Optional CVE identifier

    Returns:
        FixSignature or None if the commit cannot be found
    """
    import subprocess

    try:
        result = subprocess.run(
            ["git", "-C", git_repo_path, "show", "--format=", commit_hash],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return None

        return extract_signatures_from_diff(result.stdout, commit_hash, cve_id)

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def batch_extract_signatures(
    git_repo_path: str, commit_cve_pairs: List[Tuple[str, str]], max_workers: int = 4
) -> Dict[str, FixSignature]:
    """
    Extract signatures for multiple commits in batch.

    Args:
        git_repo_path: Path to the git repository
        commit_cve_pairs: List of (commit_hash, cve_id) tuples
        max_workers: Number of parallel workers

    Returns:
        Dict mapping commit_hash to FixSignature
    """
    import subprocess
    from concurrent.futures import ThreadPoolExecutor

    results = {}

    def process_one(pair):
        commit_hash, cve_id = pair
        sig = extract_signatures_from_commit(git_repo_path, commit_hash, cve_id)
        return commit_hash, sig

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for commit_hash, sig in executor.map(process_one, commit_cve_pairs):
            if sig is not None:
                results[commit_hash] = sig

    return results


# ---- CLI interface ----


def main():
    """CLI interface for extracting signatures from a single commit."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract binary-matchable fix signatures from a git commit"
    )
    parser.add_argument("git_repo", help="Path to git repository")
    parser.add_argument("commit_hash", help="Commit hash to analyze")
    parser.add_argument("--cve", default="", help="CVE identifier")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--diff-file", help="Read diff from file instead of git")

    args = parser.parse_args()

    if args.diff_file:
        with open(args.diff_file, "r") as f:
            diff_text = f.read()
        sig = extract_signatures_from_diff(diff_text, args.commit_hash, args.cve)
    else:
        sig = extract_signatures_from_commit(args.git_repo, args.commit_hash, args.cve)

    if sig is None:
        print(f"ERROR: Could not extract diff for {args.commit_hash}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps(sig.to_dict(), indent=2))
    else:
        print(f"Commit: {sig.commit_hash}")
        print(f"CVE: {sig.cve_id or 'N/A'}")
        print(f"Strength: {sig.strength}")
        print(f"Affected files: {len(sig.affected_files)}")
        print(f"  {', '.join(sig.affected_files[:5])}")
        print(f"Added strings ({len(sig.added_strings)}):")
        for s in sig.added_strings[:10]:
            print(f'  + "{s[:80]}"')
        print(f"Removed strings ({len(sig.removed_strings)}):")
        for s in sig.removed_strings[:10]:
            print(f'  - "{s[:80]}"')
        print(f"Added functions ({len(sig.added_functions)}):")
        for f in sig.added_functions:
            print(f"  + {f}()")
        print(f"Modified functions ({len(sig.modified_functions)}):")
        for f in sig.modified_functions:
            print(f"  ~ {f}()")
        print(f"Added constants ({len(sig.added_constants)}):")
        for name, val in sig.added_constants[:10]:
            print(f"  + {name} = {val}")
        print(f"Distinctive added lines: {len(sig.distinctive_added_lines)}")
        print(f"Distinctive removed lines: {len(sig.distinctive_removed_lines)}")


if __name__ == "__main__":
    main()
