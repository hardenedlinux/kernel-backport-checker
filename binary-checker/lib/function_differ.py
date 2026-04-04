#!/usr/bin/env python3
"""
function_differ.py

Function-level binary comparison between a target kernel binary and a
reference ("gold image") kernel. Used to determine if specific functions
have been patched by comparing their binary representations.

This module provides Approach B from the architecture design: build a
reference kernel matching the target version, apply a CVE fix, and compare
the changed functions against the target binary.

Analysis methods:
  1. Function size comparison (quick heuristic)
  2. Control flow graph (CFG) topology comparison
  3. Instruction mnemonic sequence comparison
  4. String reference comparison within functions
  5. Call target comparison

Requires: radare2 with r2pipe, or Ghidra headless (optional)

Usage:
    from lib.function_differ import FunctionDiffer
    differ = FunctionDiffer(target_binary, reference_binary)
    similarity = differ.compare_function("vulnerable_function_name")
"""

import os
import sys
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass
class FunctionInfo:
    """Extracted information about a single function."""
    name: str
    address: int = 0
    size: int = 0
    num_basic_blocks: int = 0
    num_edges: int = 0
    num_calls: int = 0
    call_targets: List[str] = field(default_factory=list)
    string_refs: List[str] = field(default_factory=list)
    mnemonics: List[str] = field(default_factory=list)
    # Hash of the mnemonic sequence for quick comparison
    mnemonic_hash: str = ""
    # Basic block sizes for topology comparison
    bb_sizes: List[int] = field(default_factory=list)

    def compute_mnemonic_hash(self):
        """Compute a hash of the instruction mnemonic sequence."""
        h = hashlib.sha256(' '.join(self.mnemonics).encode()).hexdigest()[:16]
        self.mnemonic_hash = h


@dataclass
class FunctionComparison:
    """Result of comparing a function between target and reference."""
    function_name: str
    target_present: bool = False
    reference_present: bool = False
    # Similarity scores (0.0 - 1.0)
    size_similarity: float = 0.0
    cfg_similarity: float = 0.0
    mnemonic_similarity: float = 0.0
    string_ref_similarity: float = 0.0
    call_similarity: float = 0.0
    # Overall similarity
    overall_similarity: float = 0.0
    # Which reference it's more similar to
    closer_to: str = "unknown"  # "unpatched" or "patched"
    details: Dict = field(default_factory=dict)


class FunctionAnalyzer:
    """
    Analyze functions in a binary using radare2.

    Provides function-level information extraction for comparison.
    """

    def __init__(self, binary_path: str, arch: str = "x86_64"):
        self.binary_path = binary_path
        self.arch = arch
        self._r2 = None
        self._analyzed = False
        self._function_cache: Dict[str, FunctionInfo] = {}

    def _ensure_r2(self):
        """Initialize r2pipe session if needed."""
        if self._r2 is not None:
            return

        try:
            import r2pipe
            self._r2 = r2pipe.open(self.binary_path, flags=['-2'])
        except ImportError:
            raise RuntimeError(
                "r2pipe is required for function-level analysis. "
                "Install with: pip install r2pipe"
            )

    def _ensure_analyzed(self):
        """Run analysis if not already done."""
        if self._analyzed:
            return

        self._ensure_r2()
        print(f"[function_differ] Analyzing {self.binary_path}...", file=sys.stderr)
        # Use 'aaa' for thorough analysis (slower but more accurate)
        self._r2.cmd('aaa')
        self._analyzed = True

    def get_function_list(self) -> List[str]:
        """Get list of all detected function names."""
        self._ensure_analyzed()
        result = self._r2.cmdj('aflj') or []
        return [f.get('name', '') for f in result if f.get('name')]

    def get_function_info(self, name: str) -> Optional[FunctionInfo]:
        """Extract detailed information about a function."""
        if name in self._function_cache:
            return self._function_cache[name]

        self._ensure_analyzed()

        # Seek to function
        self._r2.cmd(f's sym.{name}')

        # Get function info
        func_json = self._r2.cmdj(f'afij sym.{name}')
        if not func_json or len(func_json) == 0:
            # Try without sym. prefix
            self._r2.cmd(f's {name}')
            func_json = self._r2.cmdj(f'afij {name}')
            if not func_json or len(func_json) == 0:
                return None

        finfo = func_json[0]
        info = FunctionInfo(
            name=name,
            address=finfo.get('offset', 0),
            size=finfo.get('size', 0),
            num_basic_blocks=finfo.get('nbbs', 0),
            num_edges=finfo.get('edges', 0),
            num_calls=finfo.get('callrefs', 0) if isinstance(finfo.get('callrefs'), int)
                      else len(finfo.get('callrefs', [])),
        )

        # Get disassembly (mnemonics only)
        try:
            disasm = self._r2.cmdj(f'pdfj @ sym.{name}') or self._r2.cmdj(f'pdfj @ {name}')
            if disasm and 'ops' in disasm:
                for op in disasm['ops']:
                    if 'disasm' in op:
                        # Extract just the mnemonic (first word)
                        mnemonic = op['disasm'].split()[0] if op['disasm'] else ''
                        if mnemonic:
                            info.mnemonics.append(mnemonic)

                    # Extract string references
                    if 'refs' in op:
                        for ref in op['refs']:
                            if ref.get('type') == 'STRING':
                                info.string_refs.append(ref.get('name', ''))

                    # Extract call targets
                    if op.get('type') == 'call' and 'jump' in op:
                        # Resolve call target name
                        target_name = self._r2.cmd(f'fd {op["jump"]}').strip()
                        if target_name:
                            info.call_targets.append(target_name)
        except Exception:
            pass

        # Get basic block info
        try:
            bbs = self._r2.cmdj(f'afbj @ sym.{name}') or self._r2.cmdj(f'afbj @ {name}')
            if bbs:
                info.bb_sizes = [bb.get('size', 0) for bb in bbs]
                info.num_basic_blocks = len(bbs)
        except Exception:
            pass

        info.compute_mnemonic_hash()
        self._function_cache[name] = info
        return info

    def close(self):
        """Clean up r2 session."""
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


class FunctionDiffer:
    """
    Compare functions between a target binary and reference binaries.

    Used with the "gold image" approach: build an unpatched reference kernel,
    apply a CVE fix to create a patched reference, then determine which
    version the target's function is closer to.
    """

    def __init__(self, target_binary: str,
                 unpatched_reference: Optional[str] = None,
                 patched_reference: Optional[str] = None,
                 arch: str = "x86_64"):
        """
        Args:
            target_binary: The kernel binary to analyze
            unpatched_reference: Reference binary WITHOUT the fix applied
            patched_reference: Reference binary WITH the fix applied
            arch: Target architecture
        """
        self.target = FunctionAnalyzer(target_binary, arch)
        self.unpatched = (FunctionAnalyzer(unpatched_reference, arch)
                         if unpatched_reference else None)
        self.patched = (FunctionAnalyzer(patched_reference, arch)
                       if patched_reference else None)

    def close(self):
        """Clean up all analyzers."""
        self.target.close()
        if self.unpatched:
            self.unpatched.close()
        if self.patched:
            self.patched.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @staticmethod
    def _size_similarity(a: int, b: int) -> float:
        """Compare two function sizes."""
        if a == 0 and b == 0:
            return 1.0
        if a == 0 or b == 0:
            return 0.0
        return 1.0 - abs(a - b) / max(a, b)

    @staticmethod
    def _list_similarity(a: List, b: List) -> float:
        """Compare two lists using Jaccard similarity."""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        set_a, set_b = set(a), set(b)
        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        return intersection / union if union > 0 else 0.0

    @staticmethod
    def _sequence_similarity(a: List[str], b: List[str]) -> float:
        """
        Compare two sequences using a simplified LCS-based similarity.

        For performance, uses a windowed approach rather than full LCS
        on very long sequences.
        """
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0

        # For short sequences, use exact comparison
        if len(a) < 100 and len(b) < 100:
            # Simple: count matching elements at same positions
            matches = sum(1 for x, y in zip(a, b) if x == y)
            return matches / max(len(a), len(b))

        # For long sequences, use n-gram similarity
        n = 4
        def ngrams(seq, n):
            return set(tuple(seq[i:i+n]) for i in range(len(seq)-n+1))

        grams_a = ngrams(a, n)
        grams_b = ngrams(b, n)
        if not grams_a or not grams_b:
            return 0.0

        intersection = len(grams_a & grams_b)
        union = len(grams_a | grams_b)
        return intersection / union if union > 0 else 0.0

    def compare_function(self, func_name: str) -> FunctionComparison:
        """
        Compare a specific function across target and reference binaries.

        Returns similarity scores and determines which reference the target
        function is closer to.
        """
        result = FunctionComparison(function_name=func_name)

        target_info = self.target.get_function_info(func_name)
        if target_info is None:
            result.target_present = False
            result.details["error"] = f"Function '{func_name}' not found in target"
            return result
        result.target_present = True

        # Compare against unpatched reference
        unpatched_sim = 0.0
        if self.unpatched:
            unpatched_info = self.unpatched.get_function_info(func_name)
            if unpatched_info:
                result.reference_present = True
                unpatched_sim = self._compute_similarity(target_info, unpatched_info)
                result.details["unpatched_similarity"] = round(unpatched_sim, 4)

        # Compare against patched reference
        patched_sim = 0.0
        if self.patched:
            patched_info = self.patched.get_function_info(func_name)
            if patched_info:
                result.reference_present = True
                patched_sim = self._compute_similarity(target_info, patched_info)
                result.details["patched_similarity"] = round(patched_sim, 4)

        # Determine which reference is closer
        if self.unpatched and self.patched:
            if patched_sim > unpatched_sim + 0.05:  # 5% threshold
                result.closer_to = "patched"
            elif unpatched_sim > patched_sim + 0.05:
                result.closer_to = "unpatched"
            else:
                result.closer_to = "ambiguous"
            result.overall_similarity = max(patched_sim, unpatched_sim)
        elif self.patched:
            result.overall_similarity = patched_sim
            result.closer_to = "patched" if patched_sim > 0.8 else "unknown"
        elif self.unpatched:
            result.overall_similarity = unpatched_sim
            result.closer_to = "unpatched" if unpatched_sim > 0.8 else "unknown"

        return result

    def _compute_similarity(self, a: FunctionInfo, b: FunctionInfo) -> float:
        """Compute overall similarity between two function infos."""
        scores = {}

        # Size similarity (weight: 0.1)
        scores['size'] = self._size_similarity(a.size, b.size)

        # CFG topology similarity (weight: 0.2)
        cfg_sim = self._size_similarity(a.num_basic_blocks, b.num_basic_blocks)
        if a.bb_sizes and b.bb_sizes:
            cfg_sim = (cfg_sim + self._sequence_similarity(
                [str(s) for s in sorted(a.bb_sizes)],
                [str(s) for s in sorted(b.bb_sizes)]
            )) / 2
        scores['cfg'] = cfg_sim

        # Mnemonic sequence similarity (weight: 0.35)
        if a.mnemonic_hash == b.mnemonic_hash and a.mnemonic_hash:
            scores['mnemonics'] = 1.0
        else:
            scores['mnemonics'] = self._sequence_similarity(a.mnemonics, b.mnemonics)

        # String reference similarity (weight: 0.15)
        scores['strings'] = self._list_similarity(a.string_refs, b.string_refs)

        # Call target similarity (weight: 0.2)
        scores['calls'] = self._list_similarity(a.call_targets, b.call_targets)

        # Weighted average
        weights = {
            'size': 0.10,
            'cfg': 0.20,
            'mnemonics': 0.35,
            'strings': 0.15,
            'calls': 0.20,
        }

        overall = sum(scores[k] * weights[k] for k in weights)
        return overall

    def compare_functions_batch(self, func_names: List[str]) -> List[FunctionComparison]:
        """Compare multiple functions."""
        return [self.compare_function(name) for name in func_names]


# ---- CLI interface ----

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Compare functions between target and reference kernel binaries'
    )
    parser.add_argument('target', help='Target kernel binary')
    parser.add_argument('--unpatched', help='Unpatched reference binary')
    parser.add_argument('--patched', help='Patched reference binary')
    parser.add_argument('--functions', nargs='+', help='Function names to compare')
    parser.add_argument('--arch', default='x86_64', help='Architecture')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--list-functions', action='store_true',
                       help='List all functions in target binary')

    args = parser.parse_args()

    if args.list_functions:
        with FunctionAnalyzer(args.target, args.arch) as analyzer:
            funcs = analyzer.get_function_list()
            for f in sorted(funcs):
                print(f)
            print(f"\nTotal: {len(funcs)} functions", file=sys.stderr)
        return

    if not args.functions:
        print("Specify --functions or --list-functions", file=sys.stderr)
        sys.exit(1)

    with FunctionDiffer(args.target, args.unpatched, args.patched, args.arch) as differ:
        results = differ.compare_functions_batch(args.functions)

        if args.json:
            output = []
            for r in results:
                output.append({
                    'function': r.function_name,
                    'target_present': r.target_present,
                    'reference_present': r.reference_present,
                    'closer_to': r.closer_to,
                    'overall_similarity': round(r.overall_similarity, 4),
                    'details': r.details,
                })
            print(json.dumps(output, indent=2))
        else:
            for r in results:
                print(f"Function: {r.function_name}")
                print(f"  Present in target: {r.target_present}")
                if r.target_present:
                    print(f"  Closer to: {r.closer_to}")
                    print(f"  Overall similarity: {r.overall_similarity:.1%}")
                    if 'unpatched_similarity' in r.details:
                        print(f"  vs unpatched: {r.details['unpatched_similarity']:.1%}")
                    if 'patched_similarity' in r.details:
                        print(f"  vs patched: {r.details['patched_similarity']:.1%}")
                print()


if __name__ == '__main__':
    main()
