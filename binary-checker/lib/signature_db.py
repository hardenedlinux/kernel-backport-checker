#!/usr/bin/env python3
"""
signature_db.py

Manage a database of pre-computed fix signatures for CVEs.
Handles generation, caching, lookup, and serialization of signatures.

The signature database is a JSON file mapping CVE IDs to their fix signatures,
organized for efficient lookup during binary scanning.

Usage:
    from lib.signature_db import SignatureDatabase
    db = SignatureDatabase("/path/to/signatures")
    db.generate_for_cves(git_repo, cve_commit_pairs)
    sigs = db.get_signatures("CVE-2024-1234")
"""

import json
import os
import sys
import hashlib
from typing import Dict, List, Optional, Tuple
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.string_signatures import (
    FixSignature,
    extract_signatures_from_commit,
    batch_extract_signatures,
)


class SignatureDatabase:
    """
    Manages a persistent database of CVE fix signatures.

    Structure on disk:
        <db_dir>/
            index.json          - Master index: CVE -> [commit_hashes]
            sigs/
                <hash>.json     - Per-commit signature files
            meta.json           - Database metadata (version, generation info)
    """

    DB_VERSION = 1

    def __init__(self, db_dir: str):
        self.db_dir = Path(db_dir)
        self.sigs_dir = self.db_dir / "sigs"
        self.index_file = self.db_dir / "index.json"
        self.meta_file = self.db_dir / "meta.json"

        self._index: Dict[str, List[str]] = {}  # CVE -> [commit_hashes]
        self._sig_cache: Dict[str, FixSignature] = {}  # hash -> FixSignature

        self._ensure_dirs()
        self._load_index()

    def _ensure_dirs(self):
        """Create directory structure if needed."""
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.sigs_dir.mkdir(exist_ok=True)

    def _load_index(self):
        """Load the master index from disk."""
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r') as f:
                    self._index = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._index = {}

    def _save_index(self):
        """Save the master index to disk."""
        with open(self.index_file, 'w') as f:
            json.dump(self._index, f, indent=2)

    def _save_meta(self, git_repo: str = "", kernel_version: str = ""):
        """Save database metadata."""
        meta = {
            "version": self.DB_VERSION,
            "git_repo": git_repo,
            "kernel_version": kernel_version,
            "total_cves": len(self._index),
            "total_signatures": sum(len(v) for v in self._index.values()),
        }
        with open(self.meta_file, 'w') as f:
            json.dump(meta, f, indent=2)

    def _sig_path(self, commit_hash: str) -> Path:
        """Get the file path for a commit signature."""
        # Use first 2 chars as subdirectory for filesystem scalability
        subdir = self.sigs_dir / commit_hash[:2]
        subdir.mkdir(exist_ok=True)
        return subdir / f"{commit_hash}.json"

    def has_signature(self, commit_hash: str) -> bool:
        """Check if a signature exists for a commit."""
        return self._sig_path(commit_hash).exists()

    def get_signature(self, commit_hash: str) -> Optional[FixSignature]:
        """Load a single commit signature."""
        if commit_hash in self._sig_cache:
            return self._sig_cache[commit_hash]

        sig_file = self._sig_path(commit_hash)
        if not sig_file.exists():
            return None

        try:
            with open(sig_file, 'r') as f:
                data = json.load(f)
            sig = FixSignature.from_dict(data)
            self._sig_cache[commit_hash] = sig
            return sig
        except (json.JSONDecodeError, IOError, KeyError):
            return None

    def save_signature(self, sig: FixSignature):
        """Save a single commit signature to disk."""
        sig_file = self._sig_path(sig.commit_hash)
        with open(sig_file, 'w') as f:
            json.dump(sig.to_dict(), f, indent=1)
        self._sig_cache[sig.commit_hash] = sig

    def get_signatures_for_cve(self, cve_id: str) -> List[FixSignature]:
        """Get all fix signatures associated with a CVE."""
        commit_hashes = self._index.get(cve_id, [])
        sigs = []
        for h in commit_hashes:
            sig = self.get_signature(h)
            if sig is not None:
                sigs.append(sig)
        return sigs

    def register_cve_commit(self, cve_id: str, commit_hash: str):
        """Register a commit hash as a fix for a CVE."""
        if cve_id not in self._index:
            self._index[cve_id] = []
        if commit_hash not in self._index[cve_id]:
            self._index[cve_id].append(commit_hash)

    def generate_signature(self, git_repo: str, commit_hash: str,
                           cve_id: str = "", force: bool = False) -> Optional[FixSignature]:
        """
        Generate and store a signature for a single commit.

        Args:
            git_repo: Path to git repository
            commit_hash: Commit hash to analyze
            cve_id: CVE identifier
            force: Regenerate even if cached

        Returns:
            FixSignature or None if extraction failed
        """
        if not force and self.has_signature(commit_hash):
            return self.get_signature(commit_hash)

        sig = extract_signatures_from_commit(git_repo, commit_hash, cve_id)
        if sig is None:
            return None

        self.save_signature(sig)
        if cve_id:
            self.register_cve_commit(cve_id, commit_hash)

        return sig

    def generate_for_cves(self, git_repo: str,
                           cve_commit_pairs: List[Tuple[str, str]],
                           max_workers: int = 4,
                           force: bool = False,
                           progress_callback=None) -> Dict[str, int]:
        """
        Generate signatures for multiple CVE-commit pairs.

        Args:
            git_repo: Path to git repository
            cve_commit_pairs: List of (cve_id, commit_hash) tuples
            max_workers: Parallel workers
            force: Regenerate all even if cached
            progress_callback: Optional callback(current, total) for progress

        Returns:
            Dict with statistics: generated, cached, failed, total
        """
        stats = {"generated": 0, "cached": 0, "failed": 0, "total": len(cve_commit_pairs)}

        # Split into cached and needs-generation
        to_generate = []
        for cve_id, commit_hash in cve_commit_pairs:
            self.register_cve_commit(cve_id, commit_hash)
            if not force and self.has_signature(commit_hash):
                stats["cached"] += 1
            else:
                to_generate.append((commit_hash, cve_id))

        if progress_callback:
            progress_callback(stats["cached"], stats["total"])

        # Batch generate missing signatures
        if to_generate:
            results = batch_extract_signatures(git_repo, to_generate, max_workers)
            for commit_hash, sig in results.items():
                if sig is not None and not sig.is_empty():
                    self.save_signature(sig)
                    stats["generated"] += 1
                else:
                    stats["failed"] += 1

                if progress_callback:
                    done = stats["cached"] + stats["generated"] + stats["failed"]
                    progress_callback(done, stats["total"])

        # Handle commits that weren't in results (failed extraction)
        generated_hashes = set(h for h, _ in to_generate) - set(
            h for h in (results if to_generate else {}))
        stats["failed"] += len(generated_hashes)

        # Save index
        self._save_index()
        self._save_meta(git_repo)

        return stats

    def get_all_cves(self) -> List[str]:
        """Get all CVE IDs in the database."""
        return sorted(self._index.keys())

    def get_stats(self) -> Dict:
        """Get database statistics."""
        total_sigs = sum(len(v) for v in self._index.values())
        strengths = {"strong": 0, "moderate": 0, "weak": 0, "none": 0}

        for cve_id in self._index:
            for sig in self.get_signatures_for_cve(cve_id):
                strengths[sig.strength] += 1

        return {
            "total_cves": len(self._index),
            "total_signatures": total_sigs,
            "signature_strengths": strengths,
        }

    def export_summary(self, output_file: str):
        """Export a human-readable summary of the database."""
        stats = self.get_stats()
        with open(output_file, 'w') as f:
            f.write(f"Signature Database Summary\n")
            f.write(f"{'=' * 40}\n")
            f.write(f"Total CVEs: {stats['total_cves']}\n")
            f.write(f"Total signatures: {stats['total_signatures']}\n")
            f.write(f"Strength distribution:\n")
            for k, v in stats['signature_strengths'].items():
                f.write(f"  {k}: {v}\n")
            f.write(f"\n")

            for cve_id in sorted(self._index.keys()):
                sigs = self.get_signatures_for_cve(cve_id)
                f.write(f"\n{cve_id} ({len(sigs)} commits):\n")
                for sig in sigs:
                    f.write(f"  {sig.commit_hash[:12]} [{sig.strength}] "
                           f"strings=+{len(sig.added_strings)}/-{len(sig.removed_strings)} "
                           f"funcs=+{len(sig.added_functions)}/~{len(sig.modified_functions)} "
                           f"files={len(sig.affected_files)}\n")


# ---- CLI interface ----

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Manage CVE fix signature database'
    )
    subparsers = parser.add_subparsers(dest='command')

    # Generate command
    gen_parser = subparsers.add_parser('generate',
        help='Generate signatures from a CVE-commit mapping file')
    gen_parser.add_argument('git_repo', help='Path to git repository')
    gen_parser.add_argument('mapping_file',
        help='TSV file with CVE-ID<tab>commit-hash per line')
    gen_parser.add_argument('--db', default='./signatures',
        help='Signature database directory')
    gen_parser.add_argument('--jobs', type=int, default=4,
        help='Parallel workers')
    gen_parser.add_argument('--force', action='store_true',
        help='Regenerate all signatures')

    # Stats command
    stats_parser = subparsers.add_parser('stats',
        help='Show database statistics')
    stats_parser.add_argument('--db', default='./signatures',
        help='Signature database directory')

    # Lookup command
    lookup_parser = subparsers.add_parser('lookup',
        help='Look up signatures for a CVE')
    lookup_parser.add_argument('cve_id', help='CVE identifier')
    lookup_parser.add_argument('--db', default='./signatures',
        help='Signature database directory')
    lookup_parser.add_argument('--json', action='store_true',
        help='Output as JSON')

    args = parser.parse_args()

    if args.command == 'generate':
        db = SignatureDatabase(args.db)

        # Read mapping file
        pairs = []
        with open(args.mapping_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) >= 2:
                    pairs.append((parts[0], parts[1]))

        print(f"Generating signatures for {len(pairs)} CVE-commit pairs...")

        def progress(current, total):
            pct = (current / total * 100) if total > 0 else 0
            print(f"\r  Progress: {current}/{total} ({pct:.0f}%)", end='',
                  flush=True)

        stats = db.generate_for_cves(args.git_repo, pairs, args.jobs,
                                      args.force, progress)
        print()
        print(f"Results: generated={stats['generated']}, "
              f"cached={stats['cached']}, failed={stats['failed']}")

    elif args.command == 'stats':
        db = SignatureDatabase(args.db)
        stats = db.get_stats()
        print(f"Total CVEs: {stats['total_cves']}")
        print(f"Total signatures: {stats['total_signatures']}")
        print(f"Strength distribution:")
        for k, v in stats['signature_strengths'].items():
            print(f"  {k}: {v}")

    elif args.command == 'lookup':
        db = SignatureDatabase(args.db)
        sigs = db.get_signatures_for_cve(args.cve_id)
        if not sigs:
            print(f"No signatures found for {args.cve_id}")
            sys.exit(1)

        if args.json:
            print(json.dumps([s.to_dict() for s in sigs], indent=2))
        else:
            for sig in sigs:
                print(f"Commit: {sig.commit_hash}")
                print(f"  Strength: {sig.strength}")
                print(f"  Added strings: {len(sig.added_strings)}")
                print(f"  Removed strings: {len(sig.removed_strings)}")
                print(f"  Added functions: {sig.added_functions}")
                print(f"  Modified functions: {sig.modified_functions}")
                print(f"  Files: {sig.affected_files}")
                print()

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
