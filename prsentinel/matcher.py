"""
matcher.py — Match PR removed lines against known security fix patterns.

Core idea ("reverse matching"):
  - A security fix ADDS safety-check lines to the codebase.
  - A malicious PR REMOVES those exact lines.
  - We compare the PR's removed lines against every known fix's added
    lines, after normalization, using difflib.SequenceMatcher.
  - A high similarity score means: "this PR is undoing a known fix."
"""

import os
import json
import difflib
from dataclasses import dataclass

from .diff_parser import FileDiff
from .normalizer import normalize_block


@dataclass
class MatchResult:
    """Result of matching a PR diff against one known fix."""
    fix_id: str                         # e.g. "DEMO-001-PATH-TRAVERSAL"
    fix_description: str                # human-readable description
    fix_source: str                     # e.g. "OSV.dev", "demo"
    fix_severity: str                   # e.g. "HIGH", "CRITICAL"
    match_percentage: float             # 0.0 – 1.0
    matched_file: str                   # which file in the PR triggered this
    normalized_fix_lines: list[str]     # the fix's lines after normalization
    normalized_removed_lines: list[str] # the PR's removed lines after normalization


def load_fixes(fixes_path: str | None = None) -> list[dict]:
    """
    Load the known-fix library from fixes.json.

    If no path is given, we look next to the project root (one level
    above the prsentinel/ package).
    """
    if fixes_path is None:
        fixes_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'fixes.json',
        )
    with open(fixes_path, 'r') as f:
        return json.load(f)


def match_diff_against_fixes(
    file_diffs: list[FileDiff],
    fixes: list[dict],
    threshold: float = 0.50,
) -> list[MatchResult]:
    """
    Check every file's removed lines against every known fix.

    Args:
        file_diffs:  parsed diff (from diff_parser)
        fixes:       list of fix dicts from fixes.json
        threshold:   minimum SequenceMatcher ratio to report

    Returns:
        list of MatchResult, sorted best-match-first.
    """
    results: list[MatchResult] = []

    for fix in fixes:
        fix_lines = fix.get('fix_added_lines', [])
        if not fix_lines:
            continue

        # Normalize the fix's added lines once
        norm_fix = normalize_block(fix_lines)
        if not norm_fix:
            continue
        fix_text = '\n'.join(norm_fix)

        file_patterns = fix.get('file_patterns', [])

        for fd in file_diffs:
            if not fd.removed_lines:
                continue

            # Normalize the PR's removed lines
            norm_removed = normalize_block(fd.removed_lines)
            if not norm_removed:
                continue
            removed_text = '\n'.join(norm_removed)

            # ── Similarity via SequenceMatcher ──────────────────
            ratio = difflib.SequenceMatcher(
                None, fix_text, removed_text
            ).ratio()

            # Small boost if the filename matches a known pattern
            if _file_matches_patterns(fd.path, file_patterns):
                ratio = min(1.0, ratio * 1.15)

            if ratio >= threshold:
                results.append(MatchResult(
                    fix_id=fix['id'],
                    fix_description=fix['description'],
                    fix_source=fix.get('source', 'unknown'),
                    fix_severity=fix.get('severity', 'UNKNOWN'),
                    match_percentage=ratio,
                    matched_file=fd.path,
                    normalized_fix_lines=norm_fix,
                    normalized_removed_lines=norm_removed,
                ))

    # Best match first
    results.sort(key=lambda r: r.match_percentage, reverse=True)
    return results


def _file_matches_patterns(file_path: str, patterns: list[str]) -> bool:
    """Check if a file path matches any of the fix's file patterns."""
    if not patterns:
        return True  # no pattern ⇒ match everything
    basename = os.path.basename(file_path)
    return any(
        basename == p or file_path.endswith(p)
        for p in patterns
    )

