"""
diff_parser.py — Parse unified diffs and extract changed lines per file.

A unified diff looks like this:

    diff --git a/app.py b/app.py
    --- a/app.py
    +++ b/app.py
    @@ -4,10 +4,6 @@
     context line
    -removed line    ← we collect these
    +added line      ← we collect these

We parse this into FileDiff objects so the rest of the engine can
work with structured data instead of raw text.
"""

import re
from dataclasses import dataclass, field


@dataclass
class FileDiff:
    """Represents changes to a single file in a diff."""
    path: str                                    # e.g. "app.py"
    added_lines: list[str] = field(default_factory=list)    # lines starting with +
    removed_lines: list[str] = field(default_factory=list)  # lines starting with -


def parse_diff(diff_text: str) -> list[FileDiff]:
    """
    Parse a unified diff string into a list of FileDiff objects.

    Handles both:
    - git-style diffs  (diff --git a/... b/...)
    - plain unified diffs  (--- old / +++ new)

    Returns one FileDiff per file that was changed.
    """
    file_diffs: list[FileDiff] = []
    current: FileDiff | None = None

    for line in diff_text.splitlines():
        # ── New file header (git-style) ──────────────────────────
        if line.startswith('diff --git'):
            match = re.match(r'diff --git a/(.+?) b/(.+)', line)
            if match:
                current = FileDiff(path=match.group(2))
                file_diffs.append(current)
            continue

        # ── +++ header (plain unified diffs, or confirms git path) ─
        if line.startswith('+++ '):
            if current is None:
                match = re.match(r'\+\+\+ (?:b/)?(.+)', line)
                if match and match.group(1) != '/dev/null':
                    current = FileDiff(path=match.group(1))
                    file_diffs.append(current)
            continue

        # ── Skip --- header and @@ hunk markers ─────────────────
        if line.startswith('--- ') or line.startswith('@@'):
            continue

        # ── Must have a current file to record lines ─────────────
        if current is None:
            continue

        # ── Removed line (starts with -) ─────────────────────────
        if line.startswith('-'):
            current.removed_lines.append(line[1:])  # strip the leading '-'
        # ── Added line (starts with +) ───────────────────────────
        elif line.startswith('+'):
            current.added_lines.append(line[1:])    # strip the leading '+'
        # ── Context line (starts with space) — skip ──────────────

    return file_diffs

