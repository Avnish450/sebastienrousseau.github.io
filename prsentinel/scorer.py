"""
scorer.py — Calculate a 0-100 risk score with explainable breakdown.

Scoring breakdown (max 100):
  ┌────────────────────────────────────┬──────────┐
  │ Signal                             │ Max pts  │
  ├────────────────────────────────────┼──────────┤
  │ Reverse match with a known fix     │ 60       │
  │ Account under 30 days old          │ 15       │
  │ First-time contributor             │ 10       │
  │ Touches security-sensitive files   │ 10       │
  │ "Clean-up" title + removing checks │  5       │
  └────────────────────────────────────┴──────────┘

Risk levels:
  0-39  → LOW      (green)
  40-69 → MEDIUM   (yellow)
  70-100→ HIGH     (red)
"""

import re
from dataclasses import dataclass

from .matcher import MatchResult


# ── Patterns for security-sensitive file names ──────────────────
SECURITY_FILE_PATTERNS = [
    r'auth', r'login', r'password', r'passwd', r'token', r'secret',
    r'crypt', r'security', r'permission', r'access', r'sanitiz',
    r'escap', r'validat', r'firewall', r'ssl', r'tls', r'cert',
    r'session', r'cookie', r'csrf', r'xss', r'inject',
    r'traversal', r'path.*check', r'middleware',
]

# ── PR title patterns suggesting a disguised change ─────────────
CLEANUP_TITLE_PATTERNS = [
    r'clean[\s\-_]?up', r'refactor', r'tidy', r'minor', r'style',
    r'format', r'lint', r'whitespace', r'typo', r'cosmetic',
    r'nit', r'small\s+fix', r'trivial', r'housekeeping',
]


@dataclass
class ScoreBreakdown:
    """Detailed, explainable breakdown of the risk score."""
    total_score: int = 0
    risk_level: str = 'LOW'   # LOW / MEDIUM / HIGH

    # ── Individual signal scores and human-readable details ──
    reverse_match_score: int = 0
    reverse_match_detail: str = ''

    account_age_score: int = 0
    account_age_detail: str = ''

    first_time_score: int = 0
    first_time_detail: str = ''

    sensitive_files_score: int = 0
    sensitive_files_detail: str = ''

    cleanup_disguise_score: int = 0
    cleanup_disguise_detail: str = ''

    # The best-matching fix (if any)
    best_match: MatchResult | None = None

    def compute_total(self):
        """Sum all components and determine the risk level."""
        self.total_score = min(100, (
            self.reverse_match_score
            + self.account_age_score
            + self.first_time_score
            + self.sensitive_files_score
            + self.cleanup_disguise_score
        ))
        if self.total_score >= 70:
            self.risk_level = 'HIGH'
        elif self.total_score >= 40:
            self.risk_level = 'MEDIUM'
        else:
            self.risk_level = 'LOW'


def calculate_score(
    matches: list[MatchResult],
    author_age_days: int | None = None,
    is_first_time: bool = False,
    changed_files: list[str] | None = None,
    pr_title: str = '',
) -> ScoreBreakdown:
    """
    Score a PR from 0 to 100.

    Each signal is independent and adds points.  The final score is
    capped at 100 and bucketed into LOW / MEDIUM / HIGH.
    """
    bd = ScoreBreakdown()

    # ── 1. Reverse match (up to 60 pts) ─────────────────────────
    if matches:
        best = matches[0]
        bd.best_match = best
        bd.reverse_match_score = int(60 * best.match_percentage)
        pct = int(best.match_percentage * 100)
        bd.reverse_match_detail = (
            f"{pct}% match with fix {best.fix_id} "
            f"(\"{best.fix_description}\"), reversed in {best.matched_file}"
        )
    else:
        bd.reverse_match_detail = 'No known fix reversal detected'

    # ── 2. Account age (15 pts if < 30 days) ────────────────────
    if author_age_days is not None and author_age_days < 30:
        bd.account_age_score = 15
        bd.account_age_detail = (
            f"Account is only {author_age_days} day(s) old (< 30 days)"
        )
    elif author_age_days is not None:
        bd.account_age_detail = (
            f"Account is {author_age_days} days old (established)"
        )
    else:
        bd.account_age_detail = 'Account age unknown'

    # ── 3. First-time contributor (10 pts) ──────────────────────
    if is_first_time:
        bd.first_time_score = 10
        bd.first_time_detail = 'First-time contributor to this repository'
    else:
        bd.first_time_detail = 'Not a first-time contributor'

    # ── 4. Security-sensitive files (10 pts) ────────────────────
    if changed_files:
        sensitive = _find_sensitive_files(changed_files)
        if sensitive:
            bd.sensitive_files_score = 10
            bd.sensitive_files_detail = (
                f"Touches security-sensitive files: {', '.join(sensitive)}"
            )
        else:
            bd.sensitive_files_detail = 'No security-sensitive files touched'
    else:
        bd.sensitive_files_detail = 'File list not available'

    # ── 5. "Clean-up" disguise (5 pts) ──────────────────────────
    if pr_title and matches and bd.reverse_match_score > 0:
        if _is_cleanup_title(pr_title):
            bd.cleanup_disguise_score = 5
            bd.cleanup_disguise_detail = (
                f"PR titled \"{pr_title}\" disguises security-relevant "
                f"changes as routine maintenance"
            )
        else:
            bd.cleanup_disguise_detail = 'PR title does not suggest disguise'
    else:
        bd.cleanup_disguise_detail = 'PR title not available or no match found'

    bd.compute_total()
    return bd


# ── Helpers ──────────────────────────────────────────────────────

def _find_sensitive_files(file_paths: list[str]) -> list[str]:
    """Return file paths that match security-sensitive patterns."""
    sensitive = []
    for fp in file_paths:
        fp_lower = fp.lower()
        for pat in SECURITY_FILE_PATTERNS:
            if re.search(pat, fp_lower):
                sensitive.append(fp)
                break
    return sensitive


def _is_cleanup_title(title: str) -> bool:
    """True if the PR title looks like routine clean-up / refactor."""
    title_lower = title.lower()
    return any(re.search(p, title_lower) for p in CLEANUP_TITLE_PATTERNS)

