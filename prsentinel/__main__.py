"""
PRSentinel CLI — run with:  python -m prsentinel

Two modes:
  CLI mode:     python -m prsentinel --diff malicious.diff --author-age-days 6 --first-time
  GitHub mode:  python -m prsentinel --github   (inside a GitHub Action)
"""

import argparse
import json
import os
import sys

from .diff_parser import parse_diff
from .matcher import load_fixes, match_diff_against_fixes
from .scorer import calculate_score
from .explainer import generate_explanation, format_pr_comment
from .github_client import (
    get_pr_diff,
    get_pr_info,
    get_user_age_days,
    is_first_time_contributor,
    post_or_update_comment,
)


# ─────────────────────────────────────────────────────────────────
#  Core analysis pipeline (used by BOTH modes)
# ─────────────────────────────────────────────────────────────────

def analyze(
    diff_text: str,
    author_age_days: int | None = None,
    is_first_time: bool = False,
    pr_title: str = '',
    fixes_path: str | None = None,
) -> dict:
    """
    Run the full PRSentinel analysis pipeline.

    Returns a dict with keys:
      breakdown   — ScoreBreakdown dataclass
      explanation — plain-English string
      comment     — full Markdown PR comment
      json        — dict ready for JSON serialization
    """
    # Step 1: parse the diff
    file_diffs = parse_diff(diff_text)
    changed_files = [fd.path for fd in file_diffs]

    # Step 2: load known fixes
    fixes = load_fixes(fixes_path)

    # Step 3: match removed lines against known fix added lines
    matches = match_diff_against_fixes(file_diffs, fixes)

    # Step 4: score
    breakdown = calculate_score(
        matches=matches,
        author_age_days=author_age_days,
        is_first_time=is_first_time,
        changed_files=changed_files,
        pr_title=pr_title,
    )

    # Step 5: explain
    explanation = generate_explanation(breakdown, diff_text)

    # Step 6: format PR comment
    comment = format_pr_comment(breakdown, explanation)

    # JSON-serializable output
    json_output = {
        'score': breakdown.total_score,
        'risk_level': breakdown.risk_level,
        'signals': {
            'reverse_match': {
                'score': breakdown.reverse_match_score,
                'max': 60,
                'detail': breakdown.reverse_match_detail,
            },
            'account_age': {
                'score': breakdown.account_age_score,
                'max': 15,
                'detail': breakdown.account_age_detail,
            },
            'first_time': {
                'score': breakdown.first_time_score,
                'max': 10,
                'detail': breakdown.first_time_detail,
            },
            'sensitive_files': {
                'score': breakdown.sensitive_files_score,
                'max': 10,
                'detail': breakdown.sensitive_files_detail,
            },
            'cleanup_disguise': {
                'score': breakdown.cleanup_disguise_score,
                'max': 5,
                'detail': breakdown.cleanup_disguise_detail,
            },
        },
        'explanation': explanation,
        'changed_files': changed_files,
        'matches': [
            {
                'fix_id': m.fix_id,
                'match_pct': round(m.match_percentage * 100, 1),
                'file': m.matched_file,
            }
            for m in matches
        ],
    }

    return {
        'breakdown': breakdown,
        'explanation': explanation,
        'comment': comment,
        'json': json_output,
    }


# ─────────────────────────────────────────────────────────────────
#  CLI mode
# ─────────────────────────────────────────────────────────────────

def run_cli_mode(args):
    """Analyze a local .diff file and print a report."""

    if not os.path.exists(args.diff):
        print(f'❌ Diff file not found: {args.diff}', file=sys.stderr)
        sys.exit(1)

    with open(args.diff, 'r') as f:
        diff_text = f.read()

    result = analyze(
        diff_text=diff_text,
        author_age_days=args.author_age_days,
        is_first_time=args.first_time,
        pr_title=args.pr_title,
        fixes_path=args.fixes,
    )

    if args.output_json:
        print(json.dumps(result['json'], indent=2))
        return

    bd = result['breakdown']
    emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}[bd.risk_level]

    print()
    print('=' * 64)
    print('  🛡️  PRSentinel Security Report')
    print('=' * 64)
    print()
    print(f'  {emoji}  Score: {bd.total_score} / 100 — {bd.risk_level} RISK')
    print()
    print('  Score Breakdown:')
    print(f'    Fix reversal:           {bd.reverse_match_score:>2}/60  '
          f'{bd.reverse_match_detail}')
    print(f'    New account:            {bd.account_age_score:>2}/15  '
          f'{bd.account_age_detail}')
    print(f'    First-time contributor: {bd.first_time_score:>2}/10  '
          f'{bd.first_time_detail}')
    print(f'    Sensitive files:        {bd.sensitive_files_score:>2}/10  '
          f'{bd.sensitive_files_detail}')
    print(f'    Cleanup disguise:       {bd.cleanup_disguise_score:>2}/5   '
          f'{bd.cleanup_disguise_detail}')
    print()
    print('  Explanation:')
    for sentence in result['explanation'].split('. '):
        s = sentence.strip()
        if s:
            print(f'    {s}.')
    print()
    print('=' * 64)


# ─────────────────────────────────────────────────────────────────
#  GitHub Action mode
# ─────────────────────────────────────────────────────────────────

def run_github_mode(args):
    """Run inside a GitHub Action: fetch PR, analyze, post comment."""

    token = os.environ.get('GITHUB_TOKEN')
    if not token:
        print('❌ GITHUB_TOKEN not set', file=sys.stderr)
        sys.exit(1)

    event_path = os.environ.get('GITHUB_EVENT_PATH')
    if not event_path:
        print('❌ GITHUB_EVENT_PATH not set', file=sys.stderr)
        sys.exit(1)

    with open(event_path, 'r') as f:
        event = json.load(f)

    pr = event.get('pull_request', {})
    pr_number = pr.get('number')
    repo = event.get('repository', {}).get('full_name')

    if not pr_number or not repo:
        print('❌ Cannot determine PR number or repository', file=sys.stderr)
        sys.exit(1)

    pr_title = pr.get('title', '')
    author = pr.get('user', {}).get('login', '')
    author_association = pr.get('author_association', '')

    print(f'🛡️  PRSentinel analyzing PR #{pr_number} on {repo}')
    print(f'   Title:  {pr_title}')
    print(f'   Author: {author}')

    # Fetch diff
    diff_text = get_pr_diff(repo, pr_number, token)

    # Account age
    author_age_days = None
    if author:
        try:
            author_age_days = get_user_age_days(author, token)
            print(f'   Account age: {author_age_days} days')
        except Exception as e:
            print(f'   ⚠️  Could not fetch account age: {e}')

    first_time = is_first_time_contributor(author_association)
    if first_time:
        print('   ⚠️  First-time contributor')

    # Analyze
    result = analyze(
        diff_text=diff_text,
        author_age_days=author_age_days,
        is_first_time=first_time,
        pr_title=pr_title,
        fixes_path=args.fixes,
    )

    # Post comment
    comment = format_pr_comment(result['breakdown'], result['explanation'])
    try:
        post_or_update_comment(repo, pr_number, token, comment)
        print(f'\n✅ Comment posted on PR #{pr_number}')
    except Exception as e:
        print(f'\n❌ Failed to post comment: {e}', file=sys.stderr)
        print(comment)
        sys.exit(1)

    bd = result['breakdown']
    print(f'\n🛡️  Result: {bd.total_score}/100 — {bd.risk_level} RISK')

    # Write GitHub Actions output variables
    output_file = os.environ.get('GITHUB_OUTPUT')
    if output_file:
        with open(output_file, 'a') as f:
            f.write(f'score={bd.total_score}\n')
            f.write(f'risk_level={bd.risk_level}\n')


# ─────────────────────────────────────────────────────────────────
#  Argument parser & entry point
# ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog='prsentinel',
        description='🛡️ PRSentinel — The security guard for the code behind our apps.',
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--diff', type=str,
                      help='Path to a .diff file to analyze (CLI mode)')
    mode.add_argument('--github', action='store_true',
                      help='Run in GitHub Action mode (reads env vars)')

    parser.add_argument('--author-age-days', type=int, default=None,
                        help='Age of the PR author\'s account in days')
    parser.add_argument('--first-time', action='store_true',
                        help='Mark the author as a first-time contributor')
    parser.add_argument('--pr-title', type=str, default='',
                        help='Title of the pull request')
    parser.add_argument('--fixes', type=str, default=None,
                        help='Path to fixes.json (default: auto-detect)')
    parser.add_argument('--json', action='store_true', dest='output_json',
                        help='Output as JSON instead of a formatted report')

    args = parser.parse_args()

    if args.github:
        run_github_mode(args)
    else:
        run_cli_mode(args)


if __name__ == '__main__':
    main()

