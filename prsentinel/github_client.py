"""
github_client.py — Interact with the GitHub API.

Capabilities:
  - Fetch a PR's diff
  - Fetch PR metadata (title, author, association)
  - Get a user's account age in days
  - Post or update a single bot comment (no spam)

Uses only the Python standard library (urllib) — no requests needed.
"""

import json
import os
import urllib.request
from datetime import datetime, timezone


GITHUB_API = 'https://api.github.com'
BOT_MARKER = '<!-- prsentinel-bot -->'   # hidden HTML tag to find our comment


# ─────────────────────────────────────────────────────────────────
#  Read helpers
# ─────────────────────────────────────────────────────────────────

def get_pr_diff(repo: str, pr_number: int, token: str) -> str:
    """Fetch the unified diff for a pull request."""
    url = f'{GITHUB_API}/repos/{repo}/pulls/{pr_number}'
    return _get(url, token, accept='application/vnd.github.v3.diff')


def get_pr_info(repo: str, pr_number: int, token: str) -> dict:
    """Fetch PR metadata (title, author login, author_association, etc.)."""
    url = f'{GITHUB_API}/repos/{repo}/pulls/{pr_number}'
    return json.loads(_get(url, token))


def get_user_age_days(username: str, token: str) -> int:
    """Return how many days ago the GitHub account was created."""
    url = f'{GITHUB_API}/users/{username}'
    data = json.loads(_get(url, token))
    created = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
    return (datetime.now(timezone.utc) - created).days


def is_first_time_contributor(author_association: str) -> bool:
    """True when the PR event's author_association signals a newcomer."""
    return author_association.upper() in {
        'FIRST_TIME_CONTRIBUTOR', 'FIRST_TIMER', 'NONE',
    }


# ─────────────────────────────────────────────────────────────────
#  Write helper — post or update comment
# ─────────────────────────────────────────────────────────────────

def post_or_update_comment(
    repo: str,
    pr_number: int,
    token: str,
    body: str,
) -> None:
    """
    Post a PR comment, or update the existing PRSentinel comment.

    We embed a hidden HTML marker so we can find and update our own
    comment instead of posting a new one every time the Action runs.
    """
    full_body = f'{BOT_MARKER}\n{body}'

    existing_id = _find_existing_comment(repo, pr_number, token)

    if existing_id:
        # Update in place
        url = f'{GITHUB_API}/repos/{repo}/issues/comments/{existing_id}'
        method = 'PATCH'
    else:
        # New comment
        url = f'{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments'
        method = 'POST'

    payload = json.dumps({'body': full_body}).encode()
    req = urllib.request.Request(
        url, data=payload, method=method,
        headers={
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        resp.read()


# ─────────────────────────────────────────────────────────────────
#  Internal helpers
# ─────────────────────────────────────────────────────────────────

def _get(url: str, token: str, accept: str = 'application/vnd.github.v3+json') -> str:
    req = urllib.request.Request(
        url,
        headers={'Authorization': f'token {token}', 'Accept': accept},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode()


def _find_existing_comment(repo: str, pr_number: int, token: str) -> int | None:
    """Scan PR comments for our hidden marker; return comment id or None."""
    url = f'{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments?per_page=100'
    try:
        data = json.loads(_get(url, token))
        for c in data:
            if BOT_MARKER in c.get('body', ''):
                return c['id']
    except Exception:
        pass
    return None

