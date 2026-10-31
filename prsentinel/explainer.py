"""
explainer.py — Generate plain-English explanations and PR comments.

Two explanation modes:
  1. LLM-powered  — calls Gemini or OpenAI for a natural-language summary
  2. Template      — always works, no API key needed (demo insurance)

The LLM call is a single request; if it fails for any reason the
template kicks in silently.
"""

import os
import json

from .scorer import ScoreBreakdown


# ─────────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────────

def generate_explanation(breakdown: ScoreBreakdown, diff_text: str = '') -> str:
    """
    Return a plain-English explanation of the risk assessment.

    Tries an LLM first (if GEMINI_API_KEY or OPENAI_API_KEY is set),
    then falls back to a deterministic template.
    """
    api_key = (
        os.environ.get('GEMINI_API_KEY')
        or os.environ.get('OPENAI_API_KEY')
    )

    if api_key and breakdown.best_match:
        try:
            llm_text = _call_llm(breakdown, diff_text)
            if llm_text:
                return llm_text
        except Exception:
            pass  # fall through to template

    return _template_explanation(breakdown)


def format_pr_comment(breakdown: ScoreBreakdown, explanation: str) -> str:
    """Build the full Markdown comment posted on a GitHub PR."""

    emoji = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}[breakdown.risk_level]

    lines = [
        '## 🛡️ PRSentinel Security Review',
        '',
        f'### {emoji} {breakdown.total_score} / 100 — {breakdown.risk_level} RISK',
        '',
    ]

    # Score breakdown table
    lines += [
        '| Signal | Score | Detail |',
        '|--------|-------|--------|',
    ]
    signals = [
        ('Fix reversal',          breakdown.reverse_match_score,   60,
         breakdown.reverse_match_detail),
        ('New account',           breakdown.account_age_score,     15,
         breakdown.account_age_detail),
        ('First-time contributor', breakdown.first_time_score,     10,
         breakdown.first_time_detail),
        ('Sensitive files',       breakdown.sensitive_files_score, 10,
         breakdown.sensitive_files_detail),
        ('Cleanup disguise',      breakdown.cleanup_disguise_score, 5,
         breakdown.cleanup_disguise_detail),
    ]
    for name, score, mx, detail in signals:
        dot = '🔴' if score > 0 else '⚪'
        lines.append(f'| {dot} {name} | {score}/{mx} | {detail} |')

    lines += ['', '### Explanation', explanation, '']

    # Advice banner
    if breakdown.risk_level == 'HIGH':
        lines.append(
            '> **⚠️ Advice:** Do NOT merge yet. This PR may be reverting '
            'a security fix. Request a detailed review from a '
            'security-aware maintainer before proceeding.'
        )
    elif breakdown.risk_level == 'MEDIUM':
        lines.append(
            '> **⚡ Advice:** Review this PR carefully. Some signals '
            'suggest it may affect security-relevant code.'
        )
    else:
        lines.append(
            '> **✅ Advice:** No security fix reversal detected. '
            'Standard review process is sufficient.'
        )

    lines += [
        '',
        '---',
        '*🤖 PRSentinel — The security guard for the code behind our apps.*',
        '*Team TRIDENT · Aavishkar FET Hackathon · Jain University*',
    ]

    return '\n'.join(lines)


# ─────────────────────────────────────────────────────────────────
#  LLM helpers
# ─────────────────────────────────────────────────────────────────

def _call_llm(breakdown: ScoreBreakdown, diff_text: str) -> str | None:
    """Single LLM API call for a natural-language explanation."""

    prompt = (
        "You are PRSentinel, a security bot that reviews pull requests.\n"
        "Write a concise 2-3 sentence explanation for a maintainer.\n\n"
        f"Risk Score: {breakdown.total_score}/100 ({breakdown.risk_level})\n\n"
        "Signals:\n"
        f"- Reverse match: {breakdown.reverse_match_detail}\n"
        f"- Account age: {breakdown.account_age_detail}\n"
        f"- First-time: {breakdown.first_time_detail}\n"
        f"- Sensitive files: {breakdown.sensitive_files_detail}\n"
        f"- Cleanup disguise: {breakdown.cleanup_disguise_detail}\n\n"
        f"Diff snippet (first 1500 chars):\n{diff_text[:1500]}\n\n"
        "Be factual. Start with the most important finding."
    )

    if os.environ.get('GEMINI_API_KEY'):
        return _call_gemini(os.environ['GEMINI_API_KEY'], prompt)
    if os.environ.get('OPENAI_API_KEY'):
        return _call_openai(os.environ['OPENAI_API_KEY'], prompt)
    return None


def _call_gemini(api_key: str, prompt: str) -> str:
    import urllib.request
    url = (
        'https://generativelanguage.googleapis.com/v1beta/models/'
        f'gemini-2.0-flash:generateContent?key={api_key}'
    )
    body = json.dumps({
        'contents': [{'parts': [{'text': prompt}]}],
        'generationConfig': {'maxOutputTokens': 256, 'temperature': 0.3},
    }).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
        return data['candidates'][0]['content']['parts'][0]['text'].strip()


def _call_openai(api_key: str, prompt: str) -> str:
    import urllib.request
    body = json.dumps({
        'model': 'gpt-4o-mini',
        'messages': [{'role': 'user', 'content': prompt}],
        'max_tokens': 256,
        'temperature': 0.3,
    }).encode()
    req = urllib.request.Request(
        'https://api.openai.com/v1/chat/completions',
        data=body,
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
        },
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
        return data['choices'][0]['message']['content'].strip()


# ─────────────────────────────────────────────────────────────────
#  Template fallback (always works)
# ─────────────────────────────────────────────────────────────────

def _template_explanation(bd: ScoreBreakdown) -> str:
    """Deterministic explanation — no API call, guaranteed to work."""

    parts: list[str] = []

    if bd.risk_level == 'HIGH':
        parts.append('⚠️ **This pull request poses a significant security risk.**')
    elif bd.risk_level == 'MEDIUM':
        parts.append('⚡ **This pull request requires careful security review.**')
    else:
        parts.append('✅ **This pull request appears safe from a security perspective.**')

    if bd.best_match and bd.reverse_match_score > 0:
        pct = int(bd.best_match.match_percentage * 100)
        parts.append(
            f'The changes remove code that is a **{pct}% match** with a known '
            f'security fix ({bd.best_match.fix_id}: '
            f'"{bd.best_match.fix_description}"). '
            f'This appears to reverse security protections in '
            f'`{bd.best_match.matched_file}`.'
        )

    if bd.account_age_score > 0:
        parts.append(
            f'The PR author\'s account is very new '
            f'({bd.account_age_detail.lower()}).'
        )

    if bd.first_time_score > 0:
        parts.append('This is the author\'s first contribution to this repository.')

    if bd.cleanup_disguise_score > 0:
        parts.append(
            'The PR title suggests routine maintenance, which may be '
            'disguising the security-relevant changes.'
        )

    return ' '.join(parts)

