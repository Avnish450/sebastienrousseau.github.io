"""
normalizer.py — Normalize code for structure-aware comparison.

The goal: if an attacker renames variables or reformats code to hide
the fact that they're removing a security check, we still catch it.

Normalization steps:
  1. Strip comments  (# ...)
  2. Strip whitespace
  3. Lowercase everything
  4. Replace variable/function names with a placeholder "_v_"
     (but keep Python keywords and common stdlib names)

Example:
  "real_path = os.path.realpath(full_path)"
  → "_v_ = os.path.realpath(_v_)"

  "resolved = os.path.realpath(target)"
  → "_v_ = os.path.realpath(_v_)"

Both normalize to the same string — match!
"""

import re
import keyword


# ── Words we keep as-is (not replaced with _v_) ─────────────────
# Includes Python keywords, built-in names, and common stdlib/security
# identifiers so the structural "shape" is preserved.
_KEEP_WORDS: set[str] = {w.lower() for w in keyword.kwlist} | {
    # Built-in types and functions
    'print', 'len', 'range', 'str', 'int', 'float', 'bool',
    'list', 'dict', 'set', 'tuple', 'type', 'bytes', 'bytearray',
    'isinstance', 'hasattr', 'getattr', 'setattr', 'callable',
    'open', 'close', 'read', 'write', 'readline', 'readlines',
    'append', 'extend', 'insert', 'remove', 'pop', 'index', 'count',
    'split', 'strip', 'lstrip', 'rstrip', 'join', 'replace',
    'find', 'rfind', 'startswith', 'endswith', 'upper', 'lower',
    'format', 'encode', 'decode', 'sorted', 'reversed', 'enumerate',
    'map', 'filter', 'zip', 'any', 'all', 'min', 'max', 'sum', 'abs',

    # os / path (common in file-handling security fixes)
    'os', 'path', 'realpath', 'abspath', 'normpath', 'join',
    'exists', 'isfile', 'isdir', 'basename', 'dirname',
    'getsize', 'getmtime', 'listdir', 'walk',

    # sys / subprocess / security-sensitive
    'sys', 'subprocess', 'eval', 'exec', 'compile', 'input',

    # Error types
    'exception', 'valueerror', 'typeerror', 'keyerror', 'indexerror',
    'ioerror', 'oserror', 'runtimeerror', 'permissionerror',
    'filenotfounderror', 'attributeerror', 'importerror',

    # Web / HTTP / security
    'request', 'response', 'headers', 'get', 'post', 'put', 'delete',
    'jsonify', 'render_template', 'escape', 'sanitize', 'validate',
    'token', 'authorization', 'bearer',
    'cursor', 'execute', 'connection', 'query', 'commit', 'rollback',
    'urlparse', 'hostname', 'scheme', 'netloc',
    'html', 'json', 'yaml', 'xml',

    # Constants
    'true', 'false', 'none', 'self', 'cls',
    'localhost', 'http', 'https',
}


def normalize_line(line: str) -> str:
    """
    Normalize a single line of code for structural comparison.

    Returns empty string for blank/comment-only lines.
    """
    # 1. Remove comments
    line = _strip_comment(line)

    # 2. Strip whitespace
    line = line.strip()
    if not line:
        return ''

    # 3. Lowercase
    line = line.lower()

    # 4. Replace identifiers that aren't in our keep-list
    def _replace(match: re.Match) -> str:
        word = match.group(0)
        return word if word in _KEEP_WORDS else '_v_'

    line = re.sub(r'\b[a-z_][a-z0-9_]*\b', _replace, line)

    return line


def _strip_comment(line: str) -> str:
    """
    Remove a Python # comment from a line.
    Careful not to strip # characters that are inside string literals.
    """
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == '#' and not in_single and not in_double:
            return line[:i]
    return line


def normalize_block(lines: list[str]) -> list[str]:
    """
    Normalize a block of code lines, dropping empty results.
    """
    result = []
    for line in lines:
        norm = normalize_line(line)
        if norm:
            result.append(norm)
    return result

