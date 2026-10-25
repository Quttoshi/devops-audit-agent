"""Secret detection and masking.

Every piece of text that leaves a tool (towards the LLM, the trace file, logs or the final report) passes
through :func:`redact`. Secret *values* are replaced by ``[REDACTED:<kind>]`` so the agent can still see
that a credential is present (and report it) without the value ever being reproduced.

Redaction works line by line and never adds or removes lines, so line numbers stay valid.
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),  # header itself is kept, body masked
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b")),
    ("github_token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# Variable names that usually hold credentials.
_SENSITIVE_NAME = (
    r"[A-Za-z0-9_.-]*(?:passw(?:or)?d|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key"
    r"|client[_-]?secret|auth[_-]?key|credentials?)[A-Za-z0-9_.-]*"
)
# name = "value"  /  "name": "value"  /  name: 'value'
_QUOTED_ASSIGN = re.compile(
    rf"(?P<prefix>(?P<name>{_SENSITIVE_NAME})[\"']?\s*(?::|=|:=|=>)\s*(?P<q>[\"']))(?P<val>[^\"'\n]+)(?P=q)",
    re.IGNORECASE,
)
# NAME=value   /   name: value   (.env, YAML, ini) -- the value must be the rest of the line
_BARE_ASSIGN = re.compile(
    rf"^(?P<prefix>\s*(?:(?:export|ENV|ARG|set)\s+)?(?P<name>{_SENSITIVE_NAME})\s*(?::|=)\s*)"
    r"(?P<val>[^\s\"'#]+)\s*(?:#.*)?$",
    re.IGNORECASE,
)
# Dockerfile legacy form: ENV NAME value
_DOCKER_ENV = re.compile(
    rf"^(?P<prefix>\s*(?:ENV|ARG)\s+(?P<name>{_SENSITIVE_NAME})\s+)(?P<val>[^\s\"'=]+)\s*$",
    re.IGNORECASE,
)
# scheme://user:password@host
_URL_CREDENTIALS = re.compile(r"(?P<prefix>\b[a-z][a-z0-9+.-]*://[^\s:/@\"']+:)(?P<val>[^\s@/\"']+)(?=@)")

_PEM_BODY = re.compile(r"^(?P<lead>\s*(?:\d+\|\s?)?[\"']?)[A-Za-z0-9+/=]{16,}")
_PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")

_PLACEHOLDER = re.compile(
    r"^(?:|x+|\*+|\.+|<[^>]*>|\$\{.*\}|\$\(.*\)|\$[A-Za-z_]\w*|%\(?\w+\)?s?|\{\{.*\}\}|"
    r"(?:your|my|insert|enter|put|replace)[_ -].*|.*[_-]here|changeme|change_me|placeholder|example|"
    r"dummy|sample|fake|test|testing|none|null|nil|true|false|todo|tbd|secret|password|redacted.*|"
    r"\[redacted.*\]|read|write|read-all|write-all|required|optional|\d{1,7})$",
    re.IGNORECASE,
)
_CODE_REFERENCE = re.compile(r"^[A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+$|.*[()\[\]{}].*|^[A-Za-z_]\w*\($")


def is_placeholder(value: str) -> bool:
    """True for values that are clearly not real credentials (templates, env refs, dummies)."""
    v = value.strip()
    return bool(_PLACEHOLDER.match(v)) or len(v) < 4


def _mask(kind: str) -> str:
    return f"[REDACTED:{kind}]"


def _redact_line(line: str) -> str:
    for kind, pattern in _TOKEN_PATTERNS:
        if kind == "private_key":
            continue
        line = pattern.sub(_mask(kind), line)

    def quoted(m: re.Match[str]) -> str:
        val = m.group("val")
        if is_placeholder(val) or "REDACTED" in val:
            return m.group(0)
        return f"{m.group('prefix')}{_mask('secret_value')}{m.group('q')}"

    line = _QUOTED_ASSIGN.sub(quoted, line)

    m = _BARE_ASSIGN.match(line) or _DOCKER_ENV.match(line)
    if m:
        val = m.group("val")
        if not (is_placeholder(val) or "REDACTED" in val or _CODE_REFERENCE.match(val) or len(val) < 6):
            line = f"{m.group('prefix')}{_mask('secret_value')}"

    def url_cred(m: re.Match[str]) -> str:
        if is_placeholder(m.group("val")):
            return m.group(0)
        return f"{m.group('prefix')}{_mask('password')}"

    return _URL_CREDENTIALS.sub(url_cred, line)


def redact(text: str) -> str:
    """Mask secret values in ``text`` while preserving the number of lines."""
    if not text:
        return text
    out: list[str] = []
    in_key = False
    for line in text.split("\n"):
        if in_key:
            if _PEM_END.search(line):
                in_key = False
                out.append(line)
            else:
                out.append(_PEM_BODY.sub(lambda m: m.group("lead") + _mask("private_key"), line))
            continue
        if _TOKEN_PATTERNS[0][1].search(line) and not _PEM_END.search(line):
            in_key = True
            out.append(line)
            continue
        out.append(_redact_line(line))
    return "\n".join(out)


def contains_secret(text: str) -> bool:
    return redact(text) != text


def redact_obj(obj: Any) -> Any:
    """Recursively redact every string inside dicts/lists."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    return obj
