"""Violation model: validation of LLM-reported findings, evidence verification, de-duplication and report output."""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from auditor.redact import redact, redact_obj

SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

CATEGORIES = {
    "repository_hygiene": "HYG",
    "dependency_management": "DEP",
    "code_quality": "CQ",
    "testing": "TEST",
    "ci_cd": "CI",
    "security": "SEC",
    "configuration": "CFG",
    "collaboration": "COL",
    "build_release": "BLD",
}
_CATEGORY_ALIASES = {
    "hygiene": "repository_hygiene",
    "repository": "repository_hygiene",
    "repo_hygiene": "repository_hygiene",
    "dependencies": "dependency_management",
    "dependency": "dependency_management",
    "quality": "code_quality",
    "linting": "code_quality",
    "lint": "code_quality",
    "tests": "testing",
    "test": "testing",
    "ci": "ci_cd",
    "cicd": "ci_cd",
    "github_actions": "ci_cd",
    "github_actions_ci": "ci_cd",
    "ci_cd_pipeline": "ci_cd",
    "secrets": "security",
    "config": "configuration",
    "collaboration_review": "collaboration",
    "build": "build_release",
    "release": "build_release",
    "build_and_release": "build_release",
    "deployment": "build_release",
}
_SEVERITY_ALIASES = {
    "crit": "critical",
    "blocker": "critical",
    "major": "high",
    "error": "high",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "minor": "low",
    "info": "low",
    "informational": "low",
    "note": "low",
}
_RULE_ID = re.compile(r"^[A-Z]{2,5}-\d{3}$")
_ABSENCE = re.compile(r"\b(missing|absent|no\b|not (?:found|present|configured|defined)|lacks?|lacking|without)", re.I)
MIN_CONFIDENCE = 0.5
REQUIRED_TEXT = ("description", "evidence", "recommendation")


class EvidenceSource(Protocol):
    observed_files: set[str]

    def tracked_files(self) -> list[str]: ...
    def is_tracked(self, path: str) -> bool: ...
    def in_history(self, path: str) -> bool: ...
    def line_count(self, path: str) -> int | None: ...


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    file: str | None
    line: int | None
    description: str
    evidence: str
    recommendation: str
    confidence: float = 1.0
    notes: list[str] = field(default_factory=list)  # internal; not written to the report

    def report_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("confidence")
        d.pop("notes")
        return d


def _norm_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def normalize_category(value: Any) -> str | None:
    key = _norm_key(value)
    if key in CATEGORIES:
        return key
    if key in _CATEGORY_ALIASES:
        return _CATEGORY_ALIASES[key]
    for cat in CATEGORIES:  # e.g. "repository_hygiene_and_layout"
        if key.startswith(cat):
            return cat
    return None


def normalize_severity(value: Any) -> str | None:
    key = _norm_key(value)
    return key if key in SEVERITIES else _SEVERITY_ALIASES.get(key)


def _clean_file(value: Any) -> str | None:
    if value in (None, "", "null", "None", "N/A", "n/a", "-"):
        return None
    p = str(value).strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/") or None


def _clean_line(value: Any) -> int | None:
    if value in (None, "", "null"):
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n >= 1 else None


def normalize_finding(raw: dict[str, Any]) -> tuple[Finding | None, str]:
    """Validate one finding reported by the LLM. Returns (finding, "") or (None, reason it was rejected)."""
    if not isinstance(raw, dict):
        return None, "finding must be an object"
    category = normalize_category(raw.get("category"))
    if not category:
        return None, f"unknown category {raw.get('category')!r}; use one of {', '.join(CATEGORIES)}"
    severity = normalize_severity(raw.get("severity"))
    if not severity:
        return None, f"severity must be one of {', '.join(SEVERITIES)}"
    texts = {k: redact(str(raw.get(k) or "").strip()) for k in REQUIRED_TEXT}
    missing = [k for k, v in texts.items() if len(v) < 5]
    if missing:
        return None, f"missing or too short: {', '.join(missing)}"
    rule_id = str(raw.get("rule_id") or "").strip().upper()
    prefix = CATEGORIES[category]
    if not _RULE_ID.match(rule_id):
        rule_id = f"{prefix}-000"  # renumbered in finalize()
    elif not rule_id.startswith(prefix + "-"):
        rule_id = f"{prefix}-{rule_id.split('-')[1]}"  # e.g. CODE-001 in code_quality -> CQ-001
    try:
        confidence = float(raw.get("confidence", 1.0))
    except (TypeError, ValueError):
        confidence = 1.0
    return Finding(
        rule_id=rule_id,
        category=category,
        severity=severity,
        file=_clean_file(raw.get("file")),
        line=_clean_line(raw.get("line")),
        description=texts["description"],
        evidence=texts["evidence"],
        recommendation=texts["recommendation"],
        confidence=max(0.0, min(confidence, 1.0)),
    ), ""


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", text.lower()) if len(t) > 2}


def is_duplicate(a: Finding, b: Finding) -> bool:
    """Same problem reported twice: same file & category with the same line or very similar wording."""
    if a.file != b.file:
        return False
    if a.category == b.category and a.line is not None and a.line == b.line:
        return True
    ta, tb = _tokens(a.description), _tokens(b.description)
    if not ta or not tb:
        return False
    jaccard = len(ta & tb) / len(ta | tb)
    return (a.rule_id == b.rule_id and a.line == b.line) or (a.category == b.category and jaccard >= 0.6)


def dedupe(findings: list[Finding]) -> list[Finding]:
    kept: list[Finding] = []
    for f in findings:
        for i, k in enumerate(kept):
            if is_duplicate(f, k):
                if (SEVERITY_RANK[f.severity], -f.confidence) < (SEVERITY_RANK[k.severity], -k.confidence):
                    kept[i] = f
                break
        else:
            kept.append(f)
    return kept


def verify_findings(findings: list[Finding], source: EvidenceSource) -> list[Finding]:
    """Drop or repair findings whose location is not backed by the repository.

    * a cited file that is not tracked: kept if it is a tracked directory or exists in git history, kept with
      file=null for "missing X" style findings, otherwise dropped (a claim about a file that does not exist);
    * a line beyond the end of the file, or a line in a file whose contents the agent never looked at -> line=null;
    * low self-reported confidence -> dropped.
    """
    verified: list[Finding] = []
    for f in findings:
        if f.confidence < MIN_CONFIDENCE:
            continue
        if f.file is not None and not source.is_tracked(f.file):
            if any(p.startswith(f.file.rstrip("/") + "/") for p in source.tracked_files()):
                f.line = None  # a tracked directory, e.g. "__pycache__/"
            elif source.in_history(f.file):
                f.line = None  # deleted file that is still in git history (e.g. a removed key)
            elif _ABSENCE.search(f.description):
                f.file, f.line = None, None
            else:
                continue
        if f.file is not None and f.line is not None:
            n = source.line_count(f.file)
            if n is None or f.line > n or f.file not in source.observed_files:
                f.line = None
        if f.file is None:
            f.line = None
        verified.append(f)
    return verified


def finalize(findings: list[Finding]) -> list[Finding]:
    """Dedupe, sort by severity, and make every rule id unique (unnamed or clashing ids are renumbered)."""
    findings = sorted(
        dedupe(findings), key=lambda f: (SEVERITY_RANK[f.severity], f.category, f.file or "", f.line or 0)
    )
    seen: set[str] = set()
    for f in findings:
        if f.rule_id in seen:
            f.rule_id = f"{CATEGORIES[f.category]}-000"
        seen.add(f.rule_id)
    used = {f.rule_id for f in findings}
    for f in findings:
        if f.rule_id.endswith("-000"):
            prefix = CATEGORIES[f.category]
            n = 1
            while f"{prefix}-{n:03d}" in used:
                n += 1
            f.rule_id = f"{prefix}-{n:03d}"
            used.add(f.rule_id)
    return findings


def build_report(repository: str, findings: list[Finding]) -> dict[str, Any]:
    return {"repository": repository, "violations": [redact_obj(f.report_dict()) for f in findings]}


def write_report(path: str | Path, report: dict[str, Any]) -> None:
    """Atomically write the JSON report (no partial file is left behind on failure)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".report-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
