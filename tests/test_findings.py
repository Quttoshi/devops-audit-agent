from __future__ import annotations

import json

from conftest import FAKE_AWS_KEY, violation

from auditor.findings import (
    Finding,
    build_report,
    dedupe,
    finalize,
    normalize_finding,
    verify_findings,
    write_report,
)
from tools import RepoTools

REPORT_FIELDS = {"rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation"}


def test_normalize_valid_and_aliases():
    f, err = normalize_finding(violation(category="GitHub Actions / CI", severity="Major", rule_id="ci-002"))
    assert err == ""
    assert f.category == "ci_cd" and f.severity == "high" and f.rule_id == "CI-002"


def test_normalize_rejects_bad_input():
    assert normalize_finding(violation(category="ml_training"))[0] is None
    assert normalize_finding(violation(severity="urgent"))[0] is None
    assert "evidence" in normalize_finding(violation(evidence=""))[1]
    assert normalize_finding("nope")[0] is None


def test_normalize_cleans_file_line_and_secrets():
    f, _ = normalize_finding(
        violation(file="./app\\config.py", line="0", evidence=f"key {FAKE_AWS_KEY} in code", rule_id="bad id")
    )
    assert f.file == "app/config.py" and f.line is None
    assert FAKE_AWS_KEY not in f.evidence
    assert f.rule_id == "SEC-000"
    f, _ = normalize_finding(violation(file="null", line=None))
    assert f.file is None and f.line is None


def test_verify_findings_against_repository(defective_repo):
    tools = RepoTools(defective_repo)
    tools.read_file("app/config.py")
    cases = [
        normalize_finding(violation())[0],  # kept with line
        normalize_finding(violation(file="app/main.py", line=5))[0],  # never read -> line nulled
        normalize_finding(violation(file="app/config.py", line=500))[0],  # beyond EOF -> line nulled
        normalize_finding(violation(file="src/ghost.py", description="Hardcoded key in ghost module"))[0],  # dropped
        normalize_finding(violation(file="CONTRIBUTING.md", description="Missing contribution guide"))[0],  # file->null
        normalize_finding(violation(file="app/__pycache__/", line=None, category="repository_hygiene"))[0],
        normalize_finding(violation(confidence=0.2, file="README.md"))[0],  # low confidence -> dropped
        normalize_finding(violation(file="secrets.txt", line=1))[0],  # deleted, but still in git history -> kept
    ]
    out = verify_findings(cases, tools)
    assert [(f.file, f.line) for f in out] == [
        ("app/config.py", 3),
        ("app/main.py", None),
        ("app/config.py", None),
        (None, None),
        ("app/__pycache__/", None),
        ("secrets.txt", None),
    ]


def test_dedupe_keeps_most_severe():
    a = Finding("SEC-001", "security", "medium", "a.py", 3, "Hardcoded key in config", "e", "r")
    b = Finding("SEC-002", "security", "critical", "a.py", 3, "Hardcoded AWS key", "e", "r")
    c = Finding("CI-001", "ci_cd", "low", "a.py", 3, "Other problem", "e", "r")
    out = dedupe([a, b, c])
    assert [f.rule_id for f in out] == ["SEC-002", "CI-001"]


def test_finalize_sorts_and_assigns_ids():
    items = [
        Finding("HYG-000", "repository_hygiene", "low", None, None, "Missing README file", "e", "r"),
        Finding("SEC-000", "security", "critical", "x.py", 1, "Key in code", "e", "r"),
        Finding("SEC-000", "security", "high", "y.py", 1, "Token in workflow", "e", "r"),
    ]
    out = finalize(items)
    assert [f.severity for f in out] == ["critical", "high", "low"]
    assert [f.rule_id for f in out] == ["SEC-001", "SEC-002", "HYG-001"]


def test_rule_id_prefix_follows_category_and_ids_are_unique():
    f, _ = normalize_finding(violation(rule_id="CODE-004", category="code_quality"))
    assert f.rule_id == "CQ-004"
    a = Finding("SEC-001", "security", "critical", "a.py", 1, "Key in a", "e", "r")
    b = Finding("SEC-001", "security", "critical", "b.py", 1, "Token in b", "e", "r")
    assert sorted(x.rule_id for x in finalize([a, b])) == ["SEC-001", "SEC-002"]


def test_report_json_contract(tmp_path):
    f, _ = normalize_finding(violation())
    report = build_report("https://github.com/o/r", [f])
    path = tmp_path / "out" / "report.json"
    write_report(path, report)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["repository"] == "https://github.com/o/r"
    assert set(data["violations"][0]) == REPORT_FIELDS
    write_report(path, build_report("https://github.com/o/r", []))
    assert json.loads(path.read_text(encoding="utf-8"))["violations"] == []
    assert not list(path.parent.glob(".report-*"))  # no temp files left behind
