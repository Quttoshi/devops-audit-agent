from __future__ import annotations

import json
from contextlib import contextmanager

import pytest
from conftest import FAKE_AWS_KEY, FakeLLM, tool_call, violation

import agent
from auditor.llm import LLMError
from auditor.repo import CloneError, normalize_repo_url

REPORT_FIELDS = {"rule_id", "category", "severity", "file", "line", "description", "evidence", "recommendation"}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setattr(agent, "load_dotenv", lambda *a, **k: None)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")


def _patch(monkeypatch, repo_path=None, llm=None, clone_error=None):
    @contextmanager
    def fake_clone(url, timeout=300):
        if clone_error:
            raise clone_error
        yield repo_path

    monkeypatch.setattr(agent, "cloned_repo", fake_clone)
    if llm is not None:
        monkeypatch.setattr(agent, "OpenAIChatClient", lambda **kw: llm)


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://github.com/psf/requests", "https://github.com/psf/requests"),
        ("https://github.com/psf/requests.git", "https://github.com/psf/requests"),
        ("github.com/psf/requests/", "https://github.com/psf/requests"),
    ],
)
def test_normalize_repo_url(url, expected):
    assert normalize_repo_url(url) == expected


@pytest.mark.parametrize("url", ["", "https://gitlab.com/a/b", "https://github.com/onlyowner", "file:///etc", "a b"])
def test_invalid_url_exits_2(url, tmp_path, capsys):
    assert agent.main(["--repo", url, "--output", str(tmp_path / "r.json")]) == 2
    assert "error:" in capsys.readouterr().err


def test_missing_api_key_exits_2(monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("OPENAI_API_KEY")
    assert agent.main(["--repo", "https://github.com/o/r", "--output", str(tmp_path / "r.json")]) == 2
    assert "OPENAI_API_KEY" in capsys.readouterr().err


def test_empty_optional_settings_use_defaults(monkeypatch, healthy_repo, tmp_path):
    """Blank lines copied from .env.example (e.g. OPENAI_TIMEOUT=) must mean 'use the default'."""
    for name in ("OPENAI_TIMEOUT", "OPENAI_TEMPERATURE", "OPENAI_MODEL", "OPENAI_BASE_URL", "AGENT_MAX_STEPS"):
        monkeypatch.setenv(name, "")
    _patch(monkeypatch, healthy_repo, FakeLLM([tool_call("finish", summary="clean")]))
    assert agent.main(["--repo", "https://github.com/o/r", "--output", str(tmp_path / "r.json")]) == 0


def test_max_steps_read_from_env(monkeypatch, healthy_repo, tmp_path):
    monkeypatch.setenv("AGENT_MAX_STEPS", "1")
    llm = FakeLLM([tool_call("list_files"), tool_call("git_log")])
    _patch(monkeypatch, healthy_repo, llm)
    assert agent.main(["--repo", "https://github.com/o/r", "--output", str(tmp_path / "r.json")]) == 0
    assert llm.calls[1]["tools"] == ["report_violation", "finish"]  # wrap-up after one step


@pytest.mark.parametrize("name", ["OPENAI_TIMEOUT", "AGENT_MAX_STEPS", "OPENAI_TEMPERATURE"])
def test_invalid_numeric_setting_exits_2(monkeypatch, tmp_path, capsys, name):
    monkeypatch.setenv(name, "abc")
    assert agent.main(["--repo", "https://github.com/o/r", "--output", str(tmp_path / "r.json")]) == 2
    assert name in capsys.readouterr().err


def test_end_to_end_writes_valid_report(monkeypatch, defective_repo, tmp_path):
    llm = FakeLLM(
        [
            tool_call("list_files"),
            tool_call("read_file", path="app/config.py"),
            tool_call("report_violation", **violation(evidence=f"literal {FAKE_AWS_KEY}")),
            tool_call("finish", summary="done"),
        ]
    )
    _patch(monkeypatch, defective_repo, llm)
    out = tmp_path / "report.json"
    assert agent.main(["--repo", "https://github.com/o/r", "--output", str(out)]) == 0
    raw = out.read_text(encoding="utf-8")
    report = json.loads(raw)
    assert report["repository"] == "https://github.com/o/r"
    assert len(report["violations"]) == 1
    assert set(report["violations"][0]) == REPORT_FIELDS
    assert report["violations"][0]["severity"] in {"critical", "high", "medium", "low"}
    assert FAKE_AWS_KEY not in raw
    trace = (tmp_path / "report.json.trace.jsonl").read_text(encoding="utf-8")
    assert FAKE_AWS_KEY not in trace and '"tool_result"' in trace


def test_empty_violations(monkeypatch, healthy_repo, tmp_path):
    _patch(monkeypatch, healthy_repo, FakeLLM([tool_call("finish", summary="clean")]))
    out = tmp_path / "report.json"
    assert agent.main(["--repo", "https://github.com/o/r", "--output", str(out), "--trace", "none"]) == 0
    assert json.loads(out.read_text(encoding="utf-8")) == {"repository": "https://github.com/o/r", "violations": []}


def test_clone_error_exits_3(monkeypatch, tmp_path, capsys):
    _patch(monkeypatch, clone_error=CloneError("repository does not exist or is not public"))
    out = tmp_path / "r.json"
    assert agent.main(["--repo", "https://github.com/o/missing", "--output", str(out)]) == 3
    assert "not public" in capsys.readouterr().err
    assert not out.exists()


def test_llm_error_exits_4(monkeypatch, defective_repo, tmp_path):
    _patch(monkeypatch, defective_repo, FakeLLM([LLMError("authentication failed")]))
    out = tmp_path / "r.json"
    assert agent.main(["--repo", "https://github.com/o/r", "--output", str(out)]) == 4
    assert not out.exists()
