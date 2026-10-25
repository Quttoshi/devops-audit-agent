"""Shared fixtures: throw-away git repositories with known defects and a scripted fake LLM."""

from __future__ import annotations

import itertools
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from auditor.llm import LLMResponse, ToolCall  # noqa: E402

# Fake credentials are assembled at runtime so no secret-looking literal exists in this repository.
FAKE_AWS_KEY = "AKIA" + "Q7XYZ3EXAMPLE7K2"
FAKE_GH_TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
FAKE_DB_PASSWORD = "Sup3r" + "S3cretPassw0rd!"

DEFECTIVE_WORKFLOW = """\
name: CI
on:
  pull_request_target:
  push:
    branches: [master]
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Greet
        run: echo "${{ github.event.pull_request.title }}"
      - name: Tests
        run: pytest || true
      - uses: someone/deploy-action@main
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: twine upload dist/*
"""

HEALTHY_WORKFLOW = """\
name: CI
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: ruff check .
      - run: pytest
"""


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgsign=false", *args],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout


def write_files(root: Path, files: dict[str, str | bytes]) -> None:
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")


def make_repo(root: Path, commits: list[dict[str, str | bytes | None]]) -> Path:
    """Create a git repo; each commit maps path -> content (None deletes the file)."""
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "-q", "-b", "main")
    git(root, "config", "core.autocrlf", "false")
    for i, files in enumerate(commits, 1):
        for rel, content in files.items():
            if content is None:
                git(root, "rm", "-q", rel)
            else:
                write_files(root, {rel: content})
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", f"commit {i}")
    return root


@pytest.fixture
def defective_repo(tmp_path: Path) -> Path:
    first = {
        "README.md": "# Demo\n\nA demo service.\n",
        "requirements.txt": "flask\nrequests\n",
        "app/__init__.py": "",
        "app/config.py": (
            "import os\n\n"
            f'AWS_ACCESS_KEY_ID = "{FAKE_AWS_KEY}"\n'
            'DATA_DIR = "C:\\\\Users\\\\alice\\\\data"\n'
            "DEBUG = True\n"
            'API_URL = os.environ.get("API_URL", "http://localhost")\n'
        ),
        "app/main.py": "import os\n\n\ndef handler():\n    return undefined_name\n",
        ".env": f"DB_PASSWORD={FAKE_DB_PASSWORD}\nDEBUG=1\n",
        ".env.example": "DB_PASSWORD=changeme\nAPI_KEY=your-api-key-here\n",
        ".gitignore": "*.log\n",
        "app/__pycache__/main.cpython-312.pyc": b"\x00\x01\x02binary\x00",
        ".github/workflows/ci.yml": DEFECTIVE_WORKFLOW,
        "tests/test_app.py": "def test_ok():\n    assert True\n",
        "secrets.txt": f"token={FAKE_GH_TOKEN}\n",
    }
    second = {"secrets.txt": None}
    return make_repo(tmp_path / "defective", [first, second])


@pytest.fixture
def healthy_repo(tmp_path: Path) -> Path:
    files = {
        "README.md": "# Healthy\n\nInstall with pip install -r requirements.txt\n",
        "requirements.txt": "flask==3.0.3\nrequests==2.32.3\n",
        "pyproject.toml": "[tool.ruff]\nline-length = 100\n",
        ".gitignore": ".env\n__pycache__/\n*.pyc\n.venv/\n",
        "src/app.py": "import os\n\nAPI_KEY = os.environ['API_KEY']\n",
        "tests/test_app.py": "def test_ok():\n    assert 1 + 1 == 2\n",
        ".github/workflows/ci.yml": HEALTHY_WORKFLOW,
    }
    return make_repo(tmp_path / "healthy", [files])


# ---------------------------------------------------------------------- fake LLM
_ids = itertools.count(1)


def tool_call(name: str, content: str | None = None, **args: Any) -> LLMResponse:
    """An assistant turn that calls one tool."""
    return LLMResponse(
        content=content or f"Next I will call {name}.",
        tool_calls=[ToolCall(id=f"call_{next(_ids)}", name=name, arguments=json.dumps(args))],
    )


def multi_call(*calls: tuple[str, dict[str, Any]]) -> LLMResponse:
    return LLMResponse(
        content="Running several tools in parallel.",
        tool_calls=[ToolCall(id=f"call_{next(_ids)}", name=n, arguments=json.dumps(a)) for n, a in calls],
    )


def violation(**overrides: Any) -> dict[str, Any]:
    base = {
        "rule_id": "SEC-001",
        "category": "security",
        "severity": "critical",
        "file": "app/config.py",
        "line": 3,
        "description": "Hardcoded AWS access key in source code",
        "evidence": "AWS_ACCESS_KEY_ID is assigned a literal key ([REDACTED])",
        "recommendation": "Load the key from the environment or a secrets manager and rotate it",
        "confidence": 0.95,
    }
    base.update(overrides)
    return base


class FakeLLM:
    """Scripted stand-in for OpenAIChatClient.

    ``script`` items are LLMResponse objects, exceptions to raise, or callables ``f(messages) -> LLMResponse``
    (used to show that the next tool choice depends on the previous tool output).
    """

    model = "fake-model"

    def __init__(self, script: list[Any], review: str | Exception | None = None):
        self.script = list(script)
        self.review = review
        self.calls: list[dict[str, Any]] = []
        self.total_usage: dict[str, int] = {}

    def chat(self, messages, tools=None, json_mode=False):
        self.calls.append(
            {
                "messages": [dict(m) for m in messages],
                "tools": [t["function"]["name"] for t in tools or []],
                "json_mode": json_mode,
            }
        )
        if json_mode:
            if isinstance(self.review, Exception):
                raise self.review
            return LLMResponse(content=self.review if self.review is not None else '{"decisions": []}')
        if not self.script:
            return tool_call("finish", summary="done")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        if callable(item):
            item = item(messages)
        return item
