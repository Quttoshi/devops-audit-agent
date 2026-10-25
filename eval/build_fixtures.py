"""Build local fixture repositories that mimic the hidden evaluation set.

    a_obvious  - obvious defects (missing README/.gitignore, tracked .env and __pycache__, hardcoded key, ...)
    b_subtle   - subtler CI / security / configuration defects
    c_healthy  - a mostly healthy repository using acceptable alternatives (tests false positives)

Run:  uv run python eval/build_fixtures.py   (writes eval/fixtures/<name>/ as git repositories)
The known defects for each fixture are listed in eval/expected/<name>.json.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from auditor.repo import remove_tree  # noqa: E402

ROOT = Path(__file__).resolve().parent / "fixtures"

# Fake credentials are concatenated so that no secret-looking literal is committed to this repository.
AWS_KEY = "AKIA" + "R4NDOMF4KEK3Y9Z1"
AWS_SECRET = "wJalr" + "XUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY12"
API_TOKEN = "tok_" + "9f8e7d6c5b4a39281706f5e4d3c2b1a0"
PEM = (
    "-----BEGIN "
    + "RSA PRIVATE KEY-----\n"
    + ("MIIEpAIBAAKCAQEAx" + "Q" * 47 + "\n") * 3
    + "-----END RSA PRIVATE KEY-----\n"
)

A_OBVIOUS = [
    {
        "app.py": (
            "import boto3\n"
            "import pandas as pd\n\n"
            f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n'
            f'AWS_SECRET_ACCESS_KEY = "{AWS_SECRET}"\n'
            'DATA_PATH = "C:\\\\Users\\\\john\\\\Desktop\\\\project\\\\data.csv"\n\n\n'
            "def load():\n"
            "    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID,\n"
            "                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY)\n"
            "    return pd.read_csv(DATA_PATH)\n\n\n"
            "def main():\n"
            "    try:\n"
            "        print(load().head())\n"
            "    except:\n"
            "        pass\n\n\n"
            'if __name__ == "__main__":\n'
            "    main()\n"
        ),
        "utils.py": "def add(a, b):\n    return a + b\n",
        "requirements.txt": "boto3\npandas\nflask\n",
        ".env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\nDB_PASSWORD=hunter2hunter2\n",
        "__pycache__/utils.cpython-311.pyc": b"\x00\x0d\x0d\x0a\x00binary-bytecode\x00",
        "debug.log": "2024-01-01 12:00:00 ERROR something failed\n" * 20,
    }
]

B_SUBTLE_WORKFLOW = """\
name: CI
on:
  push:
    branches: [master]
  pull_request:
    branches: [master]
permissions:
  contents: write
  pull-requests: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - name: Announce branch
        run: echo "Testing branch ${{ github.head_ref }}"
      - name: Run tests
        run: pytest
        continue-on-error: true
      - uses: some-org/notify-action@master
"""

B_SUBTLE = [
    {
        "README.md": "# Orders service\n\nRun `pip install -r requirements.txt` then `python -m orders`.\n",
        ".gitignore": "__pycache__/\n*.pyc\n.env\n",
        "pyproject.toml": (
            '[project]\nname = "orders"\nversion = "0.3.0"\nrequires-python = ">=3.11"\n'
            'dependencies = ["requests>=2.32", "django>=5.0"]\n\n[tool.ruff]\nline-length = 100\n'
        ),
        "requirements.txt": "requests==2.25.1\ndjango==3.2.0\n",
        "orders/__init__.py": "",
        "orders/__main__.py": "from orders.service import run\n\nrun()\n",
        "orders/service.py": (
            "import os\n\nimport requests\n\n\n"
            "def run():\n"
            '    url = os.environ.get("ORDERS_API", "https://api.example.com")\n'
            "    return requests.get(url, timeout=10).status_code\n"
        ),
        "orders/settings/__init__.py": "",
        "orders/settings/prod.py": (
            'import os\n\nDEBUG = True\nALLOWED_HOSTS = ["*"]\nSECRET_KEY = os.environ["DJANGO_SECRET_KEY"]\n'
        ),
        "tests/test_service.py": (
            "from unittest import mock\n\nfrom orders import service\n\n\n"
            "def test_run():\n"
            "    with mock.patch.object(service.requests, 'get') as g:\n"
            "        g.return_value.status_code = 200\n"
            "        assert service.run() == 200\n"
        ),
        ".vscode/settings.json": (
            '{\n  "python.defaultInterpreterPath": "/Users/bob/.virtualenvs/orders/bin/python",\n'
            '  "python.envFile": "/Users/bob/secrets/orders.env"\n}\n'
        ),
        "Dockerfile": (
            "FROM python:latest\n"
            "WORKDIR /app\n"
            "COPY . .\n"
            "RUN pip install -r requirements.txt\n"
            f"ENV ORDERS_API_TOKEN={API_TOKEN}\n"
            'CMD ["python", "-m", "orders"]\n'
        ),
        ".github/workflows/ci.yml": B_SUBTLE_WORKFLOW,
        "deploy/credentials.pem": PEM,
    },
    {"deploy/credentials.pem": None},
]

C_HEALTHY = [
    {
        "README.md": (
            "# inventory\n\nSmall inventory API.\n\n## Development\n\n```\nuv sync\nuv run pytest\n```\n\n"
            "Configuration is read from environment variables; see `.env.example`.\n"
        ),
        ".gitignore": ".venv/\n__pycache__/\n*.pyc\n.env\n.pytest_cache/\n.ruff_cache/\ndist/\n",
        ".env.example": "DATABASE_URL=postgresql://user:password@localhost:5432/inventory\nAPI_KEY=your-api-key-here\n",
        "pyproject.toml": (
            '[project]\nname = "inventory"\nversion = "1.2.0"\nrequires-python = ">=3.11"\n'
            'dependencies = ["fastapi>=0.110,<1", "pydantic>=2.6,<3"]\n\n'
            '[dependency-groups]\ndev = ["pytest>=8", "ruff>=0.4"]\n\n'
            "[tool.ruff]\nline-length = 100\n\n[tool.pytest.ini_options]\ntestpaths = ['tests']\n"
        ),
        "uv.lock": 'version = 1\nrequires-python = ">=3.11"\n\n[[package]]\nname = "fastapi"\nversion = "0.115.0"\n',
        ".pre-commit-config.yaml": (
            "repos:\n  - repo: https://github.com/astral-sh/ruff-pre-commit\n"
            "    rev: 3b2f7b3d1f5a6c8e9d0a1b2c3d4e5f6a7b8c9d0e  # v0.6.9\n"
            "    hooks:\n      - id: ruff\n      - id: ruff-format\n"
        ),
        "src/inventory/__init__.py": "",
        "src/inventory/config.py": (
            "import os\n\n\n"
            "class Settings:\n"
            '    database_url = os.environ.get("DATABASE_URL", "sqlite:///./dev.db")\n'
            '    api_key = os.environ.get("API_KEY")\n'
            '    debug = os.environ.get("DEBUG", "false").lower() == "true"\n'
        ),
        "src/inventory/api.py": (
            "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n"
            '@app.get("/health")\n'
            "def health() -> dict[str, str]:\n"
            '    return {"status": "ok"}\n'
        ),
        "tests/test_api.py": (
            'from inventory.api import health\n\n\ndef test_health():\n    assert health() == {"status": "ok"}\n'
        ),
        "Dockerfile": (
            "FROM python:3.12.4-slim\n"
            "RUN useradd --create-home app\n"
            "WORKDIR /home/app\n"
            "COPY --chown=app:app . .\n"
            "RUN pip install --no-cache-dir .\n"
            "USER app\n"
            'CMD ["uvicorn", "inventory.api:app", "--host", "0.0.0.0"]\n'
        ),
        ".github/workflows/ci.yml": (
            "name: CI\non:\n  push:\n    branches: [main]\n  pull_request:\npermissions:\n  contents: read\n"
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    timeout-minutes: 10\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: astral-sh/setup-uv@e92bafb6253dcd438e0484186d7669ea7a8ca1cc  # v6\n"
            "      - run: uv sync --locked\n"
            "      - run: uv run ruff check .\n"
            "      - run: uv run pytest\n"
        ),
        ".github/workflows/release.yml": (
            "name: Release\non:\n  push:\n    tags: ['v*']\npermissions:\n  contents: read\n"
            "jobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: astral-sh/setup-uv@e92bafb6253dcd438e0484186d7669ea7a8ca1cc  # v6\n"
            "      - run: uv sync --locked && uv run pytest\n"
            "  publish:\n    needs: test\n    runs-on: ubuntu-latest\n    environment: pypi\n"
            "    permissions:\n      id-token: write\n    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "      - uses: astral-sh/setup-uv@e92bafb6253dcd438e0484186d7669ea7a8ca1cc  # v6\n"
            "      - run: uv build\n"
            "      - uses: pypa/gh-action-pypi-publish@76f52bc884231f62b9a034ebfe128415bbaabdfc  # v1.12.4\n"
        ),
    }
]

FIXTURES = {"a_obvious": A_OBVIOUS, "b_subtle": B_SUBTLE, "c_healthy": C_HEALTHY}


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.com", "-c", "commit.gpgsign=false", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def build(name: str, commits: list[dict]) -> Path:
    root = ROOT / name
    if root.exists():
        remove_tree(root)
    root.mkdir(parents=True)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "core.autocrlf", "false")
    for i, files in enumerate(commits, 1):
        for rel, content in files.items():
            if content is None:
                _git(root, "rm", "-q", rel)
                continue
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8", newline="\n")
        _git(root, "add", "-A", "-f")
        _git(root, "commit", "-q", "-m", f"fixture commit {i}")
    return root


def main() -> int:
    for name, commits in FIXTURES.items():
        print(f"built {build(name, commits)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
