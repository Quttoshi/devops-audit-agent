from __future__ import annotations

import pytest
from conftest import FAKE_AWS_KEY, FAKE_DB_PASSWORD, FAKE_GH_TOKEN, make_repo

from auditor.repo import working_tree_is_clean
from tools import TOOL_NAMES, TOOL_SCHEMAS, RepoTools, ToolError


@pytest.fixture
def tools(defective_repo):
    return RepoTools(defective_repo)


def test_schemas_cover_all_tools():
    assert {"list_files", "read_file", "search_code", "git_log"} <= TOOL_NAMES
    for schema in TOOL_SCHEMAS:
        assert schema["type"] == "function"
        assert schema["function"]["parameters"]["type"] == "object"
        assert "rationale" in schema["function"]["parameters"]["required"]


def test_not_a_git_repo(tmp_path):
    with pytest.raises(ToolError):
        RepoTools(tmp_path)


# ------------------------------------------------------------------ list_files
def test_list_files_shows_tracked_files_including_junk(tools):
    out = tools.list_files()
    assert "README.md" in out
    assert ".env" in out
    assert "app/__pycache__/main.cpython-312.pyc" in out
    assert "secrets.txt" not in out  # deleted in the second commit


def test_list_files_collapses_deep_directories(tools):
    out = tools.list_files(max_depth=1)
    assert ".github/  [1 files]" in out and "app/  [4 files]" in out
    assert "README.md" in out


def test_list_files_subdirectory(tools):
    out = tools.list_files("app")
    assert "app/config.py" in out and "README.md" not in out
    assert tools.call("list_files", {"path": "nope"}).startswith("ERROR")


# ------------------------------------------------------------------ read_file
def test_read_file_numbers_lines_and_masks_secrets(tools):
    out = tools.read_file("app/config.py")
    assert "    3| AWS_ACCESS_KEY_ID" in out
    assert FAKE_AWS_KEY not in out
    assert "[REDACTED:aws_access_key]" in out
    assert "app/config.py" in tools.observed_files


def test_read_file_dotenv_masked(tools):
    out = tools.read_file(".env")
    assert FAKE_DB_PASSWORD not in out
    assert "DB_PASSWORD=[REDACTED" in out


def test_read_file_range(tools):
    out = tools.read_file("app/config.py", start_line=4, end_line=4)
    assert "lines 4-4" in out and "DATA_DIR" in out and "AWS_ACCESS_KEY_ID" not in out


def test_read_file_errors(tools):
    assert "file not found" in tools.call("read_file", {"path": "missing.py"})
    assert "binary" in tools.call("read_file", {"path": "app/__pycache__/main.cpython-312.pyc"})
    assert "only" in tools.call("read_file", {"path": "README.md", "start_line": 999})


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/passwd", "C:/Windows/win.ini", ".git/config", "app/../../x"])
def test_path_traversal_rejected(tools, path):
    assert tools.call("read_file", {"path": path}).startswith("ERROR")


# ------------------------------------------------------------------ search_code
def test_search_code_finds_and_redacts(tools):
    out = tools.search_code(r"AKIA[0-9A-Z]{16}")
    assert "app/config.py:3:" in out
    assert FAKE_AWS_KEY not in out


def test_search_code_glob_and_no_match(tools):
    assert "app/main.py" in tools.search_code("undefined_name", path_glob="*.py")
    assert tools.search_code("undefined_name", path_glob="*.md").startswith("No matches")


def test_search_code_invalid_regex(tools):
    assert "invalid regular expression" in tools.call("search_code", {"pattern": "("})


def test_search_code_absolute_paths(tools):
    out = tools.search_code(r"C:\\\\Users")
    assert "app/config.py:4:" in out


# ------------------------------------------------------------------ git
def test_git_log_lists_commits_and_deletions(tools):
    out = tools.git_log()
    assert "Total commits on HEAD: 2" in out
    assert "D secrets.txt" in out


def test_git_show_old_file_is_redacted(tools):
    out = tools.call("git_show", {"revision": "HEAD~1", "path": "secrets.txt"})
    assert "secrets.txt at HEAD~1" in out
    assert FAKE_GH_TOKEN not in out
    assert "REDACTED" in out


def test_git_show_rejects_odd_revisions(tools):
    assert tools.call("git_show", {"revision": "--output=/tmp/x"}).startswith("ERROR")


# ------------------------------------------------------------------ gitignore
def test_check_gitignore_directory_patterns(healthy_repo):
    # healthy .gitignore contains "__pycache__/" (a directory-only pattern); the directory does not exist
    out = RepoTools(healthy_repo).check_gitignore(["__pycache__/", "__pycache__", "src/__pycache__/", ".venv"])
    assert "NOT ignored" not in out
    assert out.count("ignored by .gitignore") == 4


def test_check_gitignore(tools):
    out = tools.check_gitignore([".env", "debug.log", "app/__pycache__/"])
    assert ".env: TRACKED; NOT ignored" in out
    assert "debug.log: not tracked; ignored by .gitignore" in out
    assert "app/__pycache__: TRACKED" in out


# ------------------------------------------------------------------ workflows
def test_inspect_workflows_signals(tools):
    out = tools.inspect_workflows()
    assert "Default branch: main" in out
    assert "pull_request_target trigger" in out
    assert "top-level write permissions" in out
    assert "checks out untrusted PR head code" in out
    assert "script injection" in out
    assert "swallows failures (|| true)" in out
    assert "someone/deploy-action@main" in out and "mutable branch" in out
    assert "does not include the default branch 'main'" in out
    assert "deploy/release job 'deploy' has no 'needs:'" in out
    assert "L17:" in out  # line of `run: pytest || true`


def test_inspect_workflows_healthy(healthy_repo):
    out = RepoTools(healthy_repo).inspect_workflows()
    assert "signals: none" in out
    assert "lint, test" in out


def test_oidc_id_token_is_not_flagged(tmp_path):
    wf = "on: push\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n"
    repo = make_repo(tmp_path / "oidc", [{".github/workflows/p.yml": wf}])
    out = RepoTools(repo).inspect_workflows()
    assert "write permissions" not in out and '"id-token": "write"' in out


def test_inspect_workflows_invalid_and_absent(tmp_path):
    bad = make_repo(tmp_path / "bad", [{".github/workflows/x.yml": "on: [push\njobs: {", "README.md": "x"}])
    assert "INVALID YAML" in RepoTools(bad).inspect_workflows()
    none = make_repo(tmp_path / "none", [{"README.md": "x", ".gitlab-ci.yml": "test:\n  script: pytest\n"}])
    out = RepoTools(none).inspect_workflows()
    assert "No GitHub Actions workflows" in out and ".gitlab-ci.yml" in out


# ------------------------------------------------------------------ ruff
def test_run_ruff_reports_undefined_name(tools):
    out = tools.run_ruff()
    assert "F821" in out and "app/main.py:5" in out


def test_run_ruff_no_python(tmp_path):
    repo = make_repo(tmp_path / "js", [{"index.js": "console.log(1)\n"}])
    assert "not applicable" in RepoTools(repo).run_ruff()


# ------------------------------------------------------------------ dispatch & safety
def test_call_handles_unknown_tool_and_bad_args(tools):
    assert "unknown tool" in tools.call("rm_rf", {})
    assert "invalid arguments" in tools.call("read_file", {"bogus": 1})  # required path missing


def test_unknown_arguments_are_ignored_with_a_note(tools):
    out = tools.call("inspect_workflows", {"*": None, "rationale": "why"})
    assert out.startswith("NOTE: ignored unknown argument(s) *")
    assert "pull_request_target" in out


def test_in_history(tools):
    assert tools.in_history("secrets.txt") and not tools.in_history("never-existed.txt")


def test_output_is_capped(tmp_path):
    repo = make_repo(tmp_path / "big", [{f"f{i:04d}.txt": "x\n" for i in range(2000)}])
    out = RepoTools(repo).call("list_files", {})
    assert "[output truncated" in out


def test_tools_leave_repository_unchanged(tools, defective_repo):
    for name, args in [
        ("list_files", {}),
        ("read_file", {"path": "app/config.py"}),
        ("search_code", {"pattern": "password"}),
        ("git_log", {}),
        ("check_gitignore", {"paths": [".env"]}),
        ("inspect_workflows", {}),
        ("run_ruff", {}),
    ]:
        tools.call(name, args)
    assert working_tree_is_clean(defective_repo)
