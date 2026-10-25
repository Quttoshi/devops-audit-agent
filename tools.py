"""Read-only inspection tools the agent can call on a cloned repository.

Every tool:
  * is confined to the clone root (path traversal, absolute paths and ``.git/`` internals are rejected),
  * never executes code from the target repository,
  * returns plain text that is size-capped and passed through secret redaction before the LLM sees it.

``RepoTools.call(name, args)`` is the single dispatch entry point used by the agent loop; ``TOOL_SCHEMAS``
describes the same tools in OpenAI function-calling format.
"""

from __future__ import annotations

import fnmatch
import inspect
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from auditor.redact import redact

MAX_OUTPUT_CHARS = 12_000
MAX_READ_LINES = 400
MAX_LINE_CHARS = 400
MAX_SEARCH_FILE_BYTES = 1_000_000
GIT_TIMEOUT = 60
RUFF_TIMEOUT = 180

OTHER_CI_FILES = (
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    "Jenkinsfile",
    "azure-pipelines.yml",
    ".travis.yml",
    "bitbucket-pipelines.yml",
    ".drone.yml",
    "buildkite.yml",
    ".buildkite/pipeline.yml",
    "cloudbuild.yaml",
)


class ToolError(Exception):
    """A tool failed in an expected way; the message is shown to the LLM."""


def _cap(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[output truncated: {len(text) - limit} more characters; narrow the request]"


def _truncate_line(line: str) -> str:
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + " …[line truncated]"


class RepoTools:
    """Inspection tools bound to one repository checkout."""

    def __init__(self, root: Path | str):
        self.root = Path(root).resolve()
        if not (self.root / ".git").exists():
            raise ToolError(f"{self.root} is not a git repository")
        self._tracked: list[str] | None = None
        # Files whose *contents* the agent has actually looked at; used to verify line-level evidence.
        self.observed_files: set[str] = set()

    # ------------------------------------------------------------------ helpers
    def _git(self, *args: str, timeout: int = GIT_TIMEOUT) -> str:
        try:
            proc = subprocess.run(
                ["git", "-c", "core.quotepath=off", *args],
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ToolError(f"git {args[0]} timed out after {timeout}s") from exc
        if proc.returncode != 0:
            raise ToolError(f"git {args[0]} failed: {proc.stderr.strip()[:300]}")
        return proc.stdout

    def tracked_files(self) -> list[str]:
        if self._tracked is None:
            out = self._git("ls-files", "-z")
            self._tracked = sorted(p for p in out.split("\0") if p)
        return self._tracked

    def is_tracked(self, path: str) -> bool:
        return path in set(self.tracked_files())

    def in_history(self, path: str) -> bool:
        """True if ``path`` existed in some commit (e.g. a secret file that was deleted later)."""
        try:
            return bool(self._git("log", "--all", "--format=%h", "-n", "1", "--", self._normalize(path)).strip())
        except ToolError:
            return False

    def _normalize(self, path: str) -> str:
        """Validate a repo-relative path and return it in normalised posix form."""
        p = (path or ".").strip().replace("\\", "/")
        while p.startswith("./"):
            p = p[2:]
        p = p or "."
        if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
            raise ToolError(f"absolute paths are not allowed: {path!r}; use a path relative to the repository root")
        parts = PurePosixPath(p).parts
        if ".." in parts:
            raise ToolError(f"path escapes the repository: {path!r}")
        if parts and parts[0] == ".git":
            raise ToolError("the .git directory is internal; use git_log / git_show instead")
        full = (self.root / p).resolve()
        if full != self.root and self.root not in full.parents:
            raise ToolError(f"path escapes the repository: {path!r}")
        return "." if p == "." else str(PurePosixPath(p))

    def _read_text(self, rel: str) -> str:
        full = self.root / rel
        if not full.is_file():
            raise ToolError(f"file not found: {rel} (use list_files to see what exists)")
        data = full.read_bytes()
        if b"\0" in data[:8192]:
            raise ToolError(f"{rel} is a binary file ({len(data)} bytes); its contents cannot be shown")
        return data.decode("utf-8", errors="replace")

    def line_count(self, rel: str) -> int | None:
        try:
            return len(self._read_text(rel).splitlines())
        except (ToolError, OSError):
            return None

    # ------------------------------------------------------------------ tools
    def list_files(self, path: str = ".", max_depth: int = 4) -> str:
        """Tracked files (what is actually committed) under ``path``, collapsing deep directories."""
        prefix = self._normalize(path)
        max_depth = max(1, min(int(max_depth), 10))
        files = self.tracked_files()
        if prefix != ".":
            files = [f for f in files if f == prefix or f.startswith(prefix + "/")]
            if not files:
                raise ToolError(f"no tracked files under {prefix!r}")
        shown: list[str] = []
        collapsed: Counter[str] = Counter()
        base_depth = 0 if prefix == "." else len(PurePosixPath(prefix).parts)
        for f in files:
            parts = PurePosixPath(f).parts
            if len(parts) - base_depth <= max_depth:
                try:
                    size = (self.root / f).stat().st_size
                except OSError:
                    size = -1
                shown.append(f"{f}  ({size} B)" if size >= 0 else f)
            else:
                collapsed["/".join(parts[: base_depth + max_depth]) + "/"] += 1
        lines = [f"{len(files)} tracked file(s) under {prefix!r} (depth <= {max_depth}):"]
        lines += shown
        if collapsed:
            lines.append("Collapsed deeper directories (call list_files with that path to expand):")
            lines += [f"  {d}  [{n} files]" for d, n in sorted(collapsed.items())]
        if not files:
            lines.append("(repository has no tracked files)")
        return "\n".join(lines)

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        """File contents with line numbers (at most MAX_READ_LINES per call)."""
        rel = self._normalize(path)
        text = redact(self._read_text(rel))
        lines = text.splitlines()
        total = len(lines)
        start = max(1, int(start_line or 1))
        end = int(end_line) if end_line else start + MAX_READ_LINES - 1
        end = min(end, start + MAX_READ_LINES - 1, total)
        self.observed_files.add(rel)
        tracked = "" if self.is_tracked(rel) else "  [NOTE: not tracked by git]"
        if total == 0:
            return f"{rel}: empty file{tracked}"
        if start > total:
            raise ToolError(f"{rel} has only {total} lines")
        body = "\n".join(f"{i:>5}| {_truncate_line(lines[i - 1])}" for i in range(start, end + 1))
        more = f"\n[{total - end} more lines; call read_file with start_line={end + 1}]" if end < total else ""
        return f"{rel} (lines {start}-{end} of {total}){tracked}\n{body}{more}"

    def search_code(
        self, pattern: str, path_glob: str | None = None, max_results: int = 50, ignore_case: bool = True
    ) -> str:
        """Regex search over tracked text files. Returns ``file:line: text`` (secret values masked)."""
        if not pattern or len(pattern) > 500:
            raise ToolError("pattern must be a non-empty regex of at most 500 characters")
        try:
            rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
        except re.error as exc:
            raise ToolError(f"invalid regular expression: {exc}") from exc
        max_results = max(1, min(int(max_results), 200))
        hits: list[str] = []
        total = 0
        files_hit: set[str] = set()
        for rel in self.tracked_files():
            if path_glob and not (
                fnmatch.fnmatch(rel, path_glob) or fnmatch.fnmatch(PurePosixPath(rel).name, path_glob)
            ):
                continue
            full = self.root / rel
            try:
                if not full.is_file() or full.stat().st_size > MAX_SEARCH_FILE_BYTES:
                    continue
                data = full.read_bytes()
            except OSError:
                continue
            if b"\0" in data[:8192]:
                continue
            raw = data.decode("utf-8", errors="replace").splitlines()
            redacted: list[str] | None = None
            for i, line in enumerate(raw, 1):
                if rx.search(line[:5000]):
                    total += 1
                    files_hit.add(rel)
                    if len(hits) < max_results:
                        if redacted is None:
                            redacted = redact("\n".join(raw)).split("\n")
                        shown = redacted[i - 1] if i - 1 < len(redacted) else ""
                        hits.append(f"{rel}:{i}: {_truncate_line(shown.strip())}")
        self.observed_files |= files_hit
        if not hits:
            scope = f" in files matching {path_glob!r}" if path_glob else ""
            return f"No matches for /{pattern}/{scope}."
        head = f"{total} match(es) in {len(files_hit)} file(s)"
        if total > len(hits):
            head += f" (showing first {len(hits)})"
        return head + ":\n" + "\n".join(hits)

    def git_log(self, max_count: int = 30, path: str | None = None) -> str:
        """Recent commits with the files each one added/modified/deleted."""
        max_count = max(1, min(int(max_count), 200))
        args = ["log", f"--max-count={max_count}", "--date=short", "--format=@@%h %ad %s", "--name-status"]
        if path:
            args += ["--", self._normalize(path)]
        out = self._git(*args).strip()
        if not out:
            return "No commits found" + (f" touching {path}" if path else "") + "."
        total = self._git("rev-list", "--count", "HEAD").strip()
        lines = [f"Total commits on HEAD: {total} (showing up to {max_count}, newest first)"]
        for line in out.splitlines():
            if line.startswith("@@"):
                lines.append(line[2:])
            elif line.strip():
                lines.append("    " + line.replace("\t", " "))
        return redact("\n".join(lines))

    def git_show(self, revision: str, path: str | None = None) -> str:
        """Show a commit's diff (or one file as of that commit), e.g. to inspect content deleted later."""
        rev = (revision or "").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{4,40}(?:~\d{1,3}|\^)?|HEAD(?:~\d{1,3}|\^)?", rev):
            raise ToolError("revision must be a commit hash (e.g. from git_log) or HEAD~N")
        if path:
            rel = self._normalize(path)
            out = self._git("show", f"{rev}:{rel}")
            lines = redact(out).splitlines()
            return f"{rel} at {rev}:\n" + "\n".join(
                f"{i:>5}| {_truncate_line(t)}" for i, t in enumerate(lines[:MAX_READ_LINES], 1)
            )
        out = self._git("show", "--stat", "--patch", "--format=commit %h%nDate: %ad%n%n    %s%n", "--date=short", rev)
        return redact(out)

    def check_gitignore(self, paths: list[str]) -> str:
        """For each path: is it tracked, and would the repository's .gitignore rules ignore it?"""
        if isinstance(paths, str):
            paths = [paths]
        if not paths:
            raise ToolError("provide at least one path")
        tracked = set(self.tracked_files())
        rows = []
        for raw in paths[:50]:
            rel = self._normalize(raw)
            is_tracked = rel in tracked or any(f.startswith(rel + "/") for f in tracked)
            # Directory-only patterns such as "__pycache__/" only match when git knows the path is a directory,
            # which for a path that does not exist means it must end in "/". Try the plain form and the dir form.
            candidates = [rel + "/"] if str(raw).rstrip().endswith("/") else [rel, rel + "/"]
            rule = ""
            for candidate in candidates:
                try:
                    rule = self._git("check-ignore", "--no-index", "-v", candidate).strip()
                except ToolError:
                    rule = ""  # exit code 1 == not ignored
                if rule:
                    break
            source = rule.split("\t")[0]
            if not rule:
                ignored = "NOT ignored"
            elif source.split(":", 2)[-1].startswith("!"):
                ignored = f"NOT ignored (re-included by {source})"
            else:
                ignored = f"ignored by {source}"
            rows.append(f"{rel}: {'TRACKED' if is_tracked else 'not tracked'}; {ignored}")
        has_gitignore = ".gitignore" in tracked
        return (
            "(repository has a .gitignore)\n" if has_gitignore else "(repository has NO root .gitignore)\n"
        ) + "\n".join(rows)

    def inspect_workflows(self) -> str:
        """Parse GitHub Actions workflows and summarise triggers, permissions, jobs and risk signals."""
        tracked = self.tracked_files()
        wfs = [f for f in tracked if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", f)]
        other_ci = [f for f in OTHER_CI_FILES if f in tracked]
        default_branch = self._default_branch()
        out = [f"Default branch: {default_branch or 'unknown'}"]
        if other_ci:
            out.append("Other CI configuration present: " + ", ".join(other_ci))
        if not wfs:
            out.append("No GitHub Actions workflows found in .github/workflows/.")
            return "\n".join(out)
        for wf in wfs:
            self.observed_files.add(wf)
            out.append("")
            out.extend(_summarize_workflow(wf, self._read_text(wf), default_branch))
        out.append(
            "\nNOTE: 'signals' are heuristics. Read the referenced lines and judge them in context before reporting."
        )
        return redact("\n".join(out))

    def _default_branch(self) -> str | None:
        try:
            ref = self._git("symbolic-ref", "--short", "refs/remotes/origin/HEAD").strip()
            return ref.split("/", 1)[1] if "/" in ref else ref
        except ToolError:
            try:
                return self._git("rev-parse", "--abbrev-ref", "HEAD").strip() or None
            except ToolError:
                return None

    def run_ruff(self, path: str = ".") -> str:
        """Static lint of Python code with ruff (default rules: syntax errors, undefined names, unused imports...).

        Ruff only parses files; it never imports or executes repository code. ``--no-cache`` keeps the
        checkout unchanged and ``--isolated`` ignores repository config so results are comparable.
        """
        rel = self._normalize(path)
        py = [
            f
            for f in self.tracked_files()
            if f.endswith(".py") and (rel == "." or f.startswith(rel.rstrip("/") + "/") or f == rel)
        ]
        if not py:
            return "No tracked Python files in scope; ruff is not applicable."
        cmd = [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--isolated",
            "--no-cache",
            "--exit-zero",
            "--output-format",
            "json",
            rel,
        ]
        try:
            proc = subprocess.run(
                cmd,
                cwd=self.root,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=RUFF_TIMEOUT,
                check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise ToolError(
                f"ruff unavailable or timed out ({exc}); do not report lint findings from this tool"
            ) from exc
        try:
            items = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise ToolError(f"ruff produced unreadable output: {proc.stderr.strip()[:300]}") from exc
        config = [
            f
            for f in (
                "ruff.toml",
                ".ruff.toml",
                ".flake8",
                "setup.cfg",
                "tox.ini",
                ".pylintrc",
                ".pre-commit-config.yaml",
            )
            if f in self.tracked_files()
        ]
        config_text = ", ".join(config) or "none found (pyproject.toml may still configure tools)"
        header = (
            f"ruff (default rule set) checked {len(py)} Python file(s): {len(items)} issue(s). "
            f"Lint-related config files in repo: {config_text}"
        )
        if not items:
            return header
        by_code = Counter((i.get("code") or "syntax-error") for i in items)
        lines = [header, "Counts by rule: " + ", ".join(f"{c}={n}" for c, n in by_code.most_common(15))]
        for item in items[:40]:
            fname = Path(item.get("filename", "")).resolve()
            try:
                frel = fname.relative_to(self.root).as_posix()
            except ValueError:
                frel = fname.name
            self.observed_files.add(frel)
            row = (item.get("location") or {}).get("row")
            lines.append(f"{frel}:{row}: {item.get('code') or 'syntax-error'} {item.get('message', '')}")
        if len(items) > 40:
            lines.append(f"[{len(items) - 40} more issues not shown]")
        return redact("\n".join(lines))

    # ------------------------------------------------------------------ dispatch
    def call(self, name: str, args: dict[str, Any]) -> str:
        """Run tool ``name`` with ``args``; always returns text (errors are reported, never raised)."""
        func = getattr(self, name, None) if name in TOOL_NAMES else None
        if func is None:
            return f"ERROR: unknown tool {name!r}. Available tools: {', '.join(sorted(TOOL_NAMES))}"
        accepted = set(inspect.signature(func).parameters)
        ignored = sorted(k for k in args if k not in accepted and k != "rationale")
        args = {k: v for k, v in args.items() if k in accepted}
        note = f"NOTE: ignored unknown argument(s) {', '.join(ignored)}\n" if ignored else ""
        try:
            result = note + func(**args)
        except ToolError as exc:
            result = f"ERROR: {exc}"
        except TypeError as exc:
            result = f"ERROR: invalid arguments for {name}: {exc}"
        except (OSError, ValueError, UnicodeError) as exc:
            result = f"ERROR: {name} failed: {exc}"
        return _cap(redact(result))


# ---------------------------------------------------------------------- workflow analysis
_UNTRUSTED_CONTEXT = re.compile(
    r"\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits"
    r"|pages|workflow_run)[\w.\[\]*]*\.(?:title|body|message|name|ref|label|email|head_ref|default_branch)"
    r"|github\.head_ref)\s*\}\}"
)
_TEST_CMD = re.compile(
    r"\b(pytest|unittest|tox|nox|npm (?:run )?test|yarn test|pnpm test|go test|cargo test|mvn\b.*\btest"
    r"|gradle\w*\b.*\btest|make test|jest|vitest|phpunit|rspec|ctest|dotnet test)\b"
)
_LINT_CMD = re.compile(
    r"\b(ruff|flake8|pylint|black|isort|mypy|pyright|eslint|prettier|golangci-lint|clippy|"
    r"rubocop|pre-commit|hadolint|shellcheck)\b"
)
_BUILD_CMD = re.compile(
    r"\b(python -m build|pip wheel|poetry build|uv build|npm run build|docker build|"
    r"docker buildx|go build|cargo build|mvn\b.*\b(?:package|install)|gradle\w*\b.*\bbuild|make\b)"
)
_DEPLOY_JOB = re.compile(r"deploy|publish|release|gh-pages", re.I)
_DEPLOY_CMD = re.compile(
    r"\b(twine upload|npm publish|poetry publish|uv publish|docker push|kubectl apply|helm (?:upgrade|install)"
    r"|terraform apply|gh release create|aws s3 (?:sync|cp)|firebase deploy|vercel deploy|netlify deploy)\b"
)
_DEPLOY_ACTION = re.compile(r"pypa/gh-action-pypi-publish|softprops/action-gh-release|deploy|release", re.I)
_SWALLOW = re.compile(r"\|\|\s*(?:true\b|exit 0\b|echo\b|:(?=\s|$))|set \+e\b|--exit-zero\b", re.M)
_FIRST_PARTY = ("actions/", "github/", "docker/", "./")


def _grants_write(perms: Any) -> bool:
    """write-all, or any write scope other than id-token (OIDC trusted publishing is the recommended practice)."""
    if perms == "write-all":
        return True
    return isinstance(perms, dict) and any(v == "write" and k != "id-token" for k, v in perms.items())


def _line_of(lines: list[str], needle: str, start: int = 0) -> int | None:
    needle = needle.strip()
    if not needle:
        return None
    for i in range(start, len(lines)):
        if needle in lines[i]:
            return i + 1
    return None


def _fmt_triggers(on: Any) -> tuple[str, dict[str, Any]]:
    if isinstance(on, str):
        return on, {on: None}
    if isinstance(on, list):
        return ", ".join(map(str, on)), {str(t): None for t in on}
    if isinstance(on, dict):
        parts = []
        for k, v in on.items():
            if isinstance(v, dict):
                filt = {
                    fk: fv
                    for fk, fv in v.items()
                    if fk in ("branches", "branches-ignore", "paths", "paths-ignore", "tags", "types")
                }
                parts.append(f"{k}({json.dumps(filt)})" if filt else str(k))
            else:
                parts.append(str(k))
        return ", ".join(parts), {str(k): v for k, v in on.items()}
    return "unknown", {}


def _summarize_workflow(path: str, text: str, default_branch: str | None) -> list[str]:
    lines = text.splitlines()
    out = [f"=== {path} ==="]
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark else ""
        return out + [f"  INVALID YAML{where}: {str(exc).splitlines()[0]} -> this workflow cannot run."]
    if not isinstance(doc, dict):
        return out + ["  Not a mapping; GitHub will reject this workflow."]
    on = doc.get("on", doc.get(True))  # PyYAML parses a bare `on:` key as boolean True
    trig_text, triggers = _fmt_triggers(on)
    out.append(f"  name: {doc.get('name', '(unnamed)')}")
    out.append(f"  triggers: {trig_text or 'NONE (workflow never runs)'}")
    perms = doc.get("permissions")
    perms_text = (
        json.dumps(perms) if perms is not None else "not declared (inherits repository default token permissions)"
    )
    out.append(f"  top-level permissions: {perms_text}")
    signals: list[str] = []

    def sig(msg: str, needle: str | None = None, start: int = 0) -> None:
        ln = _line_of(lines, needle, start) if needle else None
        signals.append(f"L{ln}: {msg}" if ln else msg)

    for trig in ("push", "pull_request"):
        cfg = triggers.get(trig)
        if isinstance(cfg, dict) and default_branch:
            branches = cfg.get("branches")
            if (
                isinstance(branches, list)
                and branches
                and not any(fnmatch.fnmatch(default_branch, str(b)) for b in branches)
            ):
                sig(
                    f"{trig} branch filter {branches} does not include the default branch '{default_branch}'",
                    "branches",
                )
    if "pull_request_target" in triggers:
        sig(
            "pull_request_target trigger: runs with a privileged token and secrets in the base-repo context",
            "pull_request_target",
        )
    if "workflow_run" in triggers:
        sig(
            "workflow_run trigger: privileged context; check whether artifacts/code from the triggering run are used",
            "workflow_run",
        )
    if _grants_write(perms):
        sig(f"top-level write permissions granted: {json.dumps(perms)}", "permissions")

    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict) or not jobs:
        out.append("  jobs: NONE")
    kinds_seen: set[str] = set()
    for job_id, job in jobs.items() if isinstance(jobs, dict) else []:
        if not isinstance(job, dict):
            continue
        job_start = (_line_of(lines, f"{job_id}:") or 1) - 1  # search job-level needles from the job's own line

        def jsig(msg: str, needle: str | None = None, _start: int = job_start) -> None:
            sig(msg, needle, _start)

        jl = [f"  job '{job_id}': runs-on={job.get('runs-on')}"]
        for key in ("needs", "if", "permissions", "environment", "continue-on-error", "timeout-minutes", "strategy"):
            if key in job:
                jl[0] += f", {key}={json.dumps(job[key], default=str)}"
        if "uses" in job:
            jl.append(f"    calls reusable workflow: {job['uses']}")
        jperms = job.get("permissions")
        if _grants_write(jperms):
            jsig(f"job '{job_id}' has write permissions: {json.dumps(jperms)}", "permissions")
        if job.get("continue-on-error") in (True, "true"):
            jsig(f"job '{job_id}' has continue-on-error: true (failures do not fail the workflow)", "continue-on-error")
        if str(job.get("if", "")).strip().strip("${} ").lower() == "false":
            jsig(f"job '{job_id}' is disabled with if: false", "if:")
        runs_on = json.dumps(job.get("runs-on"), default=str)
        if "self-hosted" in runs_on and ({"pull_request", "pull_request_target"} & set(triggers)):
            jsig(f"job '{job_id}' runs PR-triggered code on a self-hosted runner", "self-hosted")
        job_kinds: set[str] = set()
        for n, step in enumerate(job.get("steps") or [], 1):
            if not isinstance(step, dict):
                continue
            label = step.get("name") or step.get("uses") or (str(step.get("run", "")).strip().splitlines() or [""])[0]
            desc = f"    {n}. {label}"
            if "uses" in step:
                uses = str(step["uses"])
                desc += f"  [uses {uses}]"
                ref = uses.split("@", 1)[1] if "@" in uses else ""
                if not uses.startswith(_FIRST_PARTY) and not re.fullmatch(r"[0-9a-f]{40}", ref):
                    if ref in ("main", "master", "") or not ref:
                        jsig(f"third-party action '{uses}' tracks a mutable branch (or no ref)", uses)
                    else:
                        jsig(f"third-party action '{uses}' pinned to a tag, not a commit SHA (low risk)", uses)
                with_ = step.get("with") or {}
                if "checkout" in uses and isinstance(with_, dict):
                    ref_val = str(with_.get("ref", ""))
                    if re.search(r"pull_request\.head|head_ref|github\.event\.pull_request\.merge", ref_val) and (
                        {"pull_request_target", "workflow_run"} & set(triggers)
                    ):
                        jsig(
                            f"job '{job_id}' checks out untrusted PR head code ({ref_val}) in a privileged trigger",
                            ref_val,
                        )
            run = str(step.get("run", ""))
            if run:
                for kind, rx in (
                    ("test", _TEST_CMD),
                    ("lint", _LINT_CMD),
                    ("build", _BUILD_CMD),
                    ("deploy", _DEPLOY_CMD),
                ):
                    if rx.search(run):
                        job_kinds.add(kind)
                for m in _UNTRUSTED_CONTEXT.finditer(run):
                    jsig(
                        f"untrusted input {m.group(0)} interpolated directly into a run: script (script injection)",
                        m.group(0),
                    )
                if swallow := _SWALLOW.search(run):
                    jsig(f"step '{label}' swallows failures ({swallow.group(0).strip()})", swallow.group(0))
                if re.search(r"curl[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh", run):
                    jsig(f"step '{label}' pipes a downloaded script into a shell", "curl")
                if re.search(r"echo[^\n]*\$\{\{\s*secrets\.", run):
                    jsig(f"step '{label}' echoes a secret", "secrets.")
            if step.get("continue-on-error") in (True, "true"):
                jsig(f"step '{label}' has continue-on-error: true", "continue-on-error")
            if str(step.get("if", "")).strip().strip("${} ").lower() == "false":
                jsig(f"step '{label}' is disabled with if: false", "if:")
            if _DEPLOY_ACTION.search(str(step.get("uses", ""))):
                job_kinds.add("deploy")
            jl.append(desc)
        if _DEPLOY_JOB.search(str(job_id)) or "deploy" in job_kinds:
            job_kinds.add("deploy")
            if not job.get("needs") and len(jobs) > 1:
                jsig(f"deploy/release job '{job_id}' has no 'needs:' dependency on test/build jobs", f"{job_id}:")
            if {"pull_request", "pull_request_target"} & set(triggers) and not job.get("if"):
                jsig(f"deploy/release job '{job_id}' can run on pull_request events (no if: guard)", f"{job_id}:")
        kinds_text = ", ".join(sorted(job_kinds)) or "none (no recognised test/lint/build command)"
        jl.insert(1, f"    detected step kinds: {kinds_text}")
        kinds_seen |= job_kinds
        out.extend(jl)
    out.append(f"  workflow runs: {', '.join(sorted(kinds_seen)) or 'no recognised test/lint/build steps'}")
    out.append("  signals:" if signals else "  signals: none")
    out.extend(f"    - {s}" for s in signals)
    return out


# ---------------------------------------------------------------------- OpenAI function schemas
RATIONALE = {
    "type": "string",
    "description": "Why you are making this call: what you learned so far and what you expect to find (1-2 sentences)",
}


def _fn(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    # Every inspection tool takes a required `rationale`, so each step's reasoning is visible in the trace.
    # RepoTools.call strips it before the tool runs.
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": {"rationale": RATIONALE, **properties},
                "required": ["rationale", *(required or [])],
                "additionalProperties": False,
            },
        },
    }


TOOL_SCHEMAS: list[dict[str, Any]] = [
    _fn(
        "list_files",
        "List files tracked by git (i.e. committed) with sizes. Deep directories are collapsed; "
        "call again with a sub-path to expand.",
        {
            "path": {"type": "string", "description": "Repo-relative directory, default '.'"},
            "max_depth": {"type": "integer", "description": "Depth relative to path (1-10, default 4)"},
        },
    ),
    _fn(
        "read_file",
        f"Read a file with line numbers (max {MAX_READ_LINES} lines per call). Secret values are masked.",
        {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}},
        ["path"],
    ),
    _fn(
        "search_code",
        "Regex (Python syntax) search over all tracked text files; returns file:line: text.",
        {
            "pattern": {"type": "string"},
            "path_glob": {"type": "string", "description": "Optional glob such as '*.py' or '.github/*'"},
            "max_results": {"type": "integer"},
            "ignore_case": {"type": "boolean", "description": "Default true"},
        },
        ["pattern"],
    ),
    _fn(
        "git_log",
        "Commit history (newest first) with the files each commit added (A), modified (M) or deleted (D).",
        {
            "max_count": {"type": "integer", "description": "1-200, default 30"},
            "path": {"type": "string", "description": "Only commits touching this path"},
        },
    ),
    _fn(
        "git_show",
        "Show a commit's patch, or a file's content at that commit (useful for secrets removed later).",
        {
            "revision": {"type": "string", "description": "Commit hash from git_log, or HEAD~N"},
            "path": {"type": "string", "description": "Optional file path to show at that revision"},
        },
        ["revision"],
    ),
    _fn(
        "check_gitignore",
        "For each path report whether it is tracked and whether .gitignore rules ignore it. "
        "Paths may be hypothetical (e.g. '.env', 'node_modules/', '__pycache__/x.pyc').",
        {"paths": {"type": "array", "items": {"type": "string"}}},
        ["paths"],
    ),
    _fn(
        "inspect_workflows",
        "Parse all GitHub Actions workflows: triggers, permissions, jobs, steps, detected "
        "test/lint/build/deploy steps and heuristic risk signals with line numbers. Also lists other CI systems.",
        {},
    ),
    _fn(
        "run_ruff",
        "Run the ruff linter statically (never executes code) on Python files and summarise issues.",
        {"path": {"type": "string", "description": "Repo-relative path, default '.'"}},
    ),
]
TOOL_NAMES = {s["function"]["name"] for s in TOOL_SCHEMAS}
