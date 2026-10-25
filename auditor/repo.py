"""Repository URL validation and safe, read-only cloning of the audit target."""

from __future__ import annotations

import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from auditor.redact import redact

log = logging.getLogger(__name__)

_GITHUB_URL = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$"
)


class CloneError(Exception):
    """The repository could not be fetched."""


def normalize_repo_url(url: str) -> str:
    """Return ``https://github.com/<owner>/<repo>`` or raise ``ValueError`` for anything else."""
    m = _GITHUB_URL.match((url or "").strip())
    if not m or m.group("repo") in {".", ".."}:
        raise ValueError(f"not a GitHub repository URL: {url!r} (expected https://github.com/<owner>/<repo>)")
    return f"https://github.com/{m.group('owner')}/{m.group('repo')}"


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update(
        GIT_TERMINAL_PROMPT="0",  # never block on a username/password prompt
        GCM_INTERACTIVE="never",
        GIT_LFS_SKIP_SMUDGE="1",  # don't download LFS blobs
    )
    return env


def _clone_cmd(url: str, dest: Path, hooks_dir: Path, depth: int | None) -> list[str]:
    cmd = [
        "git",
        "-c",
        "credential.helper=",  # no credential manager pop-ups for private/missing repos
        "-c",
        f"core.hooksPath={hooks_dir}",  # no hooks run during checkout
        "-c",
        "core.symlinks=false",  # symlinks become plain files -> cannot point outside the clone
        "-c",
        "core.autocrlf=false",  # keep files byte-identical to the remote
        "-c",
        "core.longpaths=true",
        "-c",
        "protocol.file.allow=never",
        "clone",
        "--quiet",
        "--no-recurse-submodules",
    ]
    if depth:
        cmd += ["--depth", str(depth)]
    return cmd + ["--", url, str(dest)]


def clone_repo(url: str, workdir: Path, timeout: int = 300) -> Path:
    """Clone ``url`` into ``workdir/repo``. Falls back to a shallow clone if the full clone times out."""
    hooks_dir = workdir / "no-hooks"
    hooks_dir.mkdir(exist_ok=True)
    dest = workdir / "repo"
    for depth in (None, 100):
        if dest.exists():
            remove_tree(dest)
        try:
            proc = subprocess.run(
                _clone_cmd(url, dest, hooks_dir, depth),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                env=_git_env(),
                check=False,
            )
        except FileNotFoundError as exc:
            raise CloneError("git executable not found; install git and make sure it is on PATH") from exc
        except subprocess.TimeoutExpired:
            log.warning("clone %s timed out after %ss (depth=%s)", url, timeout, depth or "full")
            continue
        if proc.returncode == 0:
            return dest
        err = redact(proc.stderr.strip())
        if re.search(r"not found|could not read Username|Authentication failed|terminal prompts disabled", err, re.I):
            raise CloneError(f"repository {url} does not exist or is not public")
        raise CloneError(f"git clone failed: {err[-500:] or f'exit code {proc.returncode}'}")
    raise CloneError(f"git clone of {url} timed out after {timeout}s")


def _make_writable_and_retry(func, path, _exc) -> None:
    os.chmod(path, stat.S_IWRITE)  # git marks pack files read-only on Windows
    func(path)


def remove_tree(path: Path) -> None:
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_make_writable_and_retry)
    else:  # pragma: no cover
        shutil.rmtree(path, onerror=_make_writable_and_retry)


@contextmanager
def cloned_repo(url: str, timeout: int = 300) -> Iterator[Path]:
    """Clone into a private temp directory and always delete it afterwards."""
    workdir = Path(tempfile.mkdtemp(prefix="devops-audit-"))
    try:
        yield clone_repo(url, workdir, timeout)
    finally:
        try:
            remove_tree(workdir)
        except OSError as exc:  # pragma: no cover - best effort cleanup
            log.warning("could not remove temp clone %s: %s", workdir, exc)


def working_tree_is_clean(root: Path) -> bool:
    """True when the clone has no modified/untracked files (used to prove the audit changed nothing)."""
    proc = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    return proc.returncode == 0 and not proc.stdout.strip()
