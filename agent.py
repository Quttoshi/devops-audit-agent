"""CLI entry point: audit a public GitHub repository for DevOps best-practice violations.

    python agent.py --repo https://github.com/<owner>/<repo> --output report.json

Exit codes: 0 report written (possibly with zero violations), 1 unexpected error, 2 invalid input/configuration,
3 repository could not be cloned, 4 LLM/API failure, 130 interrupted.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from auditor.findings import build_report, write_report
from auditor.llm import LLMError, OpenAIChatClient
from auditor.loop import AuditAgent
from auditor.redact import redact
from auditor.repo import CloneError, cloned_repo, normalize_repo_url, working_tree_is_clean
from auditor.trace import Tracer
from tools import RepoTools, ToolError

DEFAULT_MODEL = "gpt-4.1"
EXIT_OK, EXIT_UNEXPECTED, EXIT_INPUT, EXIT_CLONE, EXIT_LLM = 0, 1, 2, 3, 4

log = logging.getLogger("agent")


class ConfigError(Exception):
    """An environment variable has an invalid value."""


def env_number(name: str, default: float | int | None, cast: type = float):
    """Read a numeric environment variable; empty or unset means ``default``."""
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return cast(raw)
    except ValueError:
        raise ConfigError(f"{name}={raw!r} is not a valid {cast.__name__}") from None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="LLM-driven DevOps auditing agent for public GitHub repositories.")
    p.add_argument("--repo", required=True, help="Public GitHub repository URL, e.g. https://github.com/owner/repo")
    p.add_argument("--output", required=True, help="Path of the JSON report to write")
    p.add_argument("--model", default=None, help=f"OpenAI model (default: $OPENAI_MODEL or {DEFAULT_MODEL})")
    p.add_argument(
        "--max-steps",
        type=int,
        default=None,
        help="Maximum LLM/tool rounds (default: $AGENT_MAX_STEPS or 40)",
    )
    p.add_argument("--time-limit", type=float, default=900.0, help="Investigation wall-clock limit in seconds")
    p.add_argument("--clone-timeout", type=int, default=300, help="git clone timeout in seconds")
    p.add_argument(
        "--trace",
        default=None,
        help="Where to write the JSONL tool-call trace (default: <output>.trace.jsonl; 'none' to disable)",
    )
    p.add_argument("--no-review", action="store_true", help="Skip the final LLM review pass")
    p.add_argument("--local-path", default=None, help=argparse.SUPPRESS)  # dev/eval only: audit an existing checkout
    p.add_argument("-v", "--verbose", action="store_true", help="Log each reasoning step and tool call")
    return p.parse_args(argv)


def _fail(code: int, message: str) -> int:
    print(f"error: {redact(message)}", file=sys.stderr)
    return code


def run(args: argparse.Namespace) -> int:
    try:
        repo_url = normalize_repo_url(args.repo)
    except ValueError as exc:
        return _fail(EXIT_INPUT, str(exc))
    try:
        if args.max_steps is None:
            args.max_steps = env_number("AGENT_MAX_STEPS", 40, int)
        timeout = env_number("OPENAI_TIMEOUT", 120.0)
        temperature = env_number("OPENAI_TEMPERATURE", None)
    except ConfigError as exc:
        return _fail(EXIT_INPUT, str(exc))
    if args.max_steps < 1:
        return _fail(EXIT_INPUT, "--max-steps must be at least 1")
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return _fail(EXIT_INPUT, "OPENAI_API_KEY is not set (copy .env.example to .env and fill it in)")
    output = Path(args.output)
    if output.is_dir():
        return _fail(EXIT_INPUT, f"--output {output} is a directory; give a file path")
    trace_path = None if (args.trace or "").lower() == "none" else Path(args.trace or f"{output}.trace.jsonl")

    model = args.model or os.getenv("OPENAI_MODEL", "").strip() or DEFAULT_MODEL
    llm = OpenAIChatClient(
        model=model,
        api_key=api_key,
        base_url=os.getenv("OPENAI_BASE_URL", "").strip() or None,
        timeout=timeout,
        temperature=temperature,
    )
    tracer = Tracer(trace_path)
    started = time.monotonic()
    try:
        log.info("auditing %s with model %s", repo_url, model)
        if args.local_path:
            findings = _audit(Path(args.local_path), repo_url, llm, tracer, args)
        else:
            with cloned_repo(repo_url, timeout=args.clone_timeout) as root:
                findings = _audit(root, repo_url, llm, tracer, args)
    finally:
        tracer.close()

    write_report(output, build_report(repo_url, findings))
    print(
        f"Wrote {output} with {len(findings)} violation(s) in {time.monotonic() - started:.0f}s"
        + (f"; trace: {trace_path}" if trace_path else ""),
        file=sys.stderr,
    )
    return EXIT_OK


def _audit(root: Path, repo_url: str, llm: OpenAIChatClient, tracer: Tracer, args: argparse.Namespace):
    tools = RepoTools(root)
    agent = AuditAgent(
        llm,
        tools,
        repo_url,
        max_steps=args.max_steps,
        time_limit=args.time_limit,
        review=not args.no_review,
        tracer=tracer,
    )
    findings = agent.run()
    if not working_tree_is_clean(root):  # the tools are read-only; this guards against regressions
        log.warning("the inspected checkout is no longer clean; a tool may have written to it")
    log.info("tool usage: %s; tokens: %s", dict(agent.tool_calls_made), llm.total_usage)
    return findings


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    load_dotenv(Path(__file__).resolve().parent / ".env")  # real environment variables take precedence
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return run(args)
    except CloneError as exc:
        return _fail(EXIT_CLONE, f"could not clone repository: {exc}")
    except LLMError as exc:
        return _fail(EXIT_LLM, f"LLM failure: {exc}")
    except ToolError as exc:
        return _fail(EXIT_INPUT, str(exc))
    except KeyboardInterrupt:
        return _fail(130, "interrupted")
    except Exception as exc:  # noqa: BLE001 - last-resort handler so the CLI never dies with a raw traceback
        log.debug("unexpected error", exc_info=True)
        return _fail(EXIT_UNEXPECTED, f"unexpected {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    sys.exit(main())
