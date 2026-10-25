"""The agent loop: the LLM chooses which inspection tool to run next, we execute it and feed the result back.

observe (tool result) -> reason (assistant text) -> select tool (tool_calls) -> execute (RepoTools.call)
-> interpret (next LLM turn) ... -> report_violation / finish -> verification -> review pass -> report
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections import Counter
from typing import Any

from auditor.findings import (
    CATEGORIES,
    SEVERITIES,
    Finding,
    finalize,
    is_duplicate,
    normalize_finding,
    normalize_severity,
    verify_findings,
)
from auditor.llm import ChatClient, ContextLengthError, LLMError, LLMResponse, ToolCall
from auditor.prompts import (
    FINISH_CHECK,
    NUDGE_NO_TOOL,
    REPEATED_CALL,
    REVIEW_PROMPT,
    SYSTEM_PROMPT,
    USER_PROMPT,
    WRAP_UP,
)
from auditor.trace import Tracer
from tools import TOOL_NAMES, TOOL_SCHEMAS, RepoTools

log = logging.getLogger(__name__)

CONTROL_TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "report_violation",
            "description": "Record ONE verified DevOps violation. Call once per distinct problem.",
            "parameters": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string", "description": "e.g. SEC-001, CI-002"},
                    "category": {"type": "string", "enum": list(CATEGORIES)},
                    "severity": {"type": "string", "enum": list(SEVERITIES)},
                    "file": {"type": ["string", "null"], "description": "Repo-relative path or null"},
                    "line": {"type": ["integer", "null"], "description": "1-based line or null"},
                    "description": {"type": "string"},
                    "evidence": {"type": "string", "description": "What you observed. Never include secret values."},
                    "recommendation": {"type": "string"},
                    "confidence": {"type": "number", "description": "0.0-1.0"},
                },
                "required": [
                    "rule_id",
                    "category",
                    "severity",
                    "file",
                    "line",
                    "description",
                    "evidence",
                    "recommendation",
                    "confidence",
                ],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "End the investigation once all relevant inspection areas are covered.",
            "parameters": {
                "type": "object",
                "properties": {"summary": {"type": "string", "description": "One-paragraph audit summary"}},
                "required": ["summary"],
                "additionalProperties": False,
            },
        },
    },
]

# Files whose contents usually matter for a DevOps audit (settings, environment, container and CI config).
_CONFIG_LIKE = re.compile(
    r"(?:^|/)(?:[^/]*(?:settings|config|conf|prod|production|staging|deploy)[^/]*\.(?:py|ya?ml|json|toml|ini|cfg|env)"
    r"|\.env[^/]*|Dockerfile[^/]*|docker-compose[^/]*|Makefile|\.pre-commit-config\.yaml)$",
    re.IGNORECASE,
)

OMITTED = "[earlier tool output omitted to save context; re-run the tool if you still need it] "


class AuditAgent:
    def __init__(
        self,
        llm: ChatClient,
        tools: RepoTools,
        repo_url: str,
        *,
        max_steps: int = 40,
        time_limit: float = 900.0,
        max_context_chars: int = 220_000,
        review: bool = True,
        tracer: Tracer | None = None,
    ):
        self.llm = llm
        self.tools = tools
        self.repo_url = repo_url
        self.max_steps = max_steps
        self.time_limit = time_limit
        self.max_context_chars = max_context_chars
        self.review = review
        self.tracer = tracer or Tracer(None)
        self.messages: list[dict[str, Any]] = []
        self.findings: list[Finding] = []
        self.finished = False
        self.summary = ""
        self.steps_used = 0
        self.tool_calls_made: Counter[str] = Counter()
        self._call_counts: Counter[str] = Counter()
        self._wrapping_up = False
        self._finish_checked = False

    # ------------------------------------------------------------------ main loop
    def run(self) -> list[Finding]:
        self.messages = [
            {"role": "system", "content": SYSTEM_PROMPT.format(max_steps=self.max_steps)},
            {"role": "user", "content": USER_PROMPT.format(repo_url=self.repo_url)},
        ]
        self.tracer.log(
            "start", repository=self.repo_url, model=getattr(self.llm, "model", None), max_steps=self.max_steps
        )
        started = time.monotonic()
        idle_turns = 0
        for step in range(1, self.max_steps + 1):
            if time.monotonic() - started > self.time_limit:
                log.warning("time limit of %ss reached; wrapping up", self.time_limit)
                break
            self.steps_used = step
            resp = self._chat(TOOL_SCHEMAS + CONTROL_TOOL_SCHEMAS)
            self._handle(resp, step)
            if self.finished:
                break
            if resp.tool_calls:
                idle_turns = 0
            else:
                idle_turns += 1
                if idle_turns > 2:
                    log.warning("model stopped calling tools; wrapping up")
                    break
                self.messages.append({"role": "user", "content": NUDGE_NO_TOOL})
        if not self.finished:
            self._wrap_up()

        candidates = verify_findings(self.findings, self.tools)
        if self.review and candidates:
            candidates = self._review(candidates)
        final = finalize(candidates)
        self.tracer.log(
            "end",
            steps=self.steps_used,
            tool_calls=dict(self.tool_calls_made),
            recorded=len(self.findings),
            reported=len(final),
            summary=self.summary,
        )
        return final

    def _handle(self, resp: LLMResponse, step: int) -> None:
        self.messages.append(resp.to_message())
        self.tracer.log(
            "assistant",
            step=step,
            content=resp.content,
            tool_calls=[{"name": c.name, "arguments": c.arguments} for c in resp.tool_calls],
        )
        if resp.content:
            log.info("step %d reasoning: %s", step, resp.content.strip().replace("\n", " ")[:300])
        for call in resp.tool_calls:
            result = self._execute(call)
            self.messages.append({"role": "tool", "tool_call_id": call.id, "content": result})
            self.tracer.log("tool_result", step=step, name=call.name, arguments=call.arguments, result=result)

    def _execute(self, call: ToolCall) -> str:
        self.tool_calls_made[call.name] += 1
        try:
            args = json.loads(call.arguments or "{}")
        except json.JSONDecodeError as exc:
            return f"ERROR: tool arguments were not valid JSON ({exc}); call {call.name} again with a JSON object"
        if not isinstance(args, dict):
            return "ERROR: tool arguments must be a JSON object"
        if call.name == "report_violation":
            return self._record(args)
        if call.name == "finish":
            gaps = [] if (self._finish_checked or self._wrapping_up) else self._coverage_gaps()
            if gaps:  # one reflection round; a second finish is always accepted
                self._finish_checked = True
                self.tracer.log("finish_check", missing=gaps)
                return FINISH_CHECK.format(missing="; ".join(gaps))
            self.finished = True
            self.summary = str(args.get("summary", ""))
            return "Investigation finished."
        if call.name not in TOOL_NAMES:
            return f"ERROR: unknown tool {call.name!r}"
        if self._wrapping_up:
            return "ERROR: investigation budget exhausted; only report_violation and finish are allowed now"
        key = call.name + json.dumps({k: v for k, v in args.items() if k != "rationale"}, sort_keys=True)
        self._call_counts[key] += 1
        if self._call_counts[key] > 2:
            return REPEATED_CALL
        log.info("tool %s(%s) because: %s", call.name, json.dumps(args)[:200], str(args.get("rationale", ""))[:200])
        return self.tools.call(call.name, args)

    def _coverage_gaps(self) -> list[str]:
        """Inspection areas the agent has not touched at all (reminders only; the LLM decides what to do)."""
        made = self.tool_calls_made
        gaps = []
        if not made["git_log"]:
            gaps.append("review the commit history with git_log (deleted secrets, committed artefacts)")
        if not made["inspect_workflows"]:
            gaps.append("review CI configuration with inspect_workflows")
        if not made["search_code"]:
            gaps.append("search_code for hardcoded secrets and machine-specific absolute paths")
        if not made["run_ruff"] and any(f.endswith(".py") for f in self.tools.tracked_files()):
            gaps.append("run_ruff on the Python code")
        unread = [
            f for f in self.tools.tracked_files() if _CONFIG_LIKE.search(f) and f not in self.tools.observed_files
        ]
        if unread:
            gaps.append("read configuration/build files you have not opened yet: " + ", ".join(unread[:8]))
        return gaps

    def _record(self, args: dict[str, Any]) -> str:
        finding, error = normalize_finding(args)
        if finding is None:
            self.tracer.log("finding_rejected", reason=error, finding=args)
            return f"REJECTED: {error}. Fix the fields and call report_violation again."
        if not verify_findings([finding], self.tools):
            reason = (
                f"file {finding.file!r} is not a tracked file in this repository. Use the exact path from "
                "list_files, or file=null for repository-wide problems"
                if finding.file
                else f"confidence {finding.confidence} is too low to report"
            )
            self.tracer.log("finding_rejected", reason=reason, finding=args)
            return f"REJECTED: {reason}."
        for i, existing in enumerate(self.findings, 1):
            if is_duplicate(finding, existing):
                return f"NOT RECORDED: duplicate of finding #{i} ({existing.rule_id}: {existing.description})"
        self.findings.append(finding)
        self.tracer.log("finding_recorded", finding=finding.report_dict(), confidence=finding.confidence)
        note = "" if finding.line or not args.get("line") else " (line set to null: not verified against file contents)"
        return f"Recorded #{len(self.findings)} {finding.rule_id} [{finding.severity}]{note}."

    def _wrap_up(self) -> None:
        self._wrapping_up = True
        self.messages.append({"role": "user", "content": WRAP_UP})
        for extra in range(1, 4):
            try:
                resp = self._chat(CONTROL_TOOL_SCHEMAS)
            except LLMError as exc:
                log.warning("wrap-up call failed (%s); keeping findings recorded so far", exc)
                return
            self._handle(resp, self.steps_used + extra)
            if self.finished or not resp.tool_calls:
                return

    # ------------------------------------------------------------------ LLM + context management
    def _chat(self, tools: list[dict[str, Any]]) -> LLMResponse:
        self._trim(self.max_context_chars, keep_recent=8)
        try:
            return self.llm.chat(self.messages, tools=tools)
        except ContextLengthError:
            log.warning("context window exceeded; dropping older tool outputs and retrying")
            self._trim(self.max_context_chars // 3, keep_recent=2)
            return self.llm.chat(self.messages, tools=tools)

    def _context_size(self) -> int:
        return sum(len(str(m.get("content") or "")) + len(json.dumps(m.get("tool_calls", ""))) for m in self.messages)

    def _trim(self, limit: int, keep_recent: int) -> None:
        """Shorten old tool outputs (oldest first) until the conversation fits. Message order is preserved."""
        if self._context_size() <= limit:
            return
        for msg in self.messages[2 : max(2, len(self.messages) - keep_recent)]:
            content = str(msg.get("content") or "")
            if msg["role"] == "tool" and not content.startswith(OMITTED) and len(content) > 300:
                msg["content"] = OMITTED + "First line was: " + content.splitlines()[0][:200]
                if self._context_size() <= limit:
                    return

    # ------------------------------------------------------------------ review pass
    def _review(self, candidates: list[Finding]) -> list[Finding]:
        payload = [{"index": i, **f.report_dict(), "confidence": f.confidence} for i, f in enumerate(candidates)]
        messages = [
            {"role": "system", "content": REVIEW_PROMPT},
            {"role": "user", "content": json.dumps({"repository": self.repo_url, "candidates": payload}, indent=1)},
        ]
        try:
            resp = self.llm.chat(messages, json_mode=True)
            data = json.loads(resp.content or "")
            decisions = {
                d["index"]: d
                for d in data.get("decisions", [])
                if isinstance(d, dict) and isinstance(d.get("index"), int)
            }
        except (LLMError, json.JSONDecodeError, AttributeError, TypeError) as exc:
            log.warning("review pass failed (%s); keeping all verified findings", exc)
            self.tracer.log("review_failed", error=str(exc))
            return candidates

        kept: list[Finding] = []
        kept_idx: set[int] = set()
        for i, f in enumerate(candidates):
            d = decisions.get(i, {})
            dup = d.get("duplicate_of")
            if d.get("keep") is False or (isinstance(dup, int) and dup < i and dup in kept_idx):
                self.tracer.log("review_dropped", finding=f.report_dict(), reason=d.get("reason"))
                continue
            severity = normalize_severity(d.get("severity"))
            if severity and severity != f.severity:
                self.tracer.log("review_severity", rule_id=f.rule_id, old=f.severity, new=severity)
                f.severity = severity
            kept.append(f)
            kept_idx.add(i)
        log.info("review kept %d of %d candidate findings", len(kept), len(candidates))
        return kept
