from __future__ import annotations

import json

import pytest
from conftest import FAKE_AWS_KEY, FakeLLM, multi_call, tool_call, violation

from auditor.llm import ContextLengthError, LLMError, LLMResponse, ToolCall
from auditor.loop import OMITTED, AuditAgent
from auditor.trace import Tracer
from tools import RepoTools

URL = "https://github.com/example/demo"


def make_agent(repo, llm, **kw):
    return AuditAgent(llm, RepoTools(repo), URL, tracer=Tracer(None), **kw)


def last_tool_output(messages) -> str:
    return next(m["content"] for m in reversed(messages) if m["role"] == "tool")


def test_full_cycle_with_result_driven_tool_choice(defective_repo):
    """The second tool call is derived from what the first tool returned (observe -> reason -> act)."""

    def choose_file(messages):
        listing = last_tool_output(messages)
        target = next(line.split()[0] for line in listing.splitlines() if "config" in line)
        return tool_call("read_file", content=f"{target} looks like configuration; reading it.", path=target)

    def report_if_secret(messages):
        assert "[REDACTED:aws_access_key]" in last_tool_output(messages)
        return tool_call("report_violation", **violation())

    llm = FakeLLM(
        [tool_call("list_files"), choose_file, report_if_secret, tool_call("finish", summary="one issue")],
        review=json.dumps({"decisions": [{"index": 0, "keep": True}]}),
    )
    agent = make_agent(defective_repo, llm)
    findings = agent.run()

    assert [f.rule_id for f in findings] == ["SEC-001"]
    assert findings[0].line == 3
    assert agent.tool_calls_made["read_file"] == 1
    assert agent.finished
    # every tool_call id is answered by exactly one tool message, in order
    ids = [c["id"] for m in agent.messages if m["role"] == "assistant" for c in m.get("tool_calls", [])]
    answered = [m["tool_call_id"] for m in agent.messages if m["role"] == "tool"]
    assert ids == answered
    assert FAKE_AWS_KEY not in json.dumps(agent.messages)
    assert llm.calls[-1]["json_mode"]  # review pass ran


def test_parallel_tool_calls(defective_repo):
    llm = FakeLLM([multi_call(("git_log", {}), ("inspect_workflows", {}), ("check_gitignore", {"paths": [".env"]}))])
    agent = make_agent(defective_repo, llm)
    agent.run()
    assert agent.tool_calls_made["git_log"] == agent.tool_calls_made["inspect_workflows"] == 1
    tool_msgs = [m for m in agent.messages if m["role"] == "tool"]
    assert any("pull_request_target" in m["content"] for m in tool_msgs)


def test_bad_arguments_and_unknown_tool_do_not_crash(defective_repo):
    bad_json = LLMResponse(content="oops", tool_calls=[ToolCall("c1", "read_file", "{not json")])
    llm = FakeLLM([bad_json, tool_call("delete_repo"), tool_call("read_file", path="../../etc/passwd")])
    agent = make_agent(defective_repo, llm)
    agent.run()
    outputs = [m["content"] for m in agent.messages if m["role"] == "tool"]
    assert outputs[0].startswith("ERROR: tool arguments were not valid JSON")
    assert outputs[1].startswith("ERROR: unknown tool")
    assert outputs[2].startswith("ERROR: path escapes")


def test_report_violation_validation_feedback(defective_repo):
    llm = FakeLLM(
        [
            tool_call("report_violation", **violation(severity="urgent")),
            tool_call("report_violation", **violation(file="ghost.py", description="Key in ghost file")),
            tool_call("report_violation", **violation()),
            tool_call("report_violation", **violation(rule_id="SEC-002")),  # same file/line/category
        ]
    )
    agent = make_agent(defective_repo, llm, review=False)
    findings = agent.run()
    outputs = [m["content"] for m in agent.messages if m["role"] == "tool"]
    assert outputs[0].startswith("REJECTED: severity")
    assert outputs[1].startswith("REJECTED: file 'ghost.py'")
    assert outputs[2].startswith("Recorded #1") and "line set to null" in outputs[2]  # file never read
    assert outputs[3].startswith("NOT RECORDED: duplicate")
    assert len(findings) == 1


def test_budget_exhaustion_forces_wrap_up(defective_repo):
    llm = FakeLLM(
        [tool_call("list_files"), tool_call("git_log"), tool_call("report_violation", **violation(line=None))]
    )
    agent = make_agent(defective_repo, llm, max_steps=2, review=False)
    findings = agent.run()
    assert len(findings) == 1
    wrap_call = llm.calls[2]
    assert set(wrap_call["tools"]) == {"report_violation", "finish"}
    assert "budget is exhausted" in wrap_call["messages"][-1]["content"]


def test_review_pass_drops_and_reclassifies(defective_repo):
    llm = FakeLLM(
        [
            tool_call("report_violation", **violation(line=None)),
            tool_call(
                "report_violation",
                **violation(
                    rule_id="COL-001",
                    category="collaboration",
                    severity="medium",
                    file=None,
                    line=None,
                    description="Branch protection is not enabled on main",
                ),
            ),
        ],
        review=json.dumps(
            {
                "decisions": [
                    {"index": 0, "keep": True, "severity": "high"},
                    {"index": 1, "keep": False, "reason": "branch protection is not visible in files"},
                ]
            }
        ),
    )
    findings = make_agent(defective_repo, llm).run()
    assert [(f.rule_id, f.severity) for f in findings] == [("SEC-001", "high")]


def test_review_failure_keeps_findings(defective_repo):
    llm = FakeLLM([tool_call("report_violation", **violation(line=None))], review=LLMError("down"))
    assert len(make_agent(defective_repo, llm).run()) == 1
    llm = FakeLLM([tool_call("report_violation", **violation(line=None))], review="not json")
    assert len(make_agent(defective_repo, llm).run()) == 1


def test_no_violations_on_finish(healthy_repo):
    llm = FakeLLM([tool_call("list_files"), tool_call("finish", summary="healthy")])
    assert make_agent(healthy_repo, llm).run() == []


def test_idle_model_is_nudged_then_stopped(defective_repo):
    idle = LLMResponse(content="I think the repo is fine.")
    llm = FakeLLM([idle, idle, idle, idle])
    agent = make_agent(defective_repo, llm)
    assert agent.run() == []
    nudges = [m for m in agent.messages if m["role"] == "user" and "did not call any tool" in m["content"]]
    assert len(nudges) == 2


def test_repeated_identical_calls_are_blocked(defective_repo):
    llm = FakeLLM([tool_call("git_log"), tool_call("git_log"), tool_call("git_log")])
    agent = make_agent(defective_repo, llm)
    agent.run()
    outputs = [m["content"] for m in agent.messages if m["role"] == "tool"]
    assert outputs[2].startswith("You already made this exact call")


def test_context_trimming_and_overflow_retry(defective_repo):
    script = [
        tool_call("inspect_workflows"),  # long output, oldest -> trimmed first
        tool_call("read_file", path="app/config.py"),
        tool_call("git_log"),
        ContextLengthError("too long"),
        tool_call("list_files"),
    ]
    llm = FakeLLM(script)
    agent = make_agent(defective_repo, llm, max_context_chars=4000)
    agent.run()
    tool_msgs = [m for m in agent.messages if m["role"] == "tool"]
    assert tool_msgs[0]["content"].startswith(OMITTED)
    assert agent.tool_calls_made["list_files"] == 1  # the call after the overflow went through


def test_early_finish_gets_one_coverage_reminder(defective_repo):
    llm = FakeLLM([tool_call("list_files"), tool_call("finish", summary="early"), tool_call("finish", summary="sure")])
    agent = make_agent(defective_repo, llm)
    agent.run()
    outputs = [m["content"] for m in agent.messages if m["role"] == "tool"]
    assert outputs[1].startswith("Before finishing") and "git_log" in outputs[1] and "run_ruff" in outputs[1]
    assert "app/config.py" in outputs[1] and ".env" in outputs[1]  # unread config files are listed
    assert outputs[2] == "Investigation finished." and agent.summary == "sure"


def test_no_reminder_when_areas_were_covered(healthy_repo):
    calls = [("git_log", {}), ("inspect_workflows", {}), ("search_code", {"pattern": "key"}), ("run_ruff", {})]
    llm = FakeLLM([multi_call(*calls), tool_call("finish", summary="covered")])
    agent = make_agent(healthy_repo, llm)
    agent.run()
    assert agent.summary == "covered"


def test_rationale_is_logged_but_not_passed_to_tool(defective_repo):
    llm = FakeLLM([tool_call("read_file", path="README.md", rationale="Check the docs first.")])
    tracer = Tracer(None)
    AuditAgent(llm, RepoTools(defective_repo), URL, tracer=tracer).run()
    result = next(e for e in tracer.events if e["event"] == "tool_result")
    assert "Check the docs first." in result["arguments"]
    assert result["result"].startswith("README.md (lines 1-")


def test_fatal_llm_error_propagates(defective_repo):
    llm = FakeLLM([LLMError("auth failed")])
    with pytest.raises(LLMError):
        make_agent(defective_repo, llm).run()


def test_trace_records_reasoning_and_tools(defective_repo, tmp_path):
    trace = tmp_path / "trace.jsonl"
    llm = FakeLLM([tool_call("read_file", content="Check config for secrets.", path="app/config.py")])
    tracer = Tracer(trace)
    AuditAgent(llm, RepoTools(defective_repo), URL, tracer=tracer).run()
    tracer.close()
    events = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    kinds = [e["event"] for e in events]
    assert kinds[0] == "start" and kinds[-1] == "end" and "tool_result" in kinds
    assert any(e.get("content") == "Check config for secrets." for e in events)
    assert FAKE_AWS_KEY not in trace.read_text(encoding="utf-8")
