# DevOps Repository Auditing Agent

An LLM-driven agent that audits a public GitHub repository for DevOps best-practice violations and writes
an evidence-based JSON report. The LLM decides the investigation: which file to open, what to search for,
and when to dig into git history or CI workflows. A hand-written Python loop executes those tool calls
against a read-only clone. No agent frameworks are used (no LangChain, LangGraph or n8n). The only LLM
dependency is the `openai` SDK.

```
python agent.py --repo https://github.com/<owner>/<repo> --output report.json
```

## 1. Installation

Requirements: **Python 3.10+** and **git** on `PATH`.

**Option A: uv (recommended)**

```bash
git clone https://github.com/Quttoshi/devops-audit-agent.git
cd devops-audit-agent
uv sync                      # creates .venv with the exact locked versions (uv.lock)
```

Then prefix commands with `uv run`, e.g. `uv run python agent.py ...`.

**Option B: pip**

```bash
git clone https://github.com/Quttoshi/devops-audit-agent.git
cd devops-audit-agent
python -m venv .venv
# Windows: .venv\Scripts\activate      Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt        # add -r requirements-dev.txt to run the tests
```

## 2. Configuration

```bash
cp .env.example .env         # Windows PowerShell: Copy-Item .env.example .env
```

Edit `.env`:

| Variable | Required | Meaning |
|---|---|---|
| `OPENAI_API_KEY` | yes | OpenAI API key |
| `OPENAI_MODEL` | no | Chat model with function calling (default `gpt-4.1`) |
| `OPENAI_BASE_URL` | no | OpenAI-compatible endpoint (Azure OpenAI, OpenRouter, Ollama, ...) |
| `OPENAI_TIMEOUT` | no | Per-request timeout in seconds (default 120) |
| `OPENAI_TEMPERATURE` | no | Sampling temperature (unset = model default) |
| `AGENT_MAX_STEPS` | no | Maximum investigation rounds (default 40) |

Real environment variables override `.env`. The key is never logged or written to any output.

## 3. Usage

```bash
python agent.py --repo https://github.com/example/demo-project --output report.json
```

| Option | Default | Description |
|---|---|---|
| `--repo` | (required) | Public GitHub URL (`https://github.com/owner/repo`, `.git` suffix allowed) |
| `--output` | (required) | Report path (parent directories are created) |
| `--model` | `$OPENAI_MODEL` / `gpt-4.1` | Model override |
| `--max-steps` | 40 | LLM/tool rounds before a forced wrap-up |
| `--time-limit` | 900 | Investigation wall-clock limit (seconds) |
| `--clone-timeout` | 300 | `git clone` timeout (seconds) |
| `--trace` | `<output>.trace.jsonl` | JSONL trace of reasoning and tool calls; `none` disables |
| `--no-review` | off | Skip the final precision review pass |
| `-v` | off | Log every reasoning step and tool call to stderr |

The run is fully unattended. Progress and errors go to stderr; the report is written atomically.

**Exit codes**

| Code | Meaning |
|---|---|
| 0 | Inspection completed, report written (an empty `violations` array if nothing was found) |
| 1 | Unexpected internal error |
| 2 | Invalid input or configuration (bad URL, missing `OPENAI_API_KEY`, bad arguments) |
| 3 | Repository could not be cloned (does not exist, private, network failure, timeout) |
| 4 | LLM API failure after retries (auth, quota, model not found, outage) |

### Output format

```json
{
  "repository": "https://github.com/example/demo-project",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config.py",
      "line": 17,
      "description": "Hardcoded API credential",
      "evidence": "AWS_SECRET_ACCESS_KEY is assigned a literal value ([REDACTED]) on line 17",
      "recommendation": "Load the credential from an environment variable or secrets manager and rotate it"
    }
  ]
}
```

* `severity` is one of `critical`, `high`, `medium`, `low`.
* `category` is one of `repository_hygiene`, `dependency_management`, `code_quality`, `testing`, `ci_cd`,
  `security`, `configuration`, `collaboration`, `build_release`.
* `rule_id` prefixes: `HYG`, `DEP`, `CQ`, `TEST`, `CI`, `SEC`, `CFG`, `COL`, `BLD`.
* `file` / `line` are JSON `null` for repository-wide findings. Secret values are never reproduced.

See [sample_report.json](sample_report.json) for an authentic run and [sample_trace.jsonl](sample_trace.jsonl) for
its tool-call trace.

## 4. Architecture

```
agent.py (CLI) ── validate URL ── clone (temp dir, read-only) ── AuditAgent.run() ── verify ── review ── report.json
                                                                       │
              ┌────────────────────────────────────────────────────────┴───────────────┐
              │  messages = [system prompt, "audit <url>"]                             │
              │  loop (≤ max_steps, ≤ time limit):                                     │
              │    LLM ──► reasoning text + tool_calls     (Reason / Select tool)      │
              │    for each call: RepoTools.call(name,args) (Execute, redacted+capped) │
              │    tool results appended to messages        (Observe / Interpret)      │
              │    report_violation ─► validated + verified immediately (feedback)     │
              │    finish ─► stop                                                       │
              │  budget exhausted ─► wrap-up turn (only report_violation / finish)     │
              └────────────────────────────────────────────────────────────────────────┘
```

| Module | Responsibility |
|---|---|
| [agent.py](agent.py) | CLI arguments, configuration, exit codes, orchestration |
| [tools.py](tools.py) | Inspection tools, OpenAI function schemas, safe dispatch (`RepoTools.call`) |
| [auditor/loop.py](auditor/loop.py) | Agent loop: tool dispatch, budgets, context trimming, wrap-up, review pass |
| [auditor/llm.py](auditor/llm.py) | OpenAI Chat Completions wrapper: retries, timeouts, error mapping |
| [auditor/prompts.py](auditor/prompts.py) | Investigation guidance, evidence rules, severity rubric, review prompt |
| [auditor/findings.py](auditor/findings.py) | Finding validation, evidence verification, de-duplication, report writing |
| [auditor/redact.py](auditor/redact.py) | Secret detection and masking for all tool output, traces and the report |
| [auditor/repo.py](auditor/repo.py) | URL validation, hardened `git clone`, cleanup |
| [auditor/trace.py](auditor/trace.py) | JSONL trace of every reasoning step and tool call |

### Inspection tools

| Tool | Purpose |
|---|---|
| `list_files(path, max_depth)` | Tracked (committed) files with sizes; deep directories collapsed |
| `read_file(path, start_line, end_line)` | Line-numbered contents (≤ 400 lines per call) |
| `search_code(pattern, path_glob, max_results, ignore_case)` | Regex search across tracked text files |
| `git_log(max_count, path)` | Commit history with added/modified/deleted files |
| `git_show(revision, path)` | A commit's patch or a file at an old revision (e.g. secrets deleted later) |
| `check_gitignore(paths)` | Is a path tracked, and would `.gitignore` ignore it? |
| `inspect_workflows()` | Parsed GitHub Actions: triggers vs default branch, permissions, test/lint/build/deploy steps, risk signals with line numbers; lists other CI systems |
| `run_ruff(path)` | Static lint with ruff (parses code, never runs it) |
| `report_violation(...)` / `finish(summary)` | Control tools used by the LLM to record findings and end |

The LLM chooses every call; nothing is run up front. The workflow "signals" are hints that the prompt tells
the model to verify by reading the referenced lines.

### How false positives are kept down

1. **Prompted evidence rules**: report only what a tool showed in this run. Accept equivalent alternatives
   (pyproject/poetry/uv, any linter or CI system). Never infer branch protection. Treat placeholders as non-secrets.
2. **Immediate validation**: `report_violation` rejects unknown categories or severities, missing evidence, and
   files that don't exist in the repo. The model gets the reason back and can correct itself.
3. **Evidence verification**: a line number is kept only if the agent actually read or searched that file and
   the line exists. Low-confidence findings are dropped.
4. **De-duplication**: findings with the same file, category and line, or near-identical wording, are merged.
5. **Review pass**: a separate LLM call checks all candidates against the evidence rules. It drops
   speculative ones and can correct severities.

## 5. Safety

* Only the URL form `https://github.com/<owner>/<repo>` is accepted. The clone goes into a private temp
  directory that is always deleted afterwards. Hooks, submodules, LFS downloads, credential prompts and
  symlinks are disabled during the clone.
* No code from the target repository is ever executed. `run_ruff` is a static parser run with `--no-cache`.
  The tests are read, not run.
* Every tool is confined to the clone: absolute paths, `..`, symlink escapes and `.git/` internals are refused.
  After the audit the agent checks that `git status` is clean, which proves the checkout was not modified.
* Secrets are masked (`[REDACTED:<kind>]`) before any text reaches the LLM, the trace, the logs or the report.
* Tool output is size-capped, all subprocesses have timeouts, and API calls are retried with backoff.
  Malformed tool arguments are returned to the model as errors instead of crashing the run.

## 6. Tests

```bash
uv run pytest            # or: pytest   (after pip install -r requirements-dev.txt)
uv run ruff check .
```

The tests run offline without an API key. They build temporary git repositories with injected defects and
drive the loop with a scripted fake LLM. Coverage includes every tool, path-traversal protection, redaction,
the loop (result-driven tool choice, parallel calls, bad arguments, budget wrap-up, context overflow, review
pass), the JSON contract and the CLI exit codes.

### Measuring precision / recall

[eval/](eval/) contains three local fixture repositories that mirror the hidden-evaluation types: (A) obvious
defects, (B) subtle CI/security/config defects, and (C) a healthy repo that uses acceptable alternatives. It
also holds their known-defect lists. This uses the real LLM:

```bash
uv run python eval/build_fixtures.py
uv run python eval/run_eval.py            # per-fixture and overall precision / recall
```

Results with `gpt-4.1` during development (one run each; LLM output varies between runs):

| Iteration | A (obvious) P / R | B (subtle) P / R | C (healthy) reported | Overall P / R |
|---|---|---|---|---|
| Baseline | 0.82 / 0.82 | 1.00 / 0.82 | 0 | 0.90 / 0.82 |
| + per-file secrets, finish check, rationale | 1.00 / 0.92 | 0.88 / 0.64 | 0 | 0.95 / 0.78 |
| + history-file evidence, lenient tool args | 0.92 / 1.00 | 0.69 / 0.82 | 0 | 0.81 / 0.91 |
| + review-pass facts, cross-category dedupe | 1.00 / 0.92 | 0.79 / 1.00 | 0 | 0.88 / 0.96 |
| + `.gitignore` directory-pattern fix, weak-constraint rule | 1.00 / 0.83 | 1.00 / 0.91 | 0 | 1.00 / 0.87 |

Each change was driven by reading the tool-call traces. For example, the review pass had wrongly dismissed
a `${{ github.head_ref }}` injection inside an `echo`. On the real-world repository `pallets/itsdangerous`,
the agent reported a single, borderline finding.

## 7. Limitations

* Only public GitHub repositories; the default branch is audited.
* Tests are not executed (no sandbox is assumed), so "failing tests" are only detected when visible
  statically (syntax errors, `assert False`, imports of missing modules, tests never run in CI).
* Repository settings (branch protection, secret scanning, required reviews) are not visible in files and
  are deliberately never reported.
* Results depend on the model; `gpt-4.1` or stronger is recommended.
