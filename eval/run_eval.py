"""Run the agent on the local fixtures and report precision / recall against eval/expected/*.json.

    uv run python eval/build_fixtures.py
    uv run python eval/run_eval.py [--only b_subtle] [--model gpt-4.1]

A reported violation matches a known defect when its category is one of the defect's categories, its file is
one of the accepted files (null = repository-wide), and - if keywords are given - its description/evidence
mentions at least one keyword. Each reported violation can match at most one defect (duplicates score nothing).
Requires OPENAI_API_KEY (uses the real LLM).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent


def matches(v: dict, e: dict) -> bool:
    if v.get("category") not in e["categories"]:
        return False
    vf = v.get("file")
    if vf not in e["files"] and not any(f and vf and vf.startswith(f.rstrip("/") + "/") for f in e["files"]):
        return False
    text = f"{v.get('description', '')} {v.get('evidence', '')} {v.get('file') or ''}".lower()
    return not e["keywords"] or any(k.lower() in text for k in e["keywords"])


def score(reported: list[dict], expected: list[dict]) -> tuple[int, list[str], list[dict]]:
    used: set[int] = set()
    hit: list[str] = []
    for e in expected:
        for i, v in enumerate(reported):
            if i not in used and matches(v, e):
                used.add(i)
                hit.append(e["id"])
                break
    unmatched = [v for i, v in enumerate(reported) if i not in used]
    return len(hit), hit, unmatched


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--only", help="run a single fixture")
    p.add_argument("--model", help="override OPENAI_MODEL")
    args = p.parse_args()
    out_dir = HERE / "results"
    out_dir.mkdir(exist_ok=True)
    tot_tp = tot_rep = tot_exp = 0
    for exp_file in sorted((HERE / "expected").glob("*.json")):
        name = exp_file.stem
        if args.only and name != args.only:
            continue
        fixture = HERE / "fixtures" / name
        if not fixture.exists():
            print(f"missing fixture {fixture}; run eval/build_fixtures.py first", file=sys.stderr)
            return 2
        out = out_dir / f"{name}.json"
        cmd = [
            sys.executable,
            str(ROOT / "agent.py"),
            "--repo",
            f"https://github.com/eval/{name}",
            "--output",
            str(out),
            "--local-path",
            str(fixture),
            "--trace",
            str(out_dir / f"{name}.trace.jsonl"),
        ]
        if args.model:
            cmd += ["--model", args.model]
        print(f"== {name}: running agent ...", flush=True)
        proc = subprocess.run(cmd, cwd=ROOT, check=False)
        if proc.returncode != 0:
            print(f"   agent failed with exit code {proc.returncode}")
            continue
        reported = json.loads(out.read_text(encoding="utf-8"))["violations"]
        expected = json.loads(exp_file.read_text(encoding="utf-8"))
        tp, hit, unmatched = score(reported, expected)
        precision = tp / len(reported) if reported else 1.0
        recall = tp / len(expected) if expected else 1.0
        print(
            f"   reported={len(reported)} expected={len(expected)} matched={tp} "
            f"precision={precision:.2f} recall={recall:.2f}"
        )
        missed = [e["id"] for e in expected if e["id"] not in hit]
        if missed:
            print(f"   missed: {', '.join(missed)}")
        for v in unmatched:
            print(f"   unmatched report: [{v['severity']}] {v['category']} {v['file']}:{v['line']} {v['description']}")
        tot_tp, tot_rep, tot_exp = tot_tp + tp, tot_rep + len(reported), tot_exp + len(expected)
    if tot_rep or tot_exp:
        print(
            f"\nOVERALL precision={tot_tp / tot_rep if tot_rep else 1:.2f} "
            f"recall={tot_tp / tot_exp if tot_exp else 1:.2f}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
