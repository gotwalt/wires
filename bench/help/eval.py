#!/usr/bin/env python3
"""Help-text eval driver (board card 38).

Runs headless `claude -p` sessions, one fresh session per run, each allowed
only `Bash(wires:*)` against the loopback network `bench/help/up.sh`
provisions (locked mode, as `bench/`'s token benchmark sets it up), and
appends one JSON line per run. The model is told nothing about wires but
that it is on PATH: whatever it knows, it read from `wires` itself.

Tasks:
  find     find the service that reports deploy status (ANSWER: its name)
  call     count the orders and find the largest total (ANSWER: n max)
  refused  get the payroll summary; the host refuses it (exit 77): say why
           and what next, without working around it
  premise  what is wires, and the exact command that queries the orders
           database: must be by service name, never a host or address

Per run: turns, tokens, cost, the wires commands run, and `guessed`: the
tool results that show the model guessed a flag or subcommand (a clap
usage error, or a locked-mode refusal of an override flag).
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
import time

MODEL = os.environ.get("HELP_EVAL_MODEL", "sonnet")
RUN_TIMEOUT = 300

PREAMBLE = (
    "You have a command-line program `wires` on your PATH; it is the only program you may run "
    "(through Bash). Work it out from the program itself.\n\n"
)
ANSWER_RULE = "\n\nFinish your reply with exactly one final line that starts with `ANSWER:` in this format: {fmt}"

TASKS = {
    "find": {
        "prompt": "Which wires service reports the deploy status of the production apps? Name it; don't call it.",
        "fmt": "`ANSWER: <service name>`",
    },
    "call": {
        "prompt": "How many orders are in the orders database, and what is the largest order total?",
        "fmt": "`ANSWER: <count> <largest total>`",
    },
    "refused": {
        "prompt": "Get the payroll totals for the engineering team. If you can't, say why, and what the "
        "next step is.",
        "fmt": "`ANSWER: <done|refused> <the next step, in a few words>`",
    },
    "premise": {
        "prompt": "In two or three sentences: what is wires, and how would you query the orders database "
        "with it? Give the exact command you would run (you may run it too).",
        "fmt": "`ANSWER: <the exact command>`",
    },
}

# Tool-result text that means the model guessed a flag or subcommand.
GUESS_MARKERS = [
    "error: unexpected argument",
    "error: unrecognized subcommand",
    "error: invalid value",
    "error: a value is required",
    "is not allowed in locked mode",
]
ADDRESS = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b|\bssh\b|\bip address\b|--relay-url|host address", re.I)


def answer_line(text: str) -> str | None:
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip().strip("`*")
        if line.upper().startswith("ANSWER:"):
            return line[len("ANSWER:") :].strip()
    return None


def score(task: str, ans: str | None, text: str, commands: list[str]) -> bool:
    if ans is None:
        return False
    a = ans.lower()
    if task == "find":
        return "deploy-status" in a
    if task == "call":
        nums = re.findall(r"\d+(?:\.\d+)?", a)
        return (
            os.environ["HELP_EVAL_ORDERS"] in nums
            and any(float(n) == float(os.environ["HELP_EVAL_MAX_TOTAL"]) for n in nums)
        )
    if task == "refused":
        tries = sum(1 for c in commands if "payroll" in c and " call " in f" {c} ")
        return a.startswith("refused") and tries <= 2
    if task == "premise":
        return "wires call orders-db" in a and not ADDRESS.search(text or "")
    raise ValueError(task)


def run_one(label: str, task: str, rep: int, workdir: pathlib.Path, rawdir: pathlib.Path) -> dict:
    keep = ["HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "SHELL", "LANG"]
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(
        {
            "TERM": "dumb",
            "NO_COLOR": "1",
            "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "WIRES_HOME": os.environ["WIRES_HOME"],
            "WIRES_LOCKED": "1",
            "PATH": os.environ["HELP_EVAL_BIN_DIR"] + ":" + os.environ["PATH"],
        }
    )
    t = TASKS[task]
    prompt = PREAMBLE + t["prompt"] + ANSWER_RULE.format(fmt=t["fmt"])
    cmd = [
        "claude",
        "-p",
        "--model",
        MODEL,
        "--output-format",
        "stream-json",
        "--verbose",
        "--no-session-persistence",
        "--strict-mcp-config",
        "--setting-sources",
        "project",
        "--disable-slash-commands",
        "--tools=Bash",
        "--allowedTools=Bash(wires:*)",
        "--",
        prompt,
    ]
    wd = workdir / f"{label}-{task}-{rep}"
    wd.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, cwd=wd, env=env, capture_output=True, text=True, timeout=RUN_TIMEOUT, stdin=subprocess.DEVNULL
        )
        out, rc = p.stdout, p.returncode
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        rc = -1
    wall = time.time() - t0
    (rawdir / f"{label}.{task}.r{rep}.jsonl").write_text(out)

    result, commands, guessed = None, [], []
    for line in out.splitlines():
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if m.get("type") == "result":
            result = m
        for c in (m.get("message") or {}).get("content") or []:
            if not isinstance(c, dict):
                continue
            if c.get("type") == "tool_use":
                commands.append((c.get("input") or {}).get("command", ""))
            elif c.get("type") == "tool_result":
                body = c.get("content")
                if isinstance(body, list):
                    body = " ".join(x.get("text", "") for x in body if isinstance(x, dict))
                hit = [g for g in GUESS_MARKERS if g in (body or "")]
                if hit:
                    guessed.append(hit[0])
    u = (result or {}).get("usage", {})
    text = (result or {}).get("result", "")
    ans = answer_line(text)
    total_in = u.get("input_tokens", 0) + u.get("cache_creation_input_tokens", 0) + u.get("cache_read_input_tokens", 0)
    return {
        "label": label,
        "task": task,
        "rep": rep,
        "model": MODEL,
        "rc": rc,
        "correct": score(task, ans, text, commands),
        "answer": ans,
        "num_turns": (result or {}).get("num_turns"),
        "total_input_tokens": total_in,
        "output_tokens": u.get("output_tokens", 0),
        "cost_usd": (result or {}).get("total_cost_usd", 0.0),
        "wall_s": round(wall, 1),
        "commands": commands,
        "help_reads": sum(1 for c in commands if "--help" in c or c.strip().endswith(" help")),
        "guessed": guessed,
        "permission_denials": len((result or {}).get("permission_denials") or []),
        "result_tail": (text or "")[-500:],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True, help="before / after: which binary this run used")
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--reps", type=int, default=2)
    ap.add_argument("--tasks", default=",".join(TASKS))
    ap.add_argument("--budget", type=float, default=3.0, help="stop once this many USD are spent")
    args = ap.parse_args()
    raw = pathlib.Path(args.raw)
    raw.mkdir(parents=True, exist_ok=True)
    work = raw / "work"
    spent = 0.0
    with open(args.out, "a") as f:
        for rep in range(args.reps):
            for task in args.tasks.split(","):
                if spent >= args.budget:
                    print(f"budget ${args.budget} reached", file=sys.stderr)
                    return 0
                r = run_one(args.label, task, rep, work, raw)
                spent += r["cost_usd"] or 0.0
                f.write(json.dumps(r) + "\n")
                f.flush()
                print(
                    f"{args.label:6} {task:8} rep{rep} ok={r['correct']!s:5} turns={r['num_turns']} "
                    f"in={r['total_input_tokens']:>6} out={r['output_tokens']:>5} ${r['cost_usd']:.4f} "
                    f"help={r['help_reads']} guessed={len(r['guessed'])} ans={r['answer']!r}",
                    file=sys.stderr,
                )
    print(f"spent ${spent:.4f}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
