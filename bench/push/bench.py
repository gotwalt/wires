#!/usr/bin/env python3
"""Push vs poll benchmark driver (board card 24).

One task, three ways to wait for it. The agent starts a CI build on a remote
host (`wires call deploy -- build <n>`); the build fails after a fixed time;
the agent must then read the build's log (`wires call logs`) and report the
failing test and the `left:` value of its assertion. Only the waiting differs:

  poll        check `wires call status -- build <n>` until it isn't running,
              `sleep` allowed between checks -- how the MCP tasks extension
              (`tasks/get`) works: the client asks until the answer changes.
  loop-inbox  check `wires inbox` until the build's message arrives, `sleep`
              allowed between checks -- the no-harness-change path.
  poll-loop   (extra) poll, with shell loops allowed: `until ! wires call status
              … | grep -q running; do sleep N; done` is one blocking call.
  wait        run `wires inbox --wait --timeout 10m` once: a blocking Bash call
              that returns when the push lands. Headless `claude -p` kills
              background commands when the turn ends (checked 2026-09-23 on
              Claude Code 2.1.280), so this is a *foreground* call. It costs one
              tool call and zero model turns while blocked; an interactive
              session's background command costs the same, minus the block.

Every arm gets the same permissions (deploy / status / logs / inbox / sleep),
the same model, and the same Bash timeout (10 min); the prompts differ only in
the one sentence that says how to wait. Each arm has its own agent keystore
(bench/push/up.sh), so parallel lanes never share a mailbox. The mock CI logs
every tool call with a millisecond timestamp and the moment each build
finished, so the reaction latency is measured on the host:

  latency = first `logs` call for build <n> at or after it finished
            - the moment it finished

Appends one JSON line per run to bench/push/results/<date>.jsonl.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import pathlib
import random
import subprocess
import sys
import threading
import time

MODEL = os.environ.get("BENCH_MODEL", "opus")
RUN_TIMEOUT = 1200  # seconds per claude -p run
D = pathlib.Path(os.environ.get("BENCH_PUSH_DIR", "/tmp/wb24"))
JOBS = D / "jobs"

COMMON = (
    "You're working with a CI system on a remote machine, reached through the `wires` CLI "
    "from Bash. Start build {n} with `wires call deploy -- build {n}`. The build takes a "
    "while. When it has finished, read its log with `wires call logs -- build {n} --tail 50` "
    "and find which test failed and the `left:` value of its failing assertion.\n\n"
    "{how}\n\n"
    "Finish your reply with exactly one final line in this format: "
    "`ANSWER: <failing test name> | <left value>`"
)

HOW = {
    "poll": "To find out when the build has finished, check `wires call status -- build {n}` "
    "until it no longer says running. You may run `sleep <seconds>` between checks.",
    "loop-inbox": "The CI pushes a message to you when the build finishes. `wires inbox` prints "
    "your pending messages and exits (it prints nothing if there are none). Check it until the "
    "build-{n} message arrives. You may run `sleep <seconds>` between checks.",
    "poll-loop": "To find out when the build has finished, check `wires call status -- build {n}` "
    "until it no longer says running. You may run `sleep <seconds>` between checks, and you may "
    "write the whole wait as one shell loop (`until`/`while`/`for`, with `grep`) in a single Bash call.",
    "wait": "The CI pushes a message to you when the build finishes. `wires inbox --wait "
    "--timeout 10m` blocks until a message arrives, prints it, and exits. Run it once (as one "
    "Bash call with a 600000 ms timeout) to wait for the build's result.",
}

ALLOWED = [
    "Bash(wires call deploy:*)",
    "Bash(wires call status:*)",
    "Bash(wires call logs:*)",
    "Bash(wires inbox:*)",
    "Bash(sleep:*)",
]


# poll-loop (a 4th arm, run after the three card arms): the same poll, but the
# shell loop the model reaches for first is allowed, so a whole wait can be one
# blocking Bash call -- the same shape as `wires inbox --wait`.
LOOP_EXTRA = ["Bash(until:*)", "Bash(while:*)", "Bash(for:*)", "Bash(grep:*)", "Bash(echo:*)"]


def allowed_for(arm: str) -> list[str]:
    return ALLOWED + (LOOP_EXTRA if arm == "poll-loop" else [])


def prompt_for(arm: str, n: int) -> str:
    return COMMON.format(n=n, how=HOW[arm].format(n=n))


def got(n: int) -> str:
    """The `left:` value the mock CI writes for build n (see ci.sh `got`)."""
    return f"{1234 + n % 97}.{n % 100:02d}"


def answer_line(text: str) -> str | None:
    lines = [l for l in (text or "").splitlines() if "ANSWER:" in l]
    if not lines:
        return None
    return lines[-1].split("ANSWER:", 1)[1].strip().strip("`").strip()


def score(n: int, ans: str | None) -> bool:
    return bool(ans) and "test_orders_total" in ans and got(n) in ans


def calls_for(n: int) -> list[tuple[int, str]]:
    """(ms, tool) for every tool call naming build n, from the CI's log."""
    out = []
    for line in (JOBS / "calls.log").read_text().splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        ms, tool, _caller, args = int(parts[0]), parts[1], parts[2], parts[3:]
        if (args[0] == "build" and len(args) > 1 and args[1] == str(n)) or args[0] == f"build-{n}":
            out.append((ms, tool))
    return out


def base_env(arm: str) -> dict:
    keep = ["HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "SHELL", "LANG"]
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(
        {
            "TERM": "dumb",
            "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "BASH_DEFAULT_TIMEOUT_MS": "600000",
            "BASH_MAX_TIMEOUT_MS": "600000",
            "NO_COLOR": "1",
            "WIRES_HOME": str(D / f"agent-{arm}"),
            "WIRES_LOCKED": "1",
        }
    )
    env["PATH"] = os.environ["BENCH_PUSH_BIN_DIR"] + ":" + env["PATH"]
    return env


def run_one(arm: str, secs: int, rep: int, rawdir: pathlib.Path) -> dict:
    while True:
        n = random.randint(10000, 99999)
        if not (JOBS / f"build-{n}").exists():
            break
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
        "--allowedTools=" + ",".join(allowed_for(arm)),
        "--",
        prompt_for(arm, n),
    ]
    wd = rawdir / "cwd" / arm
    wd.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    try:
        p = subprocess.run(
            cmd, cwd=wd, env=base_env(arm), capture_output=True, text=True, timeout=RUN_TIMEOUT, stdin=subprocess.DEVNULL
        )
        out, err, rc = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err, rc = "timeout", -1
    wall = time.time() - t0
    (rawdir / f"{arm}.{secs}s.r{rep}.jsonl").write_text(out)
    if err.strip():
        (rawdir / f"{arm}.{secs}s.r{rep}.stderr").write_text(err)

    result, commands = None, []
    for line in out.splitlines():
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if m.get("type") == "result":
            result = m
        elif m.get("type") == "assistant":
            for c in m.get("message", {}).get("content", []):
                if c.get("type") == "tool_use":
                    commands.append((c.get("input") or {}).get("command", c["name"]))
    u = (result or {}).get("usage", {})
    inp = u.get("input_tokens", 0)
    cw = u.get("cache_creation_input_tokens", 0)
    cr = u.get("cache_read_input_tokens", 0)
    text = (result or {}).get("result", "")
    done_f = JOBS / f"build-{n}" / "done_ms"
    done_ms = int(done_f.read_text()) if done_f.exists() else None
    calls = calls_for(n)
    logs_after = [ms for ms, tool in calls if tool == "logs" and done_ms and ms >= done_ms]
    ans = answer_line(text)
    return {
        "kind": "run",
        "arm": arm,
        "job_secs": secs,
        "rep": rep,
        "build": n,
        "rc": rc,
        "is_error": (result or {}).get("is_error", True),
        "model_usage": list(((result or {}).get("modelUsage") or {}).keys()),
        "input_tokens": inp,
        "cache_creation_input_tokens": cw,
        "cache_read_input_tokens": cr,
        "total_input_tokens": inp + cw + cr,
        "output_tokens": u.get("output_tokens", 0),
        "cost_usd": (result or {}).get("total_cost_usd", 0.0),
        "num_turns": (result or {}).get("num_turns"),
        "duration_ms": (result or {}).get("duration_ms"),
        "wall_s": round(wall, 2),
        "tool_calls": len(commands),
        "commands": [c[:120] for c in commands],
        "status_calls": sum(1 for _, t in calls if t == "status"),
        "logs_calls": sum(1 for _, t in calls if t == "logs"),
        "inbox_calls": sum(1 for c in commands if "wires inbox" in c),
        "sleep_calls": sum(1 for c in commands if c.strip().startswith("sleep") or "&& sleep" in c or "; sleep" in c),
        "permission_denials": len((result or {}).get("permission_denials") or []),
        "denied_commands": [
            (d.get("tool_input") or {}).get("command") for d in ((result or {}).get("permission_denials") or [])
        ],
        "done_ms": done_ms,
        "reaction_ms": (logs_after[0] - done_ms) if logs_after else None,
        "answer": ans,
        "expected": f"test_orders_total | {got(n)}",
        "correct": score(n, ans),
        "result_tail": (text or "")[-400:],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--arms", default="poll,loop-inbox,wait")
    ap.add_argument("--secs", default="60,300", help="build durations, comma-separated")
    ap.add_argument("--out", required=True)
    ap.add_argument("--raw", required=True)
    ap.add_argument("--budget", type=float, default=14.0)
    ap.add_argument("--rep-offset", type=int, default=0)
    args = ap.parse_args()

    arms = args.arms.split(",")
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    rawdir = pathlib.Path(args.raw)
    rawdir.mkdir(parents=True, exist_ok=True)

    spent = 0.0
    if out.exists():
        spent = sum(json.loads(l).get("cost_usd", 0.0) for l in out.read_text().splitlines() if l.strip())
    lock = threading.Lock()

    for secs in [int(s) for s in args.secs.split(",")]:
        (JOBS / "job-secs").write_text(f"{secs}\n")
        for rep in range(1 + args.rep_offset, args.reps + 1 + args.rep_offset):
            if spent >= args.budget:
                print(f"BUDGET STOP at ${spent:.2f}", flush=True)
                return 0

            def lane(arm: str) -> dict:
                return run_one(arm, secs, rep, rawdir)

            # One lane per arm, side by side: each arm has its own keystore
            # and mailbox, and they share only the host.
            with cf.ThreadPoolExecutor(max_workers=len(arms)) as ex:
                rows = list(ex.map(lane, arms))
            with lock, out.open("a") as f:
                for r in rows:
                    r["at"] = dt.datetime.now(dt.timezone.utc).isoformat()
                    f.write(json.dumps(r) + "\n")
                    spent += r["cost_usd"] or 0.0
                    lat = "-" if r["reaction_ms"] is None else f"{r['reaction_ms'] / 1000:.1f}s"
                    print(
                        f"{secs}s rep{rep} {r['arm']:10} turns={r['num_turns']} in={r['total_input_tokens']:>7} "
                        f"cw={r['cache_creation_input_tokens']:>6} cr={r['cache_read_input_tokens']:>7} "
                        f"${r['cost_usd']:.4f} react={lat} status={r['status_calls']} inbox={r['inbox_calls']} "
                        f"ok={r['correct']} | spent ${spent:.2f}",
                        flush=True,
                    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
