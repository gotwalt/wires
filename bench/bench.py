#!/usr/bin/env python3
"""MCP vs CLI token benchmark driver (board card 16).

Runs `claude -p` headless, one fresh session per run, over every
arm x task x repetition, and appends one JSON line per run to
bench/results/<date>.jsonl. Ground truth is fetched live from the GitHub API
(via `gh api`) at the start and end of each repetition, and a run is scored
correct if its ANSWER line matches either snapshot (the volatile tasks --
open-issue counts, recently merged PRs -- can move while a repetition runs).

Arms (see REPORT.md for why these five):
  mcp       GitHub MCP server (docker, stdio, --read-only, default toolsets);
            Claude Code's default tool loading (ENABLE_TOOL_SEARCH unset,
            which in 2.1.280 resolves to tool search = on).
  mcp-eager Same server, ENABLE_TOOL_SEARCH=false: every tool schema is sent
            up front (the pre-tool-search behavior).
  wires     `wires call gh -- ...` from Bash, via a loopback `wires serve
            host.json` that implements the service `gh` (bench/wires-up.sh).
  gh        bare `gh` from Bash.
  wires-only  (card 19) `wires call gh` is the ONLY thing the agent may run:
            `--allowedTools=Bash(wires call gh:*)`, no jq/head/grep helpers.
            Output shaping comes from gh's own flags or `wires call
            --jq/--head/--max-bytes` (in-process, no shell).

The GitHub token is read with `gh auth token` at runtime and passed to the
MCP container through the environment only; it is never written to disk.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
IMAGE = os.environ.get("GH_MCP_IMAGE", "ghcr.io/github/github-mcp-server")
MODEL = os.environ.get("BENCH_MODEL", "opus")
RUN_TIMEOUT = 420  # seconds per claude -p run

# ---------------------------------------------------------------- tasks ---

ANSWER_RULE = (
    "\n\nFinish your reply with exactly one final line that starts with "
    "`ANSWER:` in this format: {fmt}"
)

TASKS = {
    "t1-release": {
        "prompt": "What is the latest release of the GitHub repository cli/cli? "
        "Give its tag name and its publication date (UTC).",
        "fmt": "`ANSWER: <tag> <YYYY-MM-DD>`",
    },
    "t2-merged-prs": {
        "prompt": "What are the 3 most recently merged pull requests in the GitHub "
        "repository modelcontextprotocol/modelcontextprotocol (by merge time, most "
        "recent first)? Give their numbers and titles.",
        "fmt": "`ANSWER: #<n1>, #<n2>, #<n3>`",
    },
    "t3-bug-count": {
        "prompt": "How many open issues in the GitHub repository anthropics/claude-code "
        "currently have the label `bug`? Pull requests don't count.",
        "fmt": "`ANSWER: <integer>`",
    },
    "t4-commit-files": {
        "prompt": "Which files were changed by commit "
        "b5a6860d964e6b394ddfd8cdb0a2f14fbb22ab21 in the GitHub repository "
        "sharkdp/hyperfine? List every file path.",
        "fmt": "`ANSWER: <path>, <path>, ...`",
    },
    "t5-most-commented": {
        "prompt": "Find the open issue (not pull request) with the most comments in the "
        "GitHub repository cli/cli. Who wrote its most recent comment, and what does "
        "that comment say? Summarise it in one sentence.",
        "fmt": "`ANSWER: #<issue number> | <login of the last commenter> | <one-sentence summary>`",
    },
}

# ----------------------------------------------------------------- arms ---

PIPE_HELPERS = ["Bash(jq:*)", "Bash(head:*)", "Bash(tail:*)", "Bash(grep:*)", "Bash(wc:*)", "Bash(sort:*)"]

ARMS = {
    "mcp": {"hint": "", "tools": "ToolSearch", "allowed": ["mcp__github"], "mcp": True, "env": {}},
    "mcp-eager": {
        "hint": "",
        "tools": "ToolSearch",
        "allowed": ["mcp__github"],
        "mcp": True,
        "env": {"ENABLE_TOOL_SEARCH": "false"},
    },
    "wires": {
        "hint": "The GitHub CLI is available through Bash as `wires call gh -- <gh arguments>` "
        "(it runs `gh` on a remote, already-authenticated machine).\n\n",
        "tools": "Bash,ToolSearch",
        "allowed": ["Bash(wires call gh:*)", *PIPE_HELPERS],
        "mcp": False,
        "env": {},
    },
    "wires-only": {
        "hint": "The GitHub CLI is available through Bash as `wires call gh -- <gh arguments>` "
        "(it runs `gh` on a remote, already-authenticated machine). That is the only command you "
        "can run: there is no shell, so pipes, `jq`, `head` and other local tools are not "
        "available. Filter output with gh's own flags (`--json`, `--jq`, `--limit`) or with "
        "wires' flags, which go between the tool name and `--`: "
        "`wires call gh --jq <filter> --head <N> --max-bytes <N> -- <gh arguments>`.\n\n",
        "tools": "Bash,ToolSearch",
        "allowed": ["Bash(wires call gh:*)"],
        "mcp": False,
        "env": {},
    },
    "gh": {
        "hint": "The GitHub CLI `gh` is available through Bash (already authenticated).\n\n",
        "tools": "Bash,ToolSearch",
        "allowed": ["Bash(gh:*)", *PIPE_HELPERS],
        "mcp": False,
        "env": {},
    },
}


def prompt_for(arm: str, task: str) -> str:
    t = TASKS[task]
    return ARMS[arm]["hint"] + t["prompt"] + ANSWER_RULE.format(fmt=t["fmt"])


# --------------------------------------------------------- ground truth ---


def gh_api(path: str, *extra: str):
    out = subprocess.check_output(["gh", "api", *extra, path], text=True)
    return json.loads(out)


def truth_snapshot() -> dict:
    snap: dict = {"at": dt.datetime.now(dt.timezone.utc).isoformat()}
    rel = gh_api("repos/cli/cli/releases/latest")
    snap["t1-release"] = {"tag": rel["tag_name"], "date": rel["published_at"][:10]}

    pulls = gh_api(
        "repos/modelcontextprotocol/modelcontextprotocol/pulls?state=closed&sort=updated&direction=desc&per_page=100"
    )
    merged = sorted((p for p in pulls if p.get("merged_at")), key=lambda p: p["merged_at"], reverse=True)
    snap["t2-merged-prs"] = {"numbers": [p["number"] for p in merged[:3]]}

    s = gh_api("search/issues?q=repo:anthropics/claude-code+is:issue+is:open+label:bug&per_page=1")
    snap["t3-bug-count"] = {"count": s["total_count"]}

    c = gh_api("repos/sharkdp/hyperfine/commits/b5a6860d964e6b394ddfd8cdb0a2f14fbb22ab21")
    snap["t4-commit-files"] = {"files": sorted(f["filename"] for f in c["files"])}

    s = gh_api("search/issues?q=repo:cli/cli+is:issue+is:open+sort:comments-desc&per_page=3")
    top = s["items"][0]
    tied = [i["number"] for i in s["items"] if i["comments"] == top["comments"]]
    n = top["number"]
    count = top["comments"]
    page = max(1, count)
    last = gh_api(f"repos/cli/cli/issues/{n}/comments?per_page=1&page={page}")
    snap["t5-most-commented"] = {
        "numbers": tied,
        "comments": count,
        "last_login": last[0]["user"]["login"] if last else None,
    }
    return snap


# -------------------------------------------------------------- scoring ---


def answer_line(text: str) -> str | None:
    lines = [l for l in (text or "").splitlines() if "ANSWER:" in l]
    if not lines:
        return None
    return lines[-1].split("ANSWER:", 1)[1].strip().strip("`").strip()


def norm_login(s: str) -> str:
    # GraphQL (gh) spells bots `cli-triage`, REST (MCP) `cli-triage[bot]`.
    return s.strip().strip("`").lstrip("@").removesuffix("[bot]").lower()


def score(task: str, ans: str | None, snaps: list[dict]) -> bool:
    if not ans:
        return False
    for snap in snaps:
        t = snap[task]
        if task == "t1-release":
            if t["tag"] in ans.split() or re.search(rf"(^|\s){re.escape(t['tag'])}(\s|$)", ans):
                if t["date"] in ans:
                    return True
        elif task == "t2-merged-prs":
            got = [int(x) for x in re.findall(r"#?(\d+)", ans)][:3]
            if set(got) == set(t["numbers"]):
                return True
        elif task == "t3-bug-count":
            m = re.search(r"\d[\d,]*", ans)
            if m and abs(int(m.group().replace(",", "")) - t["count"]) <= max(3, t["count"] // 100):
                return True
        elif task == "t4-commit-files":
            got = sorted(set(p.strip().strip("`") for p in ans.split(",") if p.strip()))
            if got == t["files"]:
                return True
        elif task == "t5-most-commented":
            parts = [p.strip() for p in ans.split("|")]
            m = re.search(r"\d+", parts[0]) if parts else None
            if (
                m
                and int(m.group()) in t["numbers"]
                and len(parts) >= 2
                and t["last_login"]
                and norm_login(parts[1]) == norm_login(t["last_login"])
            ):
                return True
    return False


# ------------------------------------------------------------ one run ---


def mcp_config() -> str:
    return json.dumps(
        {
            "mcpServers": {
                "github": {
                    "command": "docker",
                    "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", IMAGE, "stdio", "--read-only"],
                }
            }
        }
    )


def base_env(extra: dict) -> dict:
    keep = ["HOME", "USER", "LOGNAME", "PATH", "TMPDIR", "SHELL", "LANG"]
    env = {k: os.environ[k] for k in keep if k in os.environ}
    env.update(
        {
            "TERM": "dumb",
            "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "GH_PROMPT_DISABLED": "1",
            "GH_NO_UPDATE_NOTIFIER": "1",
            "NO_COLOR": "1",
        }
    )
    env.update(extra)
    return env


def run_one(arm: str, task: str, rep: int, workdir: pathlib.Path, rawdir: pathlib.Path, token: str) -> dict:
    a = ARMS[arm]
    env = base_env(a["env"])
    if arm in ("wires", "wires-only"):
        env["WIRES_HOME"] = os.environ["WIRES_HOME"]
        env["PATH"] = os.environ["BENCH_WIRES_BIN_DIR"] + ":" + env["PATH"]
    if a["mcp"]:
        env["GITHUB_PERSONAL_ACCESS_TOKEN"] = token
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
        f"--tools={a['tools']}",
        "--allowedTools=" + ",".join(a["allowed"]),
    ]
    if a["mcp"]:
        cmd += ["--mcp-config", mcp_config()]
    cmd += ["--", prompt_for(arm, task)]
    wd = workdir / arm
    wd.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    try:
        p = subprocess.run(cmd, cwd=wd, env=env, capture_output=True, text=True, timeout=RUN_TIMEOUT, stdin=subprocess.DEVNULL)
        out, err, rc = p.stdout, p.stderr, p.returncode
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err, rc = "timeout", -1
    wall = time.time() - t0
    raw = rawdir / f"{arm}.{task}.r{rep}.jsonl"
    raw.write_text(out)
    if err.strip():
        (rawdir / f"{arm}.{task}.r{rep}.stderr").write_text(err)

    init, result, tool_calls = None, None, []
    for line in out.splitlines():
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if m.get("type") == "system" and m.get("subtype") == "init":
            init = m
        elif m.get("type") == "result":
            result = m
        elif m.get("type") == "assistant":
            for c in m.get("message", {}).get("content", []):
                if c.get("type") == "tool_use":
                    tool_calls.append(c["name"])
    u = (result or {}).get("usage", {})
    inp = u.get("input_tokens", 0)
    cw = u.get("cache_creation_input_tokens", 0)
    cr = u.get("cache_read_input_tokens", 0)
    text = (result or {}).get("result", "")
    return {
        "arm": arm,
        "task": task,
        "rep": rep,
        "rc": rc,
        "is_error": (result or {}).get("is_error", True),
        "model_usage": list(((result or {}).get("modelUsage") or {}).keys()),
        "init_tools": len((init or {}).get("tools", [])),
        "init_tool_names": (init or {}).get("tools", []),
        "mcp_servers": (init or {}).get("mcp_servers", []),
        "input_tokens": inp,
        "cache_creation_input_tokens": cw,
        "cache_read_input_tokens": cr,
        "total_input_tokens": inp + cw + cr,
        "output_tokens": u.get("output_tokens", 0),
        "cost_usd": (result or {}).get("total_cost_usd", 0.0),
        "num_turns": (result or {}).get("num_turns"),
        "duration_ms": (result or {}).get("duration_ms"),
        "duration_api_ms": (result or {}).get("duration_api_ms"),
        "wall_s": round(wall, 2),
        "tool_calls": tool_calls,
        "permission_denials": len((result or {}).get("permission_denials") or []),
        "denied_commands": [
            (d.get("tool_input") or {}).get("command") for d in ((result or {}).get("permission_denials") or [])
        ],
        "answer": answer_line(text),
        "result_tail": (text or "")[-600:],
    }


# ----------------------------------------------------------------- main ---


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--arms", default=",".join(ARMS))
    ap.add_argument("--tasks", default=",".join(TASKS))
    ap.add_argument("--out", required=True, help="results .jsonl (appended)")
    ap.add_argument("--raw", required=True, help="directory for raw stream-json transcripts (not committed)")
    ap.add_argument("--budget", type=float, default=38.0, help="stop starting runs past this spend (USD)")
    ap.add_argument("--rep-offset", type=int, default=0)
    args = ap.parse_args()

    arms = args.arms.split(",")
    tasks = args.tasks.split(",")
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    rawdir = pathlib.Path(args.raw)
    rawdir.mkdir(parents=True, exist_ok=True)
    workdir = rawdir / "cwd"
    token = subprocess.check_output(["gh", "auth", "token"], text=True).strip()

    spent = 0.0
    if out.exists():
        for l in out.read_text().splitlines():
            r = json.loads(l)
            spent += r.get("cost_usd", 0.0) if r.get("kind") == "run" else 0.0
    lock = threading.Lock()
    stop = threading.Event()

    for rep in range(1 + args.rep_offset, args.reps + 1 + args.rep_offset):
        before = truth_snapshot()
        rows: list[dict] = []

        def lane(arm: str) -> None:
            nonlocal spent
            for task in tasks:
                with lock:
                    if spent >= args.budget:
                        stop.set()
                if stop.is_set():
                    return
                r = run_one(arm, task, rep, workdir, rawdir, token)
                with lock:
                    spent += r["cost_usd"] or 0.0
                    rows.append(r)
                    print(
                        f"rep{rep} {arm:9} {task:17} in={r['total_input_tokens']:>7} "
                        f"cw={r['cache_creation_input_tokens']:>6} cr={r['cache_read_input_tokens']:>7} "
                        f"out={r['output_tokens']:>5} ${r['cost_usd']:.4f} turns={r['num_turns']} "
                        f"{r['wall_s']:.0f}s ans={r['answer']!r:.60} | spent ${spent:.2f}",
                        flush=True,
                    )

        # One lane per arm: each arm runs its tasks sequentially, arms run
        # side by side (they don't share a session or a cache prefix).
        with cf.ThreadPoolExecutor(max_workers=len(arms)) as ex:
            list(ex.map(lane, arms))
        after = truth_snapshot()
        with out.open("a") as f:
            f.write(json.dumps({"kind": "truth", "rep": rep, "before": before, "after": after}) + "\n")
            for r in rows:
                r["kind"] = "run"
                r["correct"] = score(r["task"], r["answer"], [before, after])
                f.write(json.dumps(r) + "\n")
        print(f"rep{rep} done: {sum(r['correct'] for r in rows)}/{len(rows)} correct; spent ${spent:.2f}", flush=True)
        if stop.is_set():
            print(f"BUDGET STOP at ${spent:.2f}", flush=True)
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
