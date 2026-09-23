#!/usr/bin/env python3
"""Summarise bench/push/results/<date>.jsonl into the tables in REPORT.md.

  python3 bench/push/report.py bench/push/results/2026-09-23.jsonl
"""

from __future__ import annotations

import json
import statistics
import sys

ARMS = ["poll", "poll-loop", "loop-inbox", "wait"]


def q(xs, p):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def mi(xs, fmt="{:,.0f}"):
    xs = [x for x in xs if x is not None]
    if not xs:
        return "–"
    return f"{fmt.format(statistics.median(xs))} ({fmt.format(q(xs, .25))}–{fmt.format(q(xs, .75))})"


def main() -> None:
    runs = [json.loads(l) for path in sys.argv[1:] for l in open(path) if l.strip()]
    runs = [r for r in runs if r.get("kind") == "run"]
    for secs in sorted({r["job_secs"] for r in runs}):
        print(f"### Build takes {secs} s (median, IQR in parentheses)\n")
        print(
            "| arm | runs | turns | total input tokens | cache write | cache read | output | cost (USD) | Σ cost "
            "| reaction latency (s) | status / inbox checks | wall s | permission denials | accuracy |"
        )
        print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for a in ARMS:
            rs = [r for r in runs if r["arm"] == a and r["job_secs"] == secs]
            if not rs:
                continue
            checks = [r["status_calls"] if a.startswith("poll") else r["inbox_calls"] for r in rs]
            print(
                f"| {a} | {len(rs)} | {mi([r['num_turns'] for r in rs])} "
                f"| {mi([r['total_input_tokens'] for r in rs])} "
                f"| {mi([r['cache_creation_input_tokens'] for r in rs])} "
                f"| {mi([r['cache_read_input_tokens'] for r in rs])} "
                f"| {mi([r['output_tokens'] for r in rs])} "
                f"| {mi([r['cost_usd'] for r in rs], '{:.4f}')} "
                f"| ${sum(r['cost_usd'] for r in rs):.2f} "
                f"| {mi([r['reaction_ms'] / 1000 if r['reaction_ms'] is not None else None for r in rs], '{:.1f}')} "
                f"| {mi(checks)} "
                f"| {mi([r['wall_s'] for r in rs], '{:.0f}')} "
                f"| {sum(r['permission_denials'] for r in rs)} "
                f"| {sum(r['correct'] for r in rs)}/{len(rs)} |"
            )
        print()
    print(f"Total: {len(runs)} runs, ${sum(r['cost_usd'] for r in runs):.2f}.")


if __name__ == "__main__":
    main()
