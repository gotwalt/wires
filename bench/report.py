#!/usr/bin/env python3
"""Summarise a bench/results/<date>.jsonl into markdown tables for REPORT.md.

  python3 bench/report.py bench/results/2026-09-23.jsonl
"""

from __future__ import annotations

import json
import statistics
import sys

ARMS = ["mcp", "mcp-eager", "wires", "gh"]


def q(xs, p):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def med_iqr(xs, fmt="{:,.0f}"):
    return f"{fmt.format(statistics.median(xs))} ({fmt.format(q(xs, .25))}–{fmt.format(q(xs, .75))})"


def main() -> None:
    rows = [json.loads(l) for l in open(sys.argv[1])]
    runs = [r for r in rows if r.get("kind") == "run"]
    tasks = sorted({r["task"] for r in runs})

    print("### Per arm (all tasks pooled; median, IQR in parentheses)\n")
    print("| arm | runs | total input tokens | uncached input | cache write | cache read | output | cost (USD) | turns | wall s | accuracy |")
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for a in ARMS:
        rs = [r for r in runs if r["arm"] == a]
        if not rs:
            continue
        print(
            f"| {a} | {len(rs)} | {med_iqr([r['total_input_tokens'] for r in rs])} "
            f"| {statistics.median([r['input_tokens'] for r in rs]):,.0f} "
            f"| {med_iqr([r['cache_creation_input_tokens'] for r in rs])} "
            f"| {med_iqr([r['cache_read_input_tokens'] for r in rs])} "
            f"| {statistics.median([r['output_tokens'] for r in rs]):,.0f} "
            f"| {med_iqr([r['cost_usd'] for r in rs], '{:.4f}')} "
            f"| {med_iqr([r['num_turns'] for r in rs], '{:.0f}')} "
            f"| {med_iqr([r['wall_s'] for r in rs], '{:.1f}')} "
            f"| {sum(r['correct'] for r in rs)}/{len(rs)} |"
        )

    print("\n### Sums over the whole run (every arm did the same 25 task-runs)\n")
    print("| arm | Σ total input | Σ cache write | Σ cost (USD) | Σ turns |")
    print("|---|---|---|---|---|")
    for a in ARMS:
        rs = [r for r in runs if r["arm"] == a]
        if rs:
            print(
                f"| {a} | {sum(r['total_input_tokens'] for r in rs):,} | {sum(r['cache_creation_input_tokens'] for r in rs):,} "
                f"| {sum(r['cost_usd'] for r in rs):.2f} | {sum(r['num_turns'] for r in rs)} |"
            )

    print("\n### Per task (median total input tokens / median cost USD / median turns / accuracy)\n")
    print("| task | " + " | ".join(ARMS) + " |")
    print("|---|" + "---|" * len(ARMS))
    for t in tasks:
        cells = []
        for a in ARMS:
            rs = [r for r in runs if r["arm"] == a and r["task"] == t]
            if not rs:
                cells.append("–")
                continue
            cells.append(
                f"{statistics.median([r['total_input_tokens'] for r in rs]):,.0f} / "
                f"{statistics.median([r['cost_usd'] for r in rs]):.3f} / "
                f"{statistics.median([r['num_turns'] for r in rs]):.0f} / "
                f"{sum(r['correct'] for r in rs)}/{len(rs)}"
            )
        print(f"| {t} | " + " | ".join(cells) + " |")

    print("\n### Tool calls (median per run)\n")
    print("| arm | tool calls | ToolSearch calls (total) |")
    print("|---|---|---|")
    for a in ARMS:
        rs = [r for r in runs if r["arm"] == a]
        if rs:
            print(
                f"| {a} | {statistics.median([len(r['tool_calls']) for r in rs]):.0f} "
                f"| {sum(c == 'ToolSearch' for r in rs for c in r['tool_calls'])} |"
            )
    total = sum(r["cost_usd"] for r in runs)
    print(f"\nTotal spend: ${total:.2f} over {len(runs)} runs. Models: {sorted({m for r in runs for m in r['model_usage']})}")
    wrong = [r for r in runs if not r["correct"]]
    if wrong:
        print("\nIncorrect runs:")
        for r in wrong:
            print(f"- {r['arm']} {r['task']} rep{r['rep']}: {r['answer']!r}")


if __name__ == "__main__":
    main()
