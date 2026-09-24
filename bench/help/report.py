#!/usr/bin/env python3
"""Summarize bench/help results (card 38): one row per model x task x label.

  python3 bench/help/report.py bench/help/results/before.jsonl bench/help/results/after.jsonl

Columns: runs, correct, median turns, median input tokens (fresh + cache),
median output tokens, total cost, mean help reads, flag guesses, and for the
refused task how many runs called payroll again after the refusal or ran
`wires login` to get around it.
"""

from __future__ import annotations

import json
import statistics
import sys
from collections import defaultdict


def main() -> int:
    rows = defaultdict(list)
    for path in sys.argv[1:]:
        for line in open(path):
            r = json.loads(line)
            rows[(r["model"], r["task"], r["label"])].append(r)
    print(
        "| model | task | label | runs | correct | turns | input tok | output tok | cost | help reads "
        "| guessed | retried after refusal |"
    )
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    total = 0.0
    for (model, task, label), rs in sorted(rows.items(), key=lambda kv: (kv[0][0], kv[0][1], kv[0][2] != "before")):
        med = lambda k: statistics.median(r[k] or 0 for r in rs)  # noqa: E731
        cost = sum(r["cost_usd"] or 0 for r in rs)
        total += cost
        guessed = sum(len(r["guessed"]) for r in rs)
        retried = "-"
        if task == "refused":
            n = 0
            for r in rs:
                pay = [c for c in r["commands"] if "call payroll" in c]
                if len(pay) > 1 or any(c.startswith("wires login") for c in r["commands"]):
                    n += 1
            retried = f"{n}/{len(rs)}"
        print(
            f"| {model} | {task} | {label} | {len(rs)} | {sum(r['correct'] for r in rs)}/{len(rs)} "
            f"| {med('num_turns'):g} | {med('total_input_tokens'):,.0f} | {med('output_tokens'):,.0f} "
            f"| ${cost:.3f} | {statistics.mean(r['help_reads'] for r in rs):.1f} | {guessed} | {retried} |"
        )
    print(f"\ntotal spend in these results: ${total:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
