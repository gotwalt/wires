# Help text an LLM can act on (card 38)

*Run 2026-09-24: 48 headless Claude Code sessions (`claude -p`, `--model sonnet` and
`--model haiku`), 3 per cell, before and after card 38's help-text changes. All 48 correct.
Spend $0.84 in results, plus about $0.02 of smoke tests. Written up by the integrator from the
worker's results (the worker's harness couldn't write this file).*

**Setup.** `bench/help/up.sh` starts a hermetic loopback network with the mock IdP and five
services. The agent is locked (`WIRES_LOCKED=1`) and allowed only `Bash(wires:*)`. `payroll`
is refused with 77 by its host's extra role requirement (`also_require`). **Tasks:**

- **find:** "find the service that reports what's deployed" (answer: its name).
- **call:** call a service with given arguments and report the result.
- **refused:** call `payroll`; you're refused. Why, and what next?
- **premise:** "what is wires, and how would you reach the orders database?" Correct only if it
  answers by service name, not host or address.

**What changed between arms:** the premise paragraph in `wires --help` and the MCP instructions;
`wires --help` cut from 34 to 24 lines (caller commands only; the rest under `--help-all`),
`wires call --help` from 31 to 23 with examples and exit codes; every error ends with the next
step; a refusal says it is policy and not to retry.

## Results (medians over 3 runs)

```
python3 bench/help/report.py bench/help/results/before.jsonl bench/help/results/after.jsonl
```

| model | task | turns | input tokens | cost (3 runs) | help reads | retried after refusal |
|---|---|---|---|---|---|---|
| sonnet | find | 4 → 3 | 30.4k → 29.6k | $0.049 → $0.043 | 2.0 → 1.0 | — |
| sonnet | call | 6 → 6 | 62.5k → 50.5k | $0.082 → $0.072 | 1.0 → 1.0 | — |
| sonnet | refused | 6 → 4 | 53.0k → 40.2k | $0.114 → $0.065 | 1.7 → 1.0 | 2/3 → 0/3 |
| sonnet | premise | 5 → 4 | 53.2k → 39.9k | $0.081 → $0.058 | 1.7 → 1.0 | — |
| haiku | find | 3 → 3 | 23.3k → 23.0k | $0.026 → $0.024 | 1.0 → 1.0 | — |
| haiku | call | 6 → 5 | 49.5k → 39.4k | $0.042 → $0.034 | 1.0 → 1.0 | — |
| haiku | refused | 8 → 4 | 69.2k → 31.4k | $0.057 → $0.032 | 1.7 → 1.0 | 2/3 → 0/3 |
| haiku | premise | 4 → 3 | 31.9k → 23.0k | $0.031 → $0.028 | 1.3 → 1.0 | — |

No run guessed a flag in either arm.

## Findings

1. **Refusals stopped being worked around.** Before, 4 of 6 refused sessions tried to get past
   the 77 (`wires login`, then calling again). After, none did, and every one stopped at 4 turns
   (was 6–8). Input tokens fell 24% (sonnet) and 55% (haiku).
2. **Help is read once.** Every session after the change read help exactly once (before: 1.3–2.0
   reads on three of four tasks).
3. **The premise lands.** Every premise answer was `wires call orders-db -- "…"`, none named a
   host or address, and input tokens fell 25–28%.
4. **Cheaper across the board,** with the biggest gains where the old text left the model unsure
   what to do next.

## Caveats

- Three runs per cell show direction, not tight numbers.
- The top-level help example is `wires call orders-db -- "select count(*) from orders"`, close to
  the answers of the *call* and *premise* tasks; the *find* and *refused* tasks have no such
  overlap, and they show the same direction.
- Both arms ran on the same machine, network and services; only the `wires` binary differed.
