# Push vs poll (card 24)

*Run 2026-09-23 (UTC): 37 headless Claude Code sessions (`claude -p`,
`--model opus` → claude-opus-5-5, Claude Code 2.1.280), all correct. Spend
$1.71 in results, plus about $0.35 of smoke tests and probes.*

*Note: the setup has changed since these runs. `bench/push/up.sh` now
registers the services for a role `bench` matched on the benchmark's IdP
identity (the runs used a built-in `member` role that no longer exists), and
a service pushes through a per-call capability instead of the host's
keystore. The results below are from the runs as they were.*

**Task:** start build *n* on a remote mock CI (`wires call deploy -- build n`),
wait for it to finish, read its log (`wires call logs -- build n --tail 50`),
and report the failing test and the `left:` value of its assertion. The value
depends on *n*, so only this build's log gives it. The build takes 60 s or
300 s. `deploy` gives no ETA. Only the one prompt sentence on how to wait
differs between arms:

- **poll**: check `wires call status` until it isn't running, `sleep` allowed
  (the MCP tasks-extension shape, `tasks/get`).
- **loop-inbox**: check `wires inbox` until the message arrives, `sleep`
  allowed. This is the no-harness-change path.
- **wait**: run `wires inbox --wait --timeout 10m` once, as a foreground Bash
  call. `claude -p` kills background commands when the turn ends (checked on
  2.1.280), so this is a blocking call: it costs one tool call, and no model
  turns while it blocks. In an interactive session, a background command
  would cost the same without blocking the agent.
- **poll-loop** (extra, **partial**: 5 + 2 runs; stopped by the integrator):
  poll, but shell loops (`until`/`while`/`for`/`grep`) are allowed, so the
  whole wait could be one blocking call.

All arms get the same allowlist (`Bash(wires call deploy|status|logs:*)`,
`Bash(wires inbox:*)`, `Bash(sleep:*)`), `WIRES_LOCKED=1`, a 10-minute Bash
timeout, and their own agent keystore. **Reaction latency** is measured on
the host: the first `logs` call for build *n* minus the moment the build
finished (the mock CI's millisecond log, `.scripts/fixtures/ci.sh`).

## Results (median, IQR in parentheses)

| job | arm | runs | turns | total input tokens | cost / run | reaction latency | checks | accuracy |
|---|---|---|---|---|---|---|---|---|
| 60 s | poll | 5 | 9 | 28,352 (28,329–28,366) | $0.046 | 44.4 s (44.3–44.5) | 3 status | 5/5 |
| 60 s | loop-inbox | 5 | 9 | 28,560 (28,554–28,631) | $0.046 | 44.3 s (44.1–44.6) | 4 inbox | 5/5 |
| 60 s | poll-loop *(partial)* | 5 | 10 | 33,759 (33,743–33,823) | $0.053 | 46.6 s (46.1–46.8) | 3 status | 5/5 |
| 60 s | **wait** | 5 | **4** | **15,440** | **$0.028** | **2.0 s (1.9–2.1)** | 1 inbox | 5/5 |
| 300 s | poll | 5 | 13 | 38,537 (38,535–38,566) | $0.058 | 20.5 s (20.5–21.0) | 5 status | 5/5 |
| 300 s | loop-inbox | 5 | 13 | 38,873 (38,868–39,055) | $0.059 | 110.6 s (24.3–110.7) | 6 inbox | 5/5 |
| 300 s | poll-loop *(partial)* | 2 | 14 | 41,960 | $0.064 | 144 s (110, 178) | 5 status | 2/2 |
| 300 s | **wait** | 5 | **4** | **15,435** | **$0.028** | **2.2 s (2.1–2.3)** | 1 inbox | 5/5 |

The full per-arm tables (cache write/read, output, wall time, permission
denials) come from `python3 bench/push/report.py bench/push/results/2026-09-23.jsonl`.

## Interpretation

- **loop-inbox costs the same as poll**, to the token: 28.4k vs 28.6k at
  60 s, 38.5k vs 38.9k at 300 s. Checking an inbox on a loop is polling. The
  savings come only from `--wait`. What `inbox` adds without `--wait` is that
  a host can reach an agent with no public endpoint at all, which webhooks
  can't do.
- **`--wait` is flat in job length**: 4 turns and about 15.4k input tokens
  whether the build takes 60 s or 300 s. That is **46% fewer input tokens and
  about 40% lower cost at 60 s, and 60% fewer tokens and about 51% lower cost at 300 s**.
  Polling grows with the wait, by roughly one turn per check.
- **Latency is where the difference is large**: about 2 s with `--wait` (the
  push reaches the waiting fetch in about 50–80 ms, and the rest is one model
  turn), against 20–178 s for the polling arms. The polling latency depends on
  where the model's back-off schedule (sleep 30, 60, 90, 120, 180) happens to
  land relative to completion, so its spread is luck rather than a property of the arm.
- Every run was correct. The absolute amounts are small (cents per run). The
  point for the pitch is that the cost doesn't grow with the wait, plus the
  latency, not dollars.

## Caveats

- One task, one model, and a 60/300 s job. A longer job widens the gap
  linearly, and a job whose ETA the agent knows narrows it: in a smoke test
  where `deploy` printed "runs about 20s", the poll arm made **one** check
  after one well-timed `sleep`. That is why `deploy` gives no ETA.
- The model's first move in the loop arms was a shell `for` loop that the
  allowlist refused (5 denials per poll/loop-inbox arm), and it then fell
  back to separate `sleep` + check calls. With loops allowed
  (poll-loop), it still used separate calls in most runs and cost slightly
  more. Real Claude Code sessions with broader permissions would loop in one
  call more often. That makes polling cheaper in turns, but a blocking loop
  then holds the agent exactly as `--wait` does, without the push latency.
- The `--wait` arm is a foreground blocking call because `claude -p` can't
  resume on a background command. The token cost of an interactive
  background command should be the same, but it wasn't measured here.
- 60 s reps 1–3 overlapped a full workspace test run on the same machine. One
  `--wait` run in that window reacted in 22.7 s (its `wires push` took 9 s
  instead of 3 s, and a fetch stalled). It is not in the median, but it is in
  the raw data.
- Prompt caching held through a 300 s blocking call: cache writes didn't grow
  in the `wait` arm.

## Reproduce

```bash
cargo build --release -p wires && ./bench/push/run.sh                 # 3 arms x {60, 300 s} x 5
./bench/push/run.sh --arms poll-loop --secs 60,300         # the extra arm
python3 bench/push/report.py bench/push/results/2026-09-23.jsonl
```

`bench/push/up.sh` provisions a loopback workbench (the mock CI, from
`.scripts/fixtures/push-host.json`) and one agent keystore per arm under
`/tmp/wb24`. The raw stream-json transcripts are not committed.
