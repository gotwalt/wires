# 24 — The push demo, and push vs. poll in numbers

**Lane:** E2 · **Depends on:** 23 · **Files:** `.scripts/demo-push.sh` (new), a mock `deploy`/`ci` tool under `.scripts/fixtures/`, `bench/push/` (new), `docs/demo.md` (a push segment)

## Scenario (the story to show)

1. The agent runs `wires call deploy -- build 41`. The tool starts a background job and returns at once with a job id. Its background job holds `$WIRES_CALLER_NODE`.
2. The agent runs `wires inbox --wait` as a **background command** (Claude Code re-invokes the agent when it exits), then carries on or goes quiet.
3. Minutes later (in the script: a few seconds), the build fails on the host, and the job runs `wires push --to "$WIRES_CALLER_NODE" --subject build-41 -- "failed: test_orders_total …"`.
4. The inbox command exits, and Claude wakes with the event, which shows the verified sender (`ci@51442ef9`). It follows up with `wires call logs -- build 41 --tail 50`.
5. The observer shows the chain: `▶ deploy` → `⇢ push build-41 delivered` → `▶ logs`, all stamped with identities.
6. Also show a **sleeping** agent: no resident receiver, the push is queued, and the agent's next `wires inbox` fetches it.

## Benchmark: push vs. poll (the number that makes it land)

Same task, same model, n=5, headless `claude -p`:
- **poll arm:** the agent is told to check a `status` tool (`wires call status -- build 41`) until the job finishes, which is how the MCP tasks extension (`tasks/get`) works.
- **loop-inbox arm:** the agent checks `wires inbox` on a loop (the no-harness-change path).
- **wait arm:** the agent uses `wires inbox --wait` as a background command.
- Job duration fixed (for example 60 s and 300 s). Report turns, total input tokens, cost, and **latency from job completion to the agent's first reaction**. Report honestly, including if loop-inbox costs about the same as poll: the saving then comes from `--wait`, and the point of `inbox` is that it works at all without a public endpoint.

## Rebuttal lines for docs/demo.md

- "Use webhooks": the laptop agent has no public endpoint; ngrok or Funnel would expose it to the internet.
- "Just poll": see the benchmark.
- "A2A has push": through webhooks to a public URL, the same problem.
- "The MCP tasks extension": poll-based by design.

## Acceptance

- [x] `.scripts/demo-push.sh` self-asserting and green, `--quiet` under 30 s.
- [x] `bench/push/REPORT.md` with the three-arm table and an honest interpretation. Budget $15.
- [x] A `docs/demo.md` push segment for the two-machine recording.

## Notes

*2026-09-23, lane E2 (worker).*

- **Demo:** `.scripts/demo-push.sh --quiet` is green in about 21–23 s. It asserts that
  deploy returns at once, and that `inbox --wait` (in locked mode) wakes 50–80 ms after the
  build fails, with a line naming the verified host. The log follow-up holds the assertion.
  The observer shows ▶ deploy → ⇢ build-41 → ▶ logs in order, all naming the email.
  For a sleeping agent, build-42 is `queued`, the next `wires inbox` fetches it, and it is
  printed once.
- **Mock CI:** `.scripts/fixtures/ci.sh` (deploy/status/logs in one script) plus
  `push-host.json`. A tool reaches its own host's `wires push` because the tool inherits
  `serve`'s environment (`WIRES_HOME` isn't scrubbed; only `WIRES_CALLER_NODE` & co. are
  replaced), so the backgrounded job just runs `$CI_WIRES push --to "$WIRES_CALLER_NODE"`.
  The job must detach stdio (`</dev/null >/dev/null 2>&1 & disown`), or the call hangs on
  the pipe. `deploy` deliberately prints no ETA (see REPORT caveats).
- **Bench:** `bench/push/{up.sh,run.sh,bench.py,report.py,REPORT.md}` and
  `results/2026-09-23.jsonl`: 37 runs, $1.71, all correct. loop-inbox ≈ poll, to the
  token. `--wait` stays flat at 4 turns / 15.4k tokens, versus 28k (60 s) and 39k (300 s),
  and reacts in about 2 s versus 20–180 s. The poll-loop arm is partial (the integrator stopped it).
- **`--wait` arm honesty:** `claude -p` kills background Bash tasks when the turn ends
  (probed: `task_updated status: killed`), so the arm is a foreground blocking call. A
  foreground `sleep 45` is allowed in `-p` with `--tools=Bash`.
- **Observed, not fixed (product):** when `inbox --wait` is fetching, the push is taken
  before `wires push` finishes its ≤3 s direct attempt, so there's no `⇢ queued` record,
  only `fetched`. `wires push` still prints `queued`, and it always takes about 3 s when no
  receiver is resident. No product code was changed.
- **Pitfall:** `cp -f` over a signed binary on macOS gets it SIGKILLed; `bench/push/run.sh`
  runs `rm` before `cp`. (bench/run.sh from card 16 has the same `cp -f`.)
- `bazel test //...`: `e2e::directory::…stopped_host_go_stale` failed once while the bench
  ran (the same load flake card 23 noted); `//wires:wires_test` green on re-run, other 4 targets green. shfmt is clean on
  all the new scripts, and shellcheck isn't on PATH.
