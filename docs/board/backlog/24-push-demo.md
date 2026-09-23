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

- [ ] `.scripts/demo-push.sh` self-asserting and green, `--quiet` under 30 s.
- [ ] `bench/push/REPORT.md` with the three-arm table and an honest interpretation. Budget $15.
- [ ] A `docs/demo.md` push segment for the two-machine recording.

## Notes
