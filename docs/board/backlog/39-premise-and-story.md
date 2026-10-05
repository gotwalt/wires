# 39 — The premise and the story

**Stage:** 3 · **Depends on:** [41](../done/41-idp-membership.md) merged (the commands the docs show must exist) · **Status:** backlog; the premise itself is on the [board](../README.md) (2026-10-05) · **Files:** `README.md`, `docs/executive-summary.md`, `docs/blog/introducing-wires.md`, `docs/storytelling.md`, `docs/usage.md`, `docs/fabric.md`, `docs/demo.md`, `docs/deployment.md`, `docs/testing.md`, `docs/agent-sandbox.md`, `docs/media/`, `CLAUDE.md`, `wires/help.rs` (the premise paragraph only)

## Why

A review on 2026-10-04 found five statements of what wires is (the README
tagline, the board's one idea, the premise, CLAUDE.md's assignment and the
executive summary) that disagreed with each other, and an executive summary
that ended by asking the audience which of four things mattered. The human
chose (2026-10-04/05):

- **The thesis:** agents work best with CLIs. They have seen far more shell
  than tool-call JSON, a CLI's output is filtered before it reaches
  context, and CLIs compose.
- **What wires adds:** the three things that stop a CLI from being shared
  across an organization: who is calling (your IdP), how they find it (a
  catalog by service name), and how they reach it (by key; no port, no VPN).
- **And one thing a local CLI can't do:** the service can message its caller
  back.
- **MCP is a bridge**, "not an end goal. Ideally, someday it becomes
  irrelevant." `wires mcp` and `wires gateway` carry existing MCP workflows
  over; the gateway is worth having for Claude on the web.
- **Cut for now:** the signed call log, OTLP and `wires watch`
  ([card 40](../done/40-cut-records.md)). **Gone:** badges and invites
  ([card 41](../done/41-idp-membership.md)).

## What to write

Every narrative doc, rewritten to the premise, in this order of care:
README, executive summary, the blog post, `usage.md`, `fabric.md`, then the
rest. Read cards 40, 41 and 42 and their *Notes* first: each lists the
statements it made false.

1. **One statement of the core**, the board's, quoted or paraphrased
   consistently everywhere. No doc carries its own variant.
2. **README.** The hook stays (a colleague's agent, your sqlite database).
   Then the thesis and why, then the three hurdles as three commands
   (`wires login`, `wires services`, `wires call`), then push, then the MCP
   bridge, then the numbers, then limits. The quick tour is card 41's first
   run, verbatim from a real run. The comparison with a remote MCP server
   loses its "record of calls" row or says plainly that wires keeps none
   yet.
3. **Argue the thesis on results, not schemas.** Our own benchmark found
   schemas cost about 400 tokens with tool search on and about 10.2k with it
   off, and that bare `gh` did slightly better than `wires call gh`: the
   saving belongs to the CLI, and wires' job is to make the CLI reachable.
   Don't write "JSON-RPC overhead": nobody measured framing. What was
   measured is results entering context whole. Cite, as others' findings
   with their own caveats:
   - Anthropic, "Code execution with MCP" (2025-11-04): tool definitions
     and intermediate results as the two costs; 150,000 → 2,000 tokens on
     one Drive-to-Salesforce workflow.
     <https://www.anthropic.com/engineering/code-execution-with-mcp>
   - Cloudflare, "Code Mode" (2025-09-26): "LLMs have seen a lot of code.
     They have not seen a lot of 'tool calls'."
     <https://blog.cloudflare.com/code-mode/>
   - Scalekit's GitHub benchmark (2026-03-11): CLI used 4–32× fewer tokens
     than GitHub's MCP server over 75 runs; it also says MCP is still needed
     for per-user authorization, tenant isolation and audit, which is the
     gap wires is aimed at (and audit is the part wires doesn't have yet).
     <https://www.scalekit.com/blog/mcp-vs-cli-use>
   Composition has no evidence of ours yet (all five benchmark tasks are
   single-service reads): say so, or don't claim a number.
4. **Answer SSH.** `storytelling.md` and the README's comparison: SSH,
   Tailscale SSH and Teleport give a person a login on a machine; wires gives
   a person a named service wherever it runs, with no account or shell on
   the host. Not "TTY versus process": `ssh host cmd` runs one command with
   no TTY.
5. **Claim only what the code does.** A service with several hosts fails
   over; it does not spread load ([card 46](46-spread-calls-across-hosts.md)),
   so no "horizontally scalable". Hosts still hold a push queue. The limits
   list gains what card 41 gave up and that no call record is kept.
6. **One word per thing**, in every doc and in help text: *network* (never
   "fabric" in prose; it remains a field name), *policy* for the signed
   document (never "registry", "state" or "signed list"), *sign-in* /
   *ID token* for the credential, *host*, *directory*, *service*, *role*,
   *push* and *inbox*. Gone words: badge, membership, invite, reader,
   record, call log, audit.
7. **`usage.md`** split by reader: a walkthrough from a real run of the
   demo script, the command reference, `host.json` (with card 42's
   environment), limits. The design rationale shrinks to what the premise
   needs.
8. **`docs/media/`**: the recording shows invites and `wires watch`. Remove
   it from the README and delete the files (git history keeps them); note on
   [card 08](../doing/08-demo-two-machine.md) that the recording is to be
   redone, and update `demo.md`'s script to the new first run.
9. **`CLAUDE.md`**: the architecture section's file list, against the tree.

## Acceptance

- [ ] Each of README, the executive summary and the blog post states the core once, the same way, and passes the rebuttal test in `storytelling.md` §1, SSH included.
- [ ] Every command, flag, file name, environment variable and output line shown in a doc exists and behaves that way: run them, or read the code.
- [ ] `grep -rniE 'badge|membership|invite|wires watch|call log|reader|registry|fabric' README.md docs/*.md docs/blog` has only hits that are deliberate (list them in *Notes*).
- [ ] No doc promises load spreading, a call record, or MCP as a goal.

## Notes
