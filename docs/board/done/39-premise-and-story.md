# 39 — The premise and the story

**Stage:** 3 · **Depends on:** [41](41-idp-membership.md) merged (the commands the docs show must exist) · **Status:** done (merged into `simplify` 2026-10-05; checked by [card 43](43-accuracy-sweep.md)) · **Files:** `README.md`, `docs/executive-summary.md`, `docs/blog/introducing-wires.md`, `docs/storytelling.md`, `docs/usage.md`, `docs/fabric.md`, `docs/demo.md`, `docs/deployment.md`, `docs/testing.md`, `docs/agent-sandbox.md`, `docs/media/`, `CLAUDE.md`, `wires/help.rs` (the premise paragraph only)

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
  ([card 40](40-cut-records.md)). **Gone:** badges and invites
  ([card 41](41-idp-membership.md)).

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
   over; it does not spread load ([card 46](../backlog/46-spread-calls-across-hosts.md)),
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

### 39a, the story half (worker, 2026-10-05, branch `worker/39a-story`)

Items 1–6, 8 and 9, in `README.md`, `docs/executive-summary.md`,
`docs/blog/introducing-wires.md`, `docs/storytelling.md`, `docs/media/`
(deleted), `CLAUDE.md`, and a dated note on card 08. Items 7 and the rest of
the narrative docs are the other worker's.

- **The core** is the board's one idea, quoted verbatim as the README's
  tagline and in the executive summary, paraphrased once in the blog post.
- **README** order: hook (with the real output of the group-by query) →
  why CLIs and the three hurdles → quick tour (card 41's first run, then a
  push and a removal) → how it works → push → MCP as a bridge → measured
  (our benchmark plus the three external sources) → compared with what you
  have (remote MCP, SSH, Tailscale; "no log of calls" stated plainly) →
  limits → more. The recording is gone from it.
- **Executive summary:** one page, ends on the next step and the board's
  kill criteria, not on a question to the audience. Dropped the Okta,
  OpenClaw and EU AI Act paragraph (it argued for call records, now cut, and
  I couldn't verify its numbers).
- **storytelling.md:** a new section with the sharpest attacks (SSH as
  machine versus service, Tailscale, remote MCP, "where's the audit log?"),
  "claim only what the code does", and the vocabulary of item 6.
- **CLAUDE.md:** overview no longer says the code "still has" badges or the
  log; protocol.md's contents listed as they are; build commands gain
  `demo-push.sh` and `make install`; the architecture list checked against
  the tree (adds `help.rs`/`help_snapshots.rs`/`snapshots/`, `clock.rs`,
  `net.rs`, `mock_idp`, shaping, locked mode, `bench/help/`,
  `bench/state-scale/`; drops `docs/media/`).
- **Integrator note (card 47) applied:** "in the network if a role matches
  you"; no output shown for a signed-in person in no role; no refusal text
  for a not-allowed or unknown service quoted; the stale-view limit says the
  hard bound is the policy's expiry, not a day; `wires remove <node>` is
  described as taking a host or directory machine out, a person is removed
  by email.
- **Verified:** the quick tour was run by hand with the release binary
  (`--features dev-mock-idp`) on one machine, three keystores, the stand-in
  IdP in place of Google (so `init` also took `--issuer` and
  `--public-client-secret`), hint files copied between keystores; every
  command exited 0, none repeated; the call after `remove` exited 77. The
  output shown is copied from that run, with long ids and the network string
  cut short and sqlite's trailing column padding trimmed; the admin edits'
  stderr notes are summarized in the footnote, not shown. Push output:
  the operator form `wires push --to <node id>` was run; the in-call
  `$WIRES_CALLER_NODE` form is shown from `.scripts/fixtures/ci.sh` without
  output. `.scripts/demo-remote-cli.sh --quiet` passed (exit 0). External
  sources' dates, quotes and numbers checked against the pages.
- **Deliberate grep hits** (`badge|membership|invite|wires watch|call
  log|reader|registry|fabric|audit|otlp|record`): CLAUDE.md 19 ("no badges,
  no invites") and 33–35 (what was cut, and that nothing records calls) —
  history a worker needs; CLAUDE.md 54 `docs/fabric.md` (the file's name);
  CLAUDE.md 169 "per-call log line" (true); README 225–226 and summary 28
  (Scalekit's own words, and that wires has no audit trail); README 263,
  blog 41, summary 127–128 (no record of calls, stated plainly); summary 88
  and 140, storytelling 11, 20, 71 ("recording", the verb/noun for video);
  storytelling 33, 60–64 (the register test and the vocabulary rule naming
  the banned words); storytelling 47 (the audit-log attack and its answer).

Errors found in files not mine (for the integrator / card 43):

- `wires/help.rs` line 25 (the premise paragraph, listed in this card's
  files but code, so not touched): "an admin-signed list of who may call
  what" uses the retired "list"; item 6 says *policy*. The snapshots follow.
- `docs/board/README.md` line 13–15 ("Until card 41 merges, the code still
  has badges and invites"), the lane table's links to `backlog/39-…` and
  `backlog/41-…` (39 is now in `doing/`, 41 in `review/`), and the Roles
  heading "The target, once card 41 merges".
- `docs/protocol.md` uses "registry" for the policy at lines 172, 222, 428,
  524 and 707 (§§3, 4, 5, 7); item 6 retires the word. (Line 573's
  "live-token registry" is another thing.)
- `bench/REPORT.md` and `bench/push/REPORT.md` notes say "admin-signed
  registry"; dated reports, left alone.
