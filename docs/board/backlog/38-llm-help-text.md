# 38 — Help text an LLM can act on: predictable, useful, terse

**Lane:** H · **Depends on:** [37](37-caller-views.md) (the CLI surface settles there) · **Status:** backlog, 2026-09-24 · **Files:** `wires/lib.rs` (clap definitions), every command's error text, `wires/caller/mcp.rs` and `wires/gateway/` (tool names, descriptions, schemas), `wires/e2e/` or a new `wires/help_snapshots` test, usage.md § Reference

## Why (the human, 2026-09-24)

"We should also do a pass to ensure that LLMs using these tools get predictable, highly useful and
terse help text." The pitch is CLIs over MCP because a model already knows how to use a CLI and
reads less to do it (card 16's token benchmark). That only holds if `--help`, the errors and
the MCP tool descriptions are what the model needs, and nothing it doesn't.

What's wrong today (at 6f2c67c):
- `wires call --help` spends 6 of its 10 options on credential overrides (`--node-seed`,
  `--membership`, `--tools-file`, …) that an agent should never touch and locked mode refuses anyway.
- No examples, anywhere. A model learns a CLI fastest from one example line.
- Refusals and failures don't always say the next command to run (`wires login`, `wires services`,
  ask the admin for …).

## The premise, told to agents (the human, 2026-09-24)

"We should also make sure to explain the fundamental premise of wires to agents: that it is a
network abstraction for authenticated remote CLI interactions." An agent that knows the model
uses it correctly: it asks for services by name, doesn't look for hosts or addresses, and treats a
refusal as policy rather than a bug to work around.

**One paragraph, one constant**, used everywhere an agent first meets wires: the preamble of
`wires --help`, `wires mcp`'s and the gateway's MCP `instructions` (replacing today's
`INSTRUCTIONS` in `caller/mcp.rs`), and the empty-result text of `wires services`. Draft, to be
tightened by the eval:

> wires is a network for authenticated remote CLI calls. Each service is a command-line program
> on another machine; run it by name (`wires call <service> -- <args>`), never by address.
> Every call runs as you: your sign-in is checked against an admin-signed list of who may call
> what, and the machine that ran it records the call. A refusal (exit 77) is that policy, not a
> fault; don't retry or work around it. `wires services` lists what you may call.

Rules: say "network" and "service", not "fabric" or "tool"; describe what the agent does and
what it can rely on, not how wires is built; under 90 words.

## Rules (the checklist every command is held to)

0. **The premise paragraph above** appears in `wires --help`, the MCP `instructions` and the empty
   `wires services` output, from one constant.
1. **First line: a verb, what it does, under 80 characters.** It's what `wires --help` lists and
   what a model reads first.
2. **One or two examples** under the usage line, as real commands (`wires call orders-db -- "select 1"`).
3. **Only what a caller uses.** Operator and credential-override flags move to `--help-all` (clap
   `hide`, listed there), still documented in usage.md.
4. **Exit codes and output shape stated once, where they matter:** `call` says 77 = refused
   (nothing on stdout), 1 = local or transport failure, else the remote exit code; `services` says
   its output format.
5. **Every error ends with the next step,** in one clause: `run \`wires login\``, `see \`wires services\``,
   `ask the admin to run \`wires invite <this node's id>\``. No stack of causes on stderr unless
   `--verbose`.
6. **Stable, parseable output** where a model will read it: `wires services` gets `--json` (name,
   description, call/read, hosts count) and its plain form stays one service per line.
7. **Same words everywhere:** "service", "host", "network" (not "fabric", "tool" or "state" in
   caller-facing text); one refusal wording (card 34).
8. **MCP matches the CLI:** tool names are service names; descriptions are the registry's
   description, trimmed to one sentence; `search_services` (card 37) and `call` descriptions state
   the refusal behaviour in one line.

## Acceptance

- [ ] The premise paragraph is one constant, shown by `wires --help`, both MCP servers'
      `instructions` and an empty `wires services` (snapshot-tested).
- [ ] Every command and subcommand passes the checklist; `wires --help` and each caller command's
      `--help` fit in 25 lines.
- [ ] Snapshot tests hold the help text and the key error messages, so a change to what a model
      reads is a reviewed diff.
- [ ] A small eval, reusing `bench/`'s harness: a few headless `claude -p` sessions, each with
      only `wires` and a task ("find the service that…", "call it", "you were refused — why?"),
      succeed without the model guessing a flag, and one task checks the premise landed (asked
      "what is wires and how do you reach the orders database?", it answers by service name, not
      host or address); report turns and tokens before and after.
- [ ] usage.md § Reference matches the help text.

## Notes
