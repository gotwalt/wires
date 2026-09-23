# 17 — README: what it's for, and why it's built this way

**Lane:** docs · **Depends on:** 12–15 (and 16's result for the efficiency row) · **Files:** `README.md`, `docs/demo.md` (new)

## Goal

Someone from the MCP team reads the first screen and can answer: what is this,
who runs which command, where is the IdP enforced, how does an agent find a
tool, and why isn't this just Tailscale plus an MCP gateway.

## Structure

1. The pitch (board README, verbatim or tighter).
2. **One diagram** of the four roles (admin, host, caller, observer), with the channel in the middle carrying the host announcements, identity claims and call records. Say *where each guarantee lives*: reach (the key, no network path), policy (`host.json` on the host), identity (the IdP token, bound at `login`, verified by every reader), observability (records written by the host, readable by anyone on the channel).
3. **The 5-minute walkthrough**: `init` / `invite` / `join` / `serve host.json` / `login` / `call` / `watch`, with real output from `demo-remote-cli.sh`.
4. **Why it's built this way**, one short paragraph per decision:
   - CLI first, MCP only for backward compatibility (with the numbers from card 16, whatever they are);
   - dial by key rather than by host and port;
   - the host writes the log, not the caller or a gateway;
   - identity is the IdP's own signature, not a wires service;
   - the channel as the directory;
   - policy in one file, with room for a real policy engine later.
5. The "why not…" table (keep it, tightened; add "why not A2A" only if it survives the rebuttal test).
6. Reference: the command list by role, `host.json` schema, the `advanced` commands.

`docs/demo.md`: the recorded-demo script, meaning narration, commands, the exact wording for ports ("no TCP listener, no firewall port opened; unauthenticated peers are refused at the handshake"), and one-line answers to the expected rebuttals.

## Acceptance

- [ ] Every sentence passes storytelling.md §1.
- [ ] Every command in the README runs as written against the current binary; the walkthrough is checked by a script, or by running `demo-remote-cli.sh`.

## Notes
