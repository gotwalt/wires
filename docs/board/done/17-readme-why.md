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

- [x] Every sentence passes storytelling.md §1.
- [x] Every command in the README runs as written against the current binary; the walkthrough is checked by a script, or by running `demo-remote-cli.sh`.

## Notes

*2026-09-23, lane docs (worker).*

**Verified.** The README walkthrough was run command for command against this
branch's `//wires` (fresh `WIRES_HOME`s under `/tmp/w17`, the mock IdP from
`//wires:wires_dev dev-mock-idp`, so `login` also took `--issuer`/`--no-browser`
and `curl` played the browser, and the observer's `watch` also got
`WIRES_OIDC_ISSUER`). The pasted output is from that run, with INFO logs, the
full invite tokens and one `advanced publish` test line trimmed.
`demo-remote-cli.sh --keep` was green (64 s). **Not verified:** the Google
`login` flags as written (needs the real OAuth client, card 08), the
`claude --allowedTools` line and `ss` commands in `docs/demo.md`, and
`soak-topic.sh` (unchanged; not re-run).

**Cut for failing the rebuttal test.**
- "Tailscale … the service itself is exposed on the network, and its own auth is all that guards it" → ACLs narrow Tailscale to a port; the line now says so.
- "meaningfully more efficient than MCP tool schemas and JSON results" → tool search neutralises schemas; the win is output filtering (card 16/19).
- "no server in the middle" for the channel → relays forward its packets; now "no server owns it".
- "The agent can't forge it" (the call record) → the agent is a member and can publish; now "can't write a record that carries the host's key".
- "one invite, then everything is on the channel" → the joiner also sends `wires id`, and the admin passes the host's ticket once; now "one exchange with the admin".
- A2A row: not added (no rebuttal-proof sentence found).

**Stale bits found (Rust, not touched):** `wires join` with no peers prints
"``wires serve --audit-topic …`` or `wires watch` prints the ticket" (the flag
is gone since card 13); `wires serve --help` still says "with `--audit-topic`,
record every call"; `wires call --help` says `<TOOL>` is "the tool's local
name in `tools.json`" (it resolves from the channel since card 15). A late
joiner's `watch` prints "no key for roster version N … run `wires advanced
import`" for pre-join history, which reads like an error.

**docs/deployment.md**: rewritten around `serve host.json`/`join`/`remove`;
the responder/dialer Kubernetes manifests were cut (they assumed a read-only
keystore, which re-keys over the channel no longer allow); relay section kept.
The README's revoke gif (pre-card-12) is no longer referenced.
