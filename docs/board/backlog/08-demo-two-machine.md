# 08 — The real demo: laptop ↔ workbench, Claude Code as the agent

**Lane:** E · **Depends on:** 07 · **Needs the human:** yes (Google OAuth client, workbench access, recording)

## Goal

The thing we show. Two physical machines, no inbound ports on workbench, a real
Claude Code session calling a remote CLI, a third terminal watching every call,
and a live revocation.

## Steps

- [ ] Google OAuth "Desktop app" client created (human); env documented in `docs/demo.md`.
- [ ] workbench: `wires` binary (cross-compiled via `//wires` Linux target or built there),
      keystore imported, `orders.db`, `wires serve --expose … --audit-topic ops --require-idp …`
      under a process supervisor. Verify with `ss -ltnp` that nothing new listens.
- [ ] laptop: `tools.json` entry for `db_query` by node id; `claude mcp add wires -- wires mcp`;
      also allow `Bash(wires call:*)` so the CLI path is shown side by side.
- [ ] observer: third terminal (or a second laptop) running `wires tail ops`.
- [ ] Script the narration in `docs/demo.md`: the prompt given to Claude, what to point at,
      the revoke command, and the one-line answers to the three expected rebuttals
      (Tailscale, MCP gateway logs, IdP/enterprise-managed auth).
- [ ] Token comparison: same task via `wires call` (Bash) vs `wires mcp` — record
      input/output token counts from the session for the CLI-efficiency claim. Report
      honestly even if the gap is small.
- [ ] Record (asciinema + agg, or screen capture) → replace `docs/demo-revoke.gif` in README.

## Notes
