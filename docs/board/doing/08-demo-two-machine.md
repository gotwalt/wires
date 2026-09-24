# 08 — The real demo: laptop ↔ workbench, Claude Code as the agent

**Lane:** E · **Depends on:** 07 · **Needs the human:** yes (Google OAuth client, workbench access, recording)

## Goal

The thing we show. Two physical machines, no TCP listener and no firewall port opened on the
workbench, a real Claude Code session calling a remote CLI by service name, a
reader streaming every call from the host's signed log, and a live removal.

## Steps

The run follows [docs/demo.md](../../demo.md) (cheat sheet at its top).

- [x] Google OAuth "Desktop app" client created (human); env documented in `docs/demo.md`.
- [x] Narration scripted in `docs/demo.md`: cheat sheet per terminal, the prompt, what to
      point at, the removal, and the one-line rebuttal answers (Tailscale, MCP gateway logs,
      IdP/enterprise-managed auth, webhooks, polling, log tampering).
- [x] Token comparison: n=1 in the Notes below, superseded by `bench/REPORT.md` (card 16,
      arm 5 in card 19) and `bench/push/REPORT.md` (card 24).
- [ ] Loopback gate green on HEAD: `.scripts/demo-remote-cli.sh --quiet` and
      `.scripts/demo-push.sh --quiet`.
- [ ] workbench on HEAD: push to `~/src/wires-demo`, `cargo build --release -p wires`,
      replace the old `wires-demo` unit (it predates the services surface), `orders.db` +
      `host.json` (Google issuer, `orders-db`, `push`), fresh keystore.
- [ ] Provision per `docs/demo.md`: `init --client-id … --public-client-secret …`;
      `role set analyst` / `role set security`; `invite` workbench; `directory add
      workbench`; `service add orders-db --allow analyst --reader security --host
      workbench` (both edits exit 1: no directory is up yet); re-invite workbench (that
      token carries the policy); `join`; `serve --check host.json`; `serve host.json` under
      `systemd-run --user` (it is also the directory); `ss -ltnp` shows no TCP listener.
- [ ] laptop: agent and reader `id` / `join`; reader `wires login` (bare: the invite names
      the IdP); Claude Code with
      `WIRES_HOME=~/.wires-agent` and `--allowedTools 'Bash(wires call orders-db:*)'`
      (optionally `wires mcp` in its MCP config, shown only as the compatibility path).
- [ ] Dry run, every beat of the cheat sheet: `services` says to `wires login` and `call`
      exits 1 (no service by that name for this node) before login → `wires login` (real Google) → `services` lists `orders-db (analyst)` → Claude
      Code answers → reader's `wires watch orders-db` shows `▶`/`■`/`✗` → optional push beat
      (`deploy`/`inbox --wait`/`logs`) → `wires remove agent` → exit 77, 0 bytes out.
- [ ] **Recording.** Capture (asciinema + agg, or screen capture) and embed it in the
      README.
- [ ] Re-record the loopback GIF/MP4 in `docs/media/` (README): they show the refusal
      text from before cards 28 and 34 ("fabric"). Card 34 deleted the unlinked push
      recording and the casts; re-cast both demos from the scripts' narrated mode.

## Notes

### Lessons from the first two workbench runs (2026-09-23)

Both runs used a surface that has since been deleted; these still hold.

- **SSH:** `ssh -o RemoteCommand=none workbench` (the ssh config forces a remote command).
- **Build natively on workbench.** Cross-compiling x86_64 Linux from macOS is broken
  (curve25519-dalek's simd backend: `curve25519_dalek_derive` unresolved). The
  Dockerfile builds natively too; fix the cross-compile only if we need x86 images from
  a Mac.
- **Reach:** with no address hints, the first call connected through n0 discovery and
  relays in 1.2 s. `ss` on workbench: **0 TCP listeners**; two UDP sockets (QUIC).
  Narration says "no TCP listener, no firewall port opened, and unauthenticated peers
  are refused at the handshake", never "no ports".
- **Safari:** the browser shows the "signed in" page after `wires login` (confirmed by
  the human; card 11's fix).
- **Tokens, n=1** (Claude Code, "highest-spend customer and share of revenue"; both
  answered umbrella, $999 of $1,629.84, 61.3%):

  | | turns | input tokens (total) | output | cost |
  |---|---|---|---|---|
  | MCP (stdio) | 5 | 167,696 | 440 | $0.2145 |
  | `wires call` via Bash | 3 | 101,090 | 402 | $0.2027 |

  Input is −40% for the CLI, but cost is only −5%, because cached reads dominate and the
  ~22k cache write is the same for both. Most of the gap is two extra schema-exploration
  turns on the MCP side. **Don't headline this number**; `bench/REPORT.md` is the n≥5
  result.
