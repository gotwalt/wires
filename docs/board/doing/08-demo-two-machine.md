# 08 — The real demo: laptop ↔ workbench, Claude Code as the agent

**Lane:** E · **Depends on:** 07 · **Needs the human:** yes (Google OAuth client, workbench access, recording)

## Goal

The thing we show. Two physical machines, no TCP listener and no firewall port opened on the
workbench, a real Claude Code session calling a remote CLI by service name, a
reader streaming every call from the host's signed log, and a live revocation.

## Steps

*Rewritten 2026-09-23 for the services surface (card 27/26). The first two
runs in the Notes used the channel-era surface (`--expose`, `--audit-topic`,
`tools.json` entries by node id, the channel, `wires tail`), which is deleted.*

- [x] Google OAuth "Desktop app" client created (human); env documented in `docs/demo.md`.
- [x] Narration scripted in `docs/demo.md`: cheat sheet per terminal, the prompt, what to
      point at, the revoke, and the one-line rebuttal answers (Tailscale, MCP gateway logs,
      IdP/enterprise-managed auth, webhooks, polling, log tampering).
- [x] Token comparison: n=1 in the Notes below, superseded by `bench/REPORT.md` (card 16,
      arm 5 in card 19) and `bench/push/REPORT.md` (card 24).
- [ ] Loopback gate green on HEAD: `.scripts/demo-remote-cli.sh --quiet` and
      `.scripts/demo-push.sh --quiet`.
- [ ] workbench on HEAD: push to `~/src/wires-demo`, `cargo build --release -p wires`, stop the
      old `wires-demo` unit (still the Bazel, channel-era build), `orders.db` +
      `host.json` v2 (Google issuer, `orders-db`, `push`), fresh keystore.
- [ ] Provision per `docs/demo.md`: `init`; `role set analyst` / `role set security`;
      `invite` workbench; `service add orders-db --allow analyst --reader security --host
      workbench`; re-invite workbench (it was offline for that push); `join`;
      `serve --check host.json`; `serve host.json` under `systemd-run --user`; `ss -ltnp`
      shows no TCP listener.
- [ ] laptop: agent and reader `id` / `join`; reader `wires login`; Claude Code with
      `WIRES_HOME=~/.wires-agent` and `--allowedTools 'Bash(wires call orders-db:*)'`
      (optionally `wires mcp` in its MCP config, shown only as the compatibility path).
- [ ] Dry run, every beat of the cheat sheet: `services` empty and `call` exit 77 before
      login → `wires login` (real Google) → `services` lists `orders-db (analyst)` → Claude
      Code answers → reader's `wires watch orders-db` shows `▶`/`■`/`✗` → optional push beat
      (`deploy`/`inbox --wait`/`logs`) → `wires remove agent` → exit 77, 0 bytes out, `✗` in
      the watch.
- [ ] **Recording — in progress.** Capture (asciinema + agg, or screen capture) and embed
      it in the README (the old `demo-revoke.gif` was deleted).

## Notes

### First two-machine run — 2026-09-23 (integrator)

- **Setup:** laptop holds the root, the agent (real Google identity, gotwalt@gmail.com), and the observer. workbench (x86_64 Ubuntu) runs `serve --expose 'db_query=sqlite3 -safe -readonly -header -column orders.db' --audit-topic ops --require-idp 'iss=https://accounts.google.com,email=gotwalt@gmail.com' --oidc-audience <client id>` as `systemd-run --user --unit wires-demo`. Code is at `~/src/wires-demo` (separate from the old `~/src/wires` clone), built natively with a user-local bazelisk (`~/.local/bin/bazelisk`; the system bazel is the wrong version). Keystore is `~/.wires-demo`. SSH needs `-o RemoteCommand=none` (the ssh config forces a remote command).
- **Linux cross-compile from macOS is broken for x86_64** (curve25519-dalek simd backend: `curve25519_dalek_derive` unresolved). Native build is fine. Needs a follow-up if we want x86 images.
- **Reach:** `tools add db_query --node <workbench id>` with **no address hints**. The first call connected through n0 discovery and relays in 1.2 s. `ss` on workbench: **0 TCP listeners**; two UDP sockets (QUIC). Narration must say "no TCP listener, no firewall port opened, and unauthenticated peers are refused at the handshake", **not** "no ports".
- **Identity:** the observer on the laptop printed `🪪 identity ecc8c1cf is gotwalt@gmail.com (verified by https://accounts.google.com)`; workbench's call records name the email.
- **Claude Code, same question through both front doors** ("highest-spend customer and share of revenue"). Both answered correctly (umbrella, $999 of $1,629.84, 61.3%):

  | | turns | input tokens (total) | output | cost |
  |---|---|---|---|---|
  | `wires mcp` | 5 | 167,696 | 440 | $0.2145 |
  | `wires call` via Bash | 3 | 101,090 | 402 | $0.2027 |

  n=1. Input is −40% for the CLI, but cost is only −5%, because cached reads dominate and the ~22k cache write is the same for both. Most of the gap is two extra schema-exploration turns on the MCP side. **Don't headline a number from this**; repeat with n≥5 and a harder task before claiming anything.
- **Still to do:** card 11 fixes (20 s audit stall after login, Safari callback page) → rebuild on workbench → `docs/demo.md` narration → recording.

### Second two-machine run, on the new surface — 2026-09-23 (integrator)

Fresh provisioning with `init` / `id` / `invite` / `join`; workbench runs `wires serve host.json` (role `analyst` = `gotwalt@gmail.com`) as `systemd-run --user --unit wires-demo` from `~/.wires-demo2`; `ss`: **0 TCP listeners**.

- Before login: `wires tools` → `1 host on channel "ops" announces nothing you may use`; `wires call db_query` → exit 77, `db_query needs a verified identity in role analyst (email=gotwalt@gmail.com)`; the refusal is on the channel.
- Real Google `wires login --topic ops`: **the browser now shows the "signed in" page (Safari fix confirmed by the human)**. Observer: `🪪 identity 4ad01c92 is gotwalt@gmail.com (verified by https://accounts.google.com)`; the announcement went from 0 to 1 sealed entry.
- After login: `wires tools` lists `db_query on 51442ef9`, with the no-shell hint line; `wires call` returns the rows; observer: `▶ … gotwalt@gmail.com (4ad0…) [analyst] db_query "select …"` / `■ exit 0`.
- **Claude Code, `WIRES_LOCKED=1`, PATH = only `wires` + /usr/bin:/bin, allowedTools `Bash(wires call:*),Bash(wires tools)`:** found the tool through `wires tools`, answered correctly (umbrella, $999.00, 61.3% of $1,629.84), 4 turns, $0.2131. Both of its queries are on the observer's log with the email and role.
- `wires remove agent` → roster v5 re-key on the channel → the agent's next call exits 77 with **0 bytes** of stdout, the `✗` is on the channel, and the workbench pid is unchanged (1727711).

**Camera polish (card 21):**
1. `watch` prints `📣 announces tools` for every 10-minute heartbeat (an overnight watch was a wall of them). Print only when an announcement changes.
2. `wires remove` prints two WARN lines (`gossip connection from a peer with no admission`, from the admin's one-shot node); `remove`/`invite` should be quiet by default.
3. A removed member's refusal reads `stale inclusion proof: proof targets version 4, head is version 5`. It should say "not in the current roster (removed at version 5)".
4. After `remove agent`, the host's re-announcement still carries **1 sealed entry**, and the only qualifying identity was the removed agent's. It looks like announcements are sealed to verified identities without checking current roster membership. The removed member can't open it (it's under the new channel key), but the recipient set should be the current roster ∩ allowed.


**Order agreed with the human (2026-09-23):** 24 → 25 (Cargo + strip) → 27 (services, not hosts; drop the channel) → 26 (host-held records) → recording.

### Steps rewritten for the services surface — 2026-09-23 (docs sweep)

Steps above now follow `docs/demo.md` (cheat sheet at its top). The workbench
unit `wires-demo` was still the Bazel, channel-era build at the time of the
sweep; it must be replaced before the dry run. Recording is in progress.
