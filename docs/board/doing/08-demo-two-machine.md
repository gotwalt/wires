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
- [ ] Record (asciinema + agg, or screen capture) → add the recording to the README (the old `demo-revoke.gif` was deleted).

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
