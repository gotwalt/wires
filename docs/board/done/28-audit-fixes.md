# 28 — Audit fixes: make the premise true

**Lane:** A · **Depends on:** 27, 26 merged · **Blocks:** 29 · **Files:** repo-wide (`library/services/`, `wires/host/`, `wires/caller/`, `wires/state/`, docs)

## Why (the human, 2026-09-23)

The premise, which defines "correct" for this card: **remote CLIs are
distributed securely over iroh; IdP authentication and authorization keep out
anyone who isn't allowed; agents can't observe each other's work; `wires watch`
lets the people the registry names observe calls for logging and compliance.**

An audit of the code and every doc against that premise found that the core
holds. JWT checks are tight, the nonce is bound to the key iroh
authenticated, the gate re-reads the state on every dial in the documented
order, the state's compare-and-swap never rolls back, and hints are never
authority. The failures are at the edges, listed below. Pre-alpha, nothing
deployed: break formats freely and don't write compatibility shims.

**Decisions (2026-09-23):**
- The premise outranks the docs, and the docs outrank the code. Fix protocol.md's "the code is correct" line.
- The isolation boundary is the verified **person** (IdP principal), not the node.
- The built-in `member` role, which admits a member without any identity, is a violation. Remove it.
- Readers may see full record content (argv, `stdin_head`, push bodies).
- A service's push can reach only that call's caller.
- A call that can't be logged doesn't run.
- An admin edit that reaches no host fails loudly, and a command re-sends it.
- Fabric-wide metadata and the quadratic state are real problems, but they're solved by redesign, not here: [card 29](../backlog/29-identity-and-scale.md).

## Findings and fixes

Severity: **H** high, **M** medium, **L** low. Every item needs a test that fails before the fix.

### 1. The service child effectively is the host (H)

The child gets `WIRES_HOME` set to the host's keystore (`wires/host/transport.rs:549`).
It runs as the same user, so any service a caller can steer into reading or
writing files lets that caller:
- read `node.seed`, which also signs the call log (`serve.rs:86`), and so re-sign a rewritten log or impersonate the host;
- push to anyone through `run/serve.sock`, whose only protection is the file mode (`control.rs:17-24`);
- copy an older `state.json` back in: the host re-reads whatever verifies (`state/store.rs:23`) and keeps no in-memory high-water mark;
- plant an attacker IdP key in `jwks/`, which the host trusts from disk once its in-memory copy expires or after a restart (`caller/jwks.rs:188-203`). That forges any identity, readers included.

Separately, only inherited `WIRES_*` variables are scrubbed (`transport.rs:529`).
`HOME`, `SSH_AUTH_SOCK`, `AWS_*` and `GH_TOKEN` reach a command whose arguments the caller chooses.

**Fix:**
- No `WIRES_HOME` for the child.
- `env_clear()`, then `PATH`/`LANG`, then `host.json` `env`, then the server-set `WIRES_*`.
- Service push uses a per-call capability: `WIRES_PUSH_SOCKET` plus a per-call token that can push only to `WIRES_CALLER_NODE` and dies shortly after the call. Operator `wires push` uses a socket the child can't reach.
- The host keeps the highest state version it has seen in memory and refuses to decide under a lower one.
- JWKS stays in memory only, or a disk entry is capped at fetch time plus the TTL.
- Refuse to `serve` from a keystore holding `root.seed`.
- Docs: tell operators to run services as a separate Unix user.

### 2. `member` admits callers with no identity (H)

`library/services/access.rs:151` (`if role.is_member() { return true; }`)
applies in `allow`, `readers` (`record_stream.rs:323`), `push.allow` and
`also_require` (`config_v2.rs:266`). `push --to member` reaches every member
(`gate.rs:397`).

**Fix:** delete `MEMBER_ROLE` and its special cases (inventory: `role.rs`, `access.rs`, `state.rs`, `registry.rs`, `gate.rs`, `config_v2.rs`, `push.rs`, `record_stream.rs`, `admin/service.rs`, `caller/services.rs`, their tests, `bench/wires-up.sh`, `bench/push/up.sh`, protocol.md). Every role needs a verified principal. "Anyone signed in" becomes an `issuer=` matcher.

### 3. Matchers aren't tied to an issuer (M)

`role.rs:227` checks `issuer` only when it is set, so `*@acme.com` matches a
token from **any** issuer the host trusts. A partner Okta could vouch for
`alice@acme.com`. `hd` becomes `org` for every issuer (`idp.rs:362`).

**Fix:** every matcher names its issuer (`role set analyst '*@acme.com'` defaults it to Google or the fabric's configured issuer). Read `org` from `hd` only for Google.

### 4. Keyed by node where the boundary is the person (M)

- `watch --mine` compares node ids (`record_stream.rs:214`).
- The host's identity index keeps one principal per node, chosen by latest `exp` (`identity.rs:167`). Push and fetch decide from it (`gate.rs:362`), and `serve_fetch` discards the result of verifying the token it was just given (`push.rs:635`).
- The push queue is keyed by `NodeId` (`push.rs:201`).
- The gateway (branch `aaron/web-gateway`, one node for many people) turns each of these into a leak.

**Fix:**
- "Mine" means the same verified principal (issuer + subject) that `Started` recorded.
- ~~Push and fetch by principal~~ → moved to [card 31](../backlog/31-inbox-delivery.md) D1 (agreed 2026-09-24).

### 5. Records and `watch` (H/M)

- **H:** a `follow` stream is authorized once and never again (`record_stream.rs:409-446`), so a removed reader keeps streaming. **Fix:** re-check freshness, membership and readers on each state change and at the token's expiry, and close with `Denied`.
- **H:** records that have no service, including every `Push`, are shown to anyone who is a reader of *any* service on that host (`record_stream.rs:221,249`). That exposes other people's push subjects and bodies. **Fix:** a `Push` names the service that sent it and is scoped by it (and shown to its recipient). A `Finished` whose `Started` was pruned is shown only as a hidden link.
- **M:** marks are keyed per query (`watch_records.rs:211`), so `watch x` vs `watch`, or a new service on the host, starts with no anchor and a rewrite goes unnoticed. **Fix:** one chain anchor per host, plus a per-view resume point.
- **M:** rollback below the reader's mark isn't detected, because the host skips `seq <= since`; and 30-day pruning looks like tampering forever. Card 29's transparency-log checkpoints fix both properly. **Here:** `Granted` carries the host's tip and first held seq, and `watch` reports a retention gap separately from tampering.
- **L:** `watch --json` prints the service label the host supplied, which no signature covers. Derive it on the reader's side.

### 6. The log can miss calls (H)

The audit sink uses `try_send` on a 256-slot queue and drops records when full
(`transport.rs:79`, `audit.rs:32`). `Started` is queued *after* the child
spawns. Any key, member or not, gets a `Denied` entry written. So flooding
with junk connections gets real calls dropped from the log.

**Fix:**
- Append and fsync `Started` before the spawn, and refuse the call if that fails.
- Await, don't drop, `Finished`/`Denied`.
- Don't log refusals of non-members; trace them instead.

### 7. Push (M)

**Moved to [card 31](../backlog/31-inbox-delivery.md)** (agreed 2026-09-24): D1 callbacks go only to the calling node + principal, D1b operator push `--to <node>` only, D3 per-service `push`, D5 caps/dedup/purge. Nothing here is built in card 28.

### 8. State sync and the caller's view of it (M)

- A removed member re-offering its old, still-fresh state gets `Have{current}` back, and `mark_checked` stops the host pulling the newer one (`state/sync.rs:370-381`). The removal then isn't enforced until the old state expires. **Fix:** refuse the offer unless it was adopted or the dialer is a member of the held copy; mark checked only after a real adopt or a reply from a host or the admin.
- The responder serves an expired state (`sync.rs:383`). **Fix:** refuse.
- The admin never listens, and non-hosts never answer pushes (only `serve` mounts the responder). So a change every host misses is never delivered. **Fix:**
  - an edit that reaches no host exits non-zero;
  - `wires state push` re-sends the current state;
  - push only to members that listen.
- `invite --ttl 1h` and `remove --ttl` set the **fabric's** expiry (`admin/service.rs:184`). **Fix:** membership TTL and state TTL are separate flags, and an edit never shortens `not_after`.
- The caller dials using an expired state, sends argv and its token before checking the host, and adopts `HelloAck.newer_state` only after the call (`call.rs:322-364`, `transport.rs:737`). **Fix:**
  - refuse an expired state;
  - send `Invoke` only after `HelloAck` verifies;
  - adopt `newer_state` first, and require that it still assigns the service to this host.
- A `tools.json` alias beats a registered service with the same name and can point at any member (`call.rs:527`, `mcp.rs:484`). **Fix:** a registered service wins, and an alias's target must be assigned the service in the current state.

### 9. Pre-auth cost and what refusals reveal (L)

- Session frames allow 16 MiB and inbox frames 4 MiB, allocated up front before any check (`transport.rs:189`, `library/calls/push.rs:97`). **Fix:** cap `Hello`/`Invoke` at 64 KiB, allocate as bytes arrive, and limit concurrent pre-auth sessions and fetches.
- Non-members get `membership rejected: <exact reason>` and the state version (`transport.rs:472`, `gate.rs:116`). Members get host-local `also_require` names and the host's HTTP errors. **Fix:** a fixed "not admitted" for non-members; generic issuer and network text; details go only to the log.
- The host verifies the token before checking membership (`transport.rs:471`). **Fix:** check membership first.

### 10. Small ones (L)

- Temp files are created with the umask and chmod'ed afterwards (`keystore.rs:336`). **Fix:** open with mode 0600.
- The short control-socket directory's owner isn't checked (`control.rs:410`).
- Locked mode can be undone through `WIRES_HOME`, `WIRES_NODE_SEED`, `WIRES_MEMBERSHIP` or `WIRES_LOCKED=0` (`lock.rs:142`). Document that it assumes the agent can't set its environment, or refuse the variables too.
- A remote exit 77 looks like a refusal (`main.rs:191`).
- OTLP export allows plain `http` to a non-loopback address (`otlp.rs:59`).
- Arguments can be options (`gh api -X DELETE`). Document that a service's fixed command must be safe against any trailing options. Offer a `host.json` flag that inserts `--`.

### 11. Docs that contradict the code or each other

- "Refused at the handshake" (README:39, deployment:17, demo:158/312, usage:231, summary:35). In fact any key can connect, and a non-member is refused at its first message, before anything runs.
- "Pushed to every member / machine" (CLAUDE.md:14, README:55, summary:24, board:47, deployment:51). Only hosts receive pushes; the others pull.
- "Cuts a member off at its next call" (README:83, usage:31/333, deployment:95, board:54, demo:296, summary:38). It happens at the next call on each host that has the new state.
- "Nothing is broadcast" vs `push --to member` and the state push. Resolved by 2 and card 29; until then, qualify it.
- "No TCP listener on either side" (README:98). `wires login` binds loopback TCP.
- "The caller never learns an address" (board:29). iroh direct paths and `run/hint` show it.
- protocol.md:128 ("catches up by its next pull") vs :282 and usage:302 ("can't start `serve`"). Fix: pull before `preflight`.
- protocol.md §8 leaves out the rule that service-less records go to any reader. §10's "caller checks membership only" isn't true of the inbox receiver.
- The call log's "fsync before it counts" (`host/call_log.rs:7`) vs "best effort" (`audit.rs:17`). Resolved by 6.
- `config_v2.rs:243` says `check_against` re-runs when the state advances. It runs only at `preflight`.
- Stale references:
  - `idp.rs:1-18` and the `IdentityClaim` docs describe the channel;
  - `keystore.rs:11` names the wrong files;
  - `role.rs:11` points at a deleted `policy.rs`;
  - `WIRES_INCLUSION_PROOF` in agent-sandbox.md:133;
  - card 09 says "without decrypting";
  - demo.md:32 expects `<id8> is not a member`.
- The board's non-negotiable "no host holds a key it doesn't need" vs 1. Resolved by 1.

## Order

1. Remove `member` (2) and name the issuer on every matcher (3). This is the shape the gateway builds against, so land it first and tell the `mcp` session.
2. The child and host hardening (1), logging fail-closed (6), and pre-auth caps (9).
3. Records (5), push (7), and person keying (4).
4. State sync and the caller (8), and the small ones (10).
5. The docs sweep (11), last, against the code as it then is.

## Acceptance

- [x] A test for each finding (named per section in the integrator review below). Red-before-fix was checked for a sample (L2a all; L2b, L3 some; L6 all), not for every test.
- [x] `make demo` green; the push demo uses the per-call push capability (`.scripts/fixtures/ci.sh`).
- [x] `grep -rn "is_member()\|MEMBER_ROLE" library wires` is empty.
- [x] README, usage, protocol, summary and CLAUDE.md agree with the code (docs sweep L5; five claims spot-checked in review).
- [x] `make lint test` green (129 / 334 / 41 at 419818b).

## Notes

### Integration (2026-09-24)

Lanes merged into `aaron/audit-fixes`: L1 (§2, §3), L2a (§1, §10 socket dir), L2b (§6, §9), L4 (§8, §10), then main (cards 30/31). Deviations from the text above:
- §8: `Invoke` is still sent with `Hello`; the caller adopts `newer_state` and re-checks the assignment before stdin, but a removed host whose membership hasn't expired still sees argv. Closed by card 29's ban list.
- §9: `MAX_INVOKE_FRAME` is 512 KiB, not 64 KiB (a legal 64 KiB `Argv` JSON-escapes to more).
- §6: refusals of non-members (including a removed member) are traced, not logged, so a removed member's later attempts no longer appear in `watch`.
- §8: pull order is last-good hosts, then other hosts, then the admin (computing "services I may call" needs a JWKS fetch).
- Admin edits that reach no host exit 1 (the state is still stored); scripts that edit before any host is up must tolerate it.
- §5 records (lane L3, 93312df) and §11 docs sweep (L5, c8ef536) merged. Review follow-ups (state-sync and record-stream pre-auth caps, receiver text, child socket placement, `end_of_options`) in lane L6.
- Decided 2026-09-24: service isolation beyond card 28 §1 is [card 32](../backlog/32-service-sandbox-OPEN.md) (a future rootless microVM); next card is 31, then 29.


### Docs sweep (§11, lane L5)

Documentation and doc comments only; no behaviour changed.
- **Precedence:** protocol.md's intro, the board's non-negotiable and CLAUDE.md now say the premise outranks the docs and the docs outrank the code. The premise is stated in the board README, protocol.md and CLAUDE.md.
- **§11 items:**
  - "refused at the handshake" is now "any key can connect; one the state doesn't list is refused at its first message";
  - "pushed to every member/machine" is now "pushed to the hosts; others pull";
  - "cuts off at next call" is now "at each host that has the new state";
  - "nothing is broadcast" is qualified by the whole state every member holds (card 29), and for records by hash links;
  - "no TCP listener on either side" is now "on the host", naming `wires login`'s loopback port and the gateway;
  - "never learns an address" is now "never names or configures one";
  - usage's "can't start `serve`" now agrees with protocol §4 (a host pulls from other hosts when its preflight fails);
  - stale references fixed: `idp.rs`/`IdentityClaim`, `invoke.rs` (`--expose`), `keystore.rs` file names, `config_v2.rs` `check_against`, `sync.rs` "before its preflight", roster-head and channel leftovers, board card 09's "without decrypting";
  - demo.md's `remove` output now matches the code.
- **`member`:** it no longer appears as a role anywhere, except protocol §3's "an ordinary role name", which is kept on purpose. Bench reports carry a one-line "setup has changed" note.
- **Push:** the docs describe push as built (per-call capability, operator socket, role push) and link card 31 as next.
- **Known limits:** README, usage, protocol §10 and the summary list what stays accepted until card 29: the O(members) org chart every member holds, argv seen by a removed host, hidden-link count and timing, and Google's ~1 h tokens with the nonce dropped on refresh.
- **Refusals and the environment:** usage's service-environment paragraph (it still said `WIRES_HOME` is passed) and its revocation text ("in the host's log") are fixed: a non-member's refusal is traced, not logged.
- **Checks:** `cargo test --workspace`, clippy `-D warnings` and `fmt --check` are green.

### Integrator review (2026-09-24) → done

An independent reviewer checked c8ef536: every in-scope finding in §1–§6, §8–§10 is fixed with a named test, and no regression against the premise was found. Its follow-ups were built in lane L6 (419818b):
- state sync reads as bytes arrive, only an offer can be large (4 KiB otherwise), 16 exchanges at a time, membership before signature verification, strangers hear only "not admitted";
- the record stream's `Open` is capped at 64 KiB with 16 undecided readers;
- the inbox receiver gives strangers the fixed refusal text;
- the child push socket lives in a private runtime directory, not the keystore;
- `host.json` `end_of_options` inserts `--` before the caller's arguments (§10).

Carried forward, by design:
- `Invoke` is still sent with `Hello`, and the in-memory high-water mark is lost on restart (card 29);
- push by principal and all of §7 (card 31);
- a same-user service can still read the host keystore at its default path ([card 32](../backlog/32-service-sandbox-OPEN.md)).

