# 29 — Person identity for headless agents: `login --for`, day-passes

**Lane:** I2 · **Depends on:** [36](../doing/36-directory.md) · **Status:** backlog; design agreed 2026-09-23, reshaped 2026-09-24 · **Files:** `library/idp/`, `library/membership/` (day-pass), `wires/caller/login.rs`, `wires/directory/` (issuing), `wires/host/{gate,identity}.rs`, protocol.md §6

**Reshaped 2026-09-24.** This card was "identity and scale". Its scale half (badges and bans,
per-caller views, moving the state) is now cards [35](../done/35-badges-and-bans.md),
[36](../doing/36-directory.md) and [37](37-caller-views.md), built around a directory; its records half
(transparency-log checkpoints) is now [card 09](09-witness.md). What's left is how a *person* is
proven when no browser is at hand.

## Why (the human, 2026-09-23)

A call admits a machine by its badge and a person by an IdP-signed ID token bound to the machine's
key. Google tokens last about an hour, and Google's refresh drops the nonce
(`LoginArgs::refresh` in `caller/login.rs`), so a person signs in again roughly hourly. That's fine
on a laptop and unworkable for a headless agent acting for someone. "We should not reinvent the
wheel": each part below names the system it copies.

## Stages (Teleport, Smallstep, `gcloud --no-browser`)

- **Stage 1 (laptops, now):** as today. Disabling someone at the IdP cuts them off within the hour
  with no wires action.
- **Stage 2 (headless agents acting for a person):**
  - `wires login --for <node-id>`: sign in on the laptop, and the token is bound to the *server's*
    key. Copy it over; it is useless without that key.
  - Then a **day-pass**, so this isn't hourly. A **directory** (card 36; the root-signed head
    already names it) checks a fresh IdP token once and signs: "key K acts for alice@acme.com
    (issuer, subject, email, groups) until <time>". Hosts check a day-pass offline, like a badge.
  - The trade-off is written down: a disabled person's agents keep working until the day-pass
    expires. The admin sets its length in the policy's `settings`.
- **Stage 3 (later: jobs that act for nobody):** GitHub Actions, GCP service accounts and
  Kubernetes issue OIDC tokens to jobs. They can't carry our nonce, but they let the job choose the
  audience. Accept a key binding through `aud = "wires:<node id>"` as well as through the nonce.
  Leave room for this; don't build it yet.

## IdP facts that constrain the design

- **Google ID tokens have no groups claim**; `hd` is the Workspace domain. With Google, roles are
  email lists or `*@domain`. Okta can add a `groups` claim. Email-list roles grow the policy with
  the number of people ([`bench/state-scale/REPORT.md`](../../../bench/state-scale/REPORT.md)):
  after card 36 that growth stays on the directory and in host slices, not on callers.
- **Issuers are signed policy** (card 36's `issuer` items), so hosts, directories and callers get
  them without `host.json` or environment variables.
- **Every matcher names its issuer**, as Kubernetes and Tailscale do. Done in card 28.

## Open questions

- How long is a day-pass by default?
- Does Okta keep the nonce on refresh? If it does, Okta users on laptops don't need a day-pass.
  Test it.
- A headless agent's first login: `login --for` plus a copy is enough for stage 2. Is a
  device-code flow worth it? A device code can't carry our nonce, so the day-pass issuer would
  have to bind it.
- Does the gateway present day-passes or raw tokens? Raw tokens for now; its sessions are about an
  hour either way.

## Acceptance (to refine when the card starts)

- [ ] A headless node, given `login --for`, then a day-pass, calls for 24 h with no browser.
- [ ] A host verifies a day-pass offline and refuses one from a key the head doesn't list in
      `directories`, or one past its `until`.
- [ ] protocol.md §6 describes day-passes; README/usage pass the rebuttal test.

## Notes
