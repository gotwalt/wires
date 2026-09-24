# 29 — Identity and scale: badges, day-passes, per-caller views

**Lane:** I2 · **Depends on:** 28 · **Status:** design agreed 2026-09-23; build after 28 · **Files:** `library/membership/`, `library/services/`, `wires/state/`, `wires/admin/`, `wires/caller/`, `wires/host/`, protocol.md

## Why (the human, 2026-09-23)

Two problems, one cause: **every member holds the whole signed state, and the
whole state moves on every change.**

- **Privacy.** Every agent's machine holds every member's node id, every role's matchers (which are often people's emails) and every service. Under the premise, agents must not observe each other; the org chart counts.
- **Bandwidth.** Every `invite` is a state edit, and every host gets the whole state again. Adding N people one at a time sends about N × hosts × (a state that grows with N). That is roughly 1.4 TB to onboard 10k people onto 200 hosts. The 4 MiB frame cap is a hidden ceiling of about 50k members. A pull when nothing has changed asks every host in turn until 8 s run out, so the hosts' refresh loops cost H² dials every 10 minutes.

"That quadratic org chart is crazy. Let's do per-member views." And: "we
should not reinvent the wheel." Each part below names the system it copies.

## The model, in plain words

Every call carries two things:

1. **A badge for the machine.** The admin signs it: "this key is in our fabric, until <date>". Hosts and agents both have one; it is today's `Membership`.
2. **An ID card for the person.** Google or Okta signs it: "this is alice@acme.com". It is stamped with the machine's key, so it's useless on another machine. It is today's nonce-bound ID token, or the day-pass below.

A host admits a call when the badge verifies and isn't banned, the person is
verified, and the rule book lets that person use that service.

## Parts and their precedents

### Machines: badges plus a banned list (Nebula, SSH CAs)

- Members leave the state. A host admits by the badge's signature; it needs no guest list.
- Removal is a **banned list** in the state: node ids whose badge hasn't expired yet. An entry drops out when its badge would have expired, so the list stays small.
- `invite` no longer edits the state, so onboarding costs zero pushes. The state holds roles, services and recent bans: it grows with services, not people.
- **Replaces the board non-negotiable** "removal by omission; no revocation list". The property it protected is kept: removal still works offline and needs no auth server. Update the board.

### People: IdP tokens, `login --for`, and later a day-pass (Teleport, Smallstep, `gcloud --no-browser`)

- **Stage 1 (laptops, now):** as today. `wires login` in a browser gives a token lasting about an hour. Google's refresh drops the nonce (`login.rs:97`), so the person signs in again roughly hourly. Disabling someone at the IdP cuts them off within the hour with no wires action.
- **Stage 2 (headless agents acting for a person):**
  - `wires login --for <node-id>`: sign in on the laptop, and the token is stamped with the *server's* key. Copy it over. It is safe to copy because it's useless without that key.
  - Then a **day-pass**, so this isn't hourly. A host the admin designates as an **issuer** (the admin signs "this host may issue day-passes") checks a fresh IdP token once and returns: "key K acts for alice@acme.com (issuer, subject, email, groups) until <time>". Every other host checks the day-pass offline, like a badge.
  - The trade-off is written down: a disabled person's agents keep working until the day-pass expires. The admin sets its length.
- **Stage 3 (later: jobs that act for nobody):** GitHub Actions, GCP service accounts and Kubernetes issue OIDC tokens to jobs. They can't carry our nonce, but they let the job choose the audience. Accept a key binding through `aud = "wires:<node id>"` as well as through the nonce. Leave room for this in the design; don't build it yet.

### IdP facts that constrain the design

- **Google ID tokens have no groups claim**; `hd` is the Workspace domain. With Google, roles are email lists or `*@domain`. Okta can add a `groups` claim.
- **Every org registers an OAuth client** with Google or Okta. Put the issuer, the client id and the accepted audiences in the admin-signed state, so hosts and agents get them without `host.json` or environment variables.
- **Every matcher names its issuer**, as Kubernetes and Tailscale do. Done in card 28.

### The rule book: grants and per-caller views (Tailscale ACL grants and netmap, Kubernetes RBAC and `SelfSubjectRulesReview`)

- Keep today's shape. It already is RBAC over OIDC claims: a role is a group of matchers, `service.allow` is a grant, and `readers` is a grant to read. Adopt Tailscale's and Kubernetes' vocabulary in the docs.
- The admin signs **each service entry separately**, with the state version. Hosts hold all of them plus the roles; that set grows with services, not people.
- **A caller gets only its own entries.** It presents its token (or day-pass) to any host, and the host returns the admin-signed entries its verified person may call or read. The caller checks each root signature itself. `wires services` shows a local cache of the last view and refreshes it from a host when stale.
- Callers never hold role matchers, other people's services or the member set.
- The first host to ask: the invite names a few hosts, chosen by the admin, as starting points.
- Not now: a policy language (Cedar, OPA). Adopt one only when rules need more than claims → roles → services, e.g. time of day, argv constraints or per-host conditions.

### Moving the state (the fix for the fan-out)

- The admin pushes the state (roles, entries, bans) **to hosts only**; callers pull their view.
- A pull stops at the first peer that confirms the caller is current. It asks the hosts of its own services, not every host.
- The state has an explicit size limit, reported when an edit would cross it, instead of the silent frame cap.

### Records: transparency-log checkpoints (Certificate Transparency RFC 9162; C2SP `tlog-checkpoint`/`tlog-witness`; Sigstore Rekor)

- Replace the hash chain with a Merkle log. The host signs a **checkpoint** (tree size plus root hash); a reader asks for a **consistency proof** from the checkpoint it holds.
- That fixes, by construction, what card 28 only patches:
  - rollback below a reader's mark;
  - pruning that looks like tampering;
  - marks kept per query.
- It also turns card 09's witness into the standard `tlog-witness` protocol.
- Non-readers get nothing about other people's calls: no hidden links, so no count and no timing. They get their own entries with inclusion proofs.

### Push from a service

- The per-call capability from card 28 stays. It is an attenuated capability in the Macaroons/Biscuit sense; a random per-call token checked by the socket is enough for now, so no Biscuit.

## Open questions

- How long is a day-pass, and who is allowed to issue them (every host, or ones the admin names)?
- Does Okta keep the nonce on refresh? If it does, Okta users on laptops don't need a day-pass. Test it.
- A headless agent's first login: `login --for` plus a copy is enough for stage 2. Is a device-code flow worth it? A device code can't carry our nonce, so the day-pass issuer would have to bind it.
- Does the gateway (`aaron/web-gateway`) present day-passes or raw tokens? Raw tokens for now; its sessions are about an hour either way.

## Acceptance (to refine when the card starts)

- [ ] Onboarding 10k members sends no state to hosts; the state's size is independent of member count (test).
- [ ] A caller's keystore holds no other member's id and no role matcher (test).
- [ ] A banned node is refused on its next call at every host that holds the ban; a ban drops out when the badge expires.
- [ ] A headless node, given `login --for`, then a day-pass, calls for 24 h with no browser.
- [ ] `watch` detects a rollback and reports pruning as retention, not tampering, from checkpoints.
- [ ] protocol.md rewritten; README/usage pass the rebuttal test.

## Notes
