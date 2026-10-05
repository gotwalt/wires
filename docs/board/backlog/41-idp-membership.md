# 41 — Signing in is joining: no badges, no invites

**Stage:** 2 · **Depends on:** [40](40-cut-records.md), [42](42-caller-identity-for-services.md) (both merged first) · **Status:** backlog · **Files:** `library/membership/` (all of it), `library/calls/{session,idp,push}.rs`, `library/services/{item,signed_policy,access}.rs`, `library/directory/frames.rs`, `wires/admin/` (all of it), `wires/caller/{join,login,view,call,inbox,mcp,services,hello}.rs`, `wires/host/{gate,transport,serve,identity,push,embed}.rs`, `wires/directory/`, `wires/policy/`, `wires/gateway/`, `wires/lib.rs`, `wires/help.rs`, `wires/snapshots/`, `wires/testutil.rs`, `wires/e2e/`, `bindings/`, `.scripts/`, `bench/*/up.sh`, `bench/wires-up.sh`, `deploy/gateway/`, `docs/protocol.md` §2–7 and §9

## Why (the human, 2026-10-05)

"I find our notion of badges really confusing. I'd rather just have a
clearer idp-sourced auth token." And: "users of wires should not need to
know the public key of the service they're calling."

A caller carries two credentials today: a badge the admin minted for the
machine and an ID token for the person. The badge is why joining is a
hand-issued invite per machine, why every node expires after 30 days with no
renewal, why the admin keeps a ledger, why removal is a ban sized to a badge's
remaining life, and why the quick tour invites the same machine twice. Every
role already needs a verified identity, so the IdP sign-in can be the whole of
membership.

## Decisions

### What admits whom

- **A caller** is admitted by an ID token from an issuer the signed policy
  trusts, bound to its node key (the `nonce`), unexpired, and not removed
  (below). `Hello` carries the token and no membership; a `Hello` without a
  token that verifies is refused at that first message, before anything
  runs. Keep the pre-auth permit pool and the stranger throttle: any key can
  still connect, and now costs the host one token check.
- **A host** is trusted by a caller because its key is in the root-signed
  entry of the service being called, and iroh authenticated that key.
  `HelloAck` carries no membership.
- **A directory** is one the head's `directories` lists. It serves the whole
  policy only to a key the policy names as a host or directory (as today,
  by key), a view only for a verified ID token (as today), and takes a
  publish only if it verifies under the root.
- **No node holds a credential the admin minted for it.** `Membership`,
  `check_inclusion`, the badge half of `check_admitted`, `membership.json`,
  `--ttl`, the 30-day lifetime, and `--membership[-file]` all go.

### Joining

- **The network string** is everything a new node needs: the root key, up to
  two directory ids, and the sign-in settings (`LoginSettings`, as the invite
  carried them). Base64url of canonical JSON, with a format discriminant.
  It is unsigned (it introduces the root: trust on first use, as the invite
  was), the same for every node, and not secret: it can sit in a wiki.
  `wires network` prints it (the admin after `init`; any joined node too).
- **`wires login <network>`** joins and signs in, in one command: the
  caller's whole onboarding. A later sign-in is a bare `wires login`.
- **`wires join <network>`** installs the network string without signing
  anyone in: what a host or a directory runs (they act for no person).
- **`wires invite` and the ledger (`issued.json`) go.** No token carries a
  policy. A host fetches its first policy from a directory (it is named by
  key). The first directory starts empty and takes the admin's first
  publish: `wires policy push`, or the next edit. That is the one bootstrap
  step; both sides must say so plainly (the directory: what it is waiting
  for; the admin's earlier edits: that the policy is stored and what will
  deliver it). No command in the first run fails by design, and none is run
  twice.
- **Labels for nodes** stay, admin-local, so the admin types a node id once:
  `label=<node-id>` wherever a node is first named (`wires directory add
  workbench=3ef7…`, `--host workbench=3ef7…`), the bare label afterwards.
  Kept in a file in the admin's keystore; not in the policy.

### Removal

- **`wires remove <who>`**, where `<who>` is a person or a node:
  - an email (issuer from `--issuer`, default as for roles): a **person
    ban**. Every host refuses that person from any machine, and every
    directory gives them an empty view.
  - a node id or label: a **node ban**, and the node is dropped from every
    service's hosts and from the directories, as today.
- **`wires restore <who>`** lifts either.
- A ban has no `until`: there is no badge whose expiry it could borrow. It
  holds until restored.
- Checked where the badge-and-ban check was: the session gate, the
  directory (views, `resolve`, whole-policy requests), push at send,
  delivery and fetch, and the gateway.
- Disabling someone at the IdP still cuts them off within one token
  lifetime, with no wires action.

### The first run this must produce

```console
admin$     wires init --client-id <id>
admin$     wires role set analyst '*@acme.com'
admin$     wires directory add workbench=<node id from `wires id` on the workbench>
admin$     wires service add orders-db --description "…" --allow analyst --host workbench
admin$     wires network                      # one string, for everyone
workbench$ wires join <network>
workbench$ wires serve host.json              # also the directory; waits for the first publish
admin$     wires policy push
agent$     wires login <network>
agent$     wires services
agent$     wires call orders-db -- "select count(*) from orders"
```

`wires/e2e/first_run.rs` and `.scripts/demo-remote-cli.sh` run exactly this
shape.

## What this gives up (protocol.md §10, and *Notes* for card 39)

- **The admin no longer approves each machine.** Anyone the IdP verifies
  under the trusted client, and a role matches, is in from any machine. A
  sign-in phished into binding an attacker's key would be admitted; with
  badges that key would also have needed an invite.
- **A stranger costs a token check**, not a signature check on a badge.
- **The ID token is the only credential**, so Google's hourly re-login
  (it drops the `nonce` on refresh) is felt on every caller. A longer-lived
  credential, when it comes ([card 29](29-person-identity.md)), must be
  something `wires login` hands over, never a separate step.
- **Node bans don't expire.**

## Do, in this order

1. `docs/protocol.md` first: §2 becomes "Admission"; §3's invite, admin
   surface, bans and versioning; §4's directory hello and bootstrap; §5's
   `Hello` / `HelloAck`; §6; §7's push admission; §9's keystore table; §10.
   New signed and wire formats get new discriminants (§1).
2. Types and signatures, tests red, implement, doctests, readability pass
   (CLAUDE.md order). New e2e coverage, at least: no token → refused at the
   first message; a token bound to another key → refused; a removed person →
   refused from a second machine too, within seconds of the publish; a
   removed node; `restore`; the first run above from empty keystores; a
   directory that starts empty and takes the first publish; the gateway
   calling for a web user with no badge of its own.
3. Help text, snapshots, error messages (every "badge", "invite",
   "membership", "not a member of this network" needs a decision: the
   refusal a caller with no valid sign-in hears should say to run
   `wires login`).
4. Everything that provisions a network: `wires/testutil.rs`, the three demo
   scripts and `lib.sh`, `bench/wires-up.sh`, `bench/push/up.sh`,
   `bench/help/up.sh` (the first two are already broken against `main`:
   they `init` and `serve` from one keystore), `deploy/gateway/` (compose
   comments, `.env.example`), the bindings' examples.
5. Grep for what's left: `badge`, `Membership`, `membership`, `invite`,
   `Invite`, `ledger`, `issued.json`, `--ttl`, `not a member`, `banned
   until`, `re-invite`, `join <token>`, `30 days`, `30d`. Fix code, comments
   and help in your lane; list hits in the narrative docs in *Notes*.

## Acceptance

- [ ] `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, shellcheck and shfmt (via `uvx`) green.
- [ ] `.scripts/demo-remote-cli.sh --quiet` and `.scripts/demo-push.sh --quiet` pass; the native-service demos pass or *Notes* says why they couldn't run here.
- [ ] `library/membership/membership.rs` and the invite token are gone; no frame carries a membership; no keystore holds `membership.json` or `issued.json`.
- [ ] The first run above works verbatim from empty keystores, with no step repeated and none exiting non-zero.
- [ ] `docs/protocol.md` describes exactly what the code does, including what was given up.
- [ ] *Notes* lists every statement in the narrative docs this card made false, and every decision taken that this card left open.

## Notes
