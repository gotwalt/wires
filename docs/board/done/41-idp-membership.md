# 41 — Signing in is joining: no badges, no invites

**Stage:** 2 · **Depends on:** [40](40-cut-records.md), [42](42-caller-identity-for-services.md) (both merged) · **Status:** done (merged into `simplify` 2026-10-05; hardened by [card 47](47-admission-hardening.md)) · **Files:** `library/membership/` (all of it), `library/calls/{session,idp,push}.rs`, `library/services/{item,signed_policy,access}.rs`, `library/directory/frames.rs`, `wires/admin/` (all of it), `wires/caller/{join,login,view,call,inbox,mcp,services,hello}.rs`, `wires/host/{gate,transport,serve,identity,push,embed}.rs`, `wires/directory/`, `wires/policy/`, `wires/gateway/`, `wires/lib.rs`, `wires/help.rs`, `wires/snapshots/`, `wires/testutil.rs`, `wires/e2e/`, `bindings/`, `.scripts/`, `bench/*/up.sh`, `bench/wires-up.sh`, `deploy/gateway/`, `docs/protocol.md` §2–9

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

## What this gives up (protocol.md §9, and *Notes* for card 39)

- **The admin no longer approves each machine.** Anyone the IdP verifies
  under the trusted client, and a role matches, is in from any machine. A
  sign-in phished into binding an attacker's key would be admitted; with
  badges that key would also have needed an invite.
- **A stranger costs a token check**, not a signature check on a badge.
- **The ID token is the only credential**, so Google's hourly re-login
  (it drops the `nonce` on refresh) is felt on every caller. A longer-lived
  credential, when it comes ([card 29](../backlog/29-person-identity.md)), must be
  something `wires login` hands over, never a separate step.
- **Node bans don't expire.**

## Do, in this order

1. `docs/protocol.md` first: §2 becomes "Admission"; §3's invite, admin
   surface, bans and versioning; §4's directory hello and bootstrap; §5's
   `Hello` / `HelloAck`; §6; §7's push admission; §8's keystore table; §9
   (card 40 renumbered: Keystore is §8, Known limits §9).
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

- [x] `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, shellcheck and shfmt (via `uvx`) green.
- [x] `.scripts/demo-remote-cli.sh --quiet` and `.scripts/demo-push.sh --quiet` pass; the native-service demos pass or *Notes* says why they couldn't run here.
- [x] `library/membership/membership.rs` and the invite token are gone; no frame carries a membership; no keystore holds `membership.json` or `issued.json`.
- [x] The first run above works verbatim from empty keystores, with no step repeated and none exiting non-zero.
- [x] `docs/protocol.md` describes exactly what the code does, including what was given up.
- [x] *Notes* lists every statement in the narrative docs this card made false, and every decision taken that this card left open.

## Notes

### What changed (worker, 2026-10-05)

- **library:** `membership.rs`, `invite.rs` and `check_inclusion` are gone;
  the `membership/` folder is now `network/` with `identity.rs`,
  `network.rs` (`Network { format: 1, root, directories ≤ 2, login }`, the
  network string; `LoginSettings` and `PublicClientSecret` moved here) and
  `admission.rs` (`check_admitted(policy, caller, principal)`: `Banned`
  when the policy bans the node or the person). Bans: `Item::Ban { key }`
  (no body, no `until`) and a new `Item::PersonBan { key: Person { issuer,
  email } }`; `Policy::{bans: BTreeSet<NodeId>, person_bans}`,
  `ban/unban/ban_person/unban_person/bans_person`; `prune_bans`,
  `is_banned` and `Ban` are gone. Head format 4 (`POLICY_V4`). Validation
  also refuses a banned directory and a malformed person ban.
  `SignedPolicy::view_for(node, principal, query)` cuts the empty view for
  a banned node or person; `authorize` refuses a banned person too.
  Session `Hello` is tag 10 with a required `id_token`; `HelloAck` is tag
  11 and carries no credential (tags 8/9 are `BadFrame`). Inbox ALPN
  `wires/inbox/3`, `hello {id_token?}`. Directory ALPNs `wires/directory/2`
  and `wires/directory-sub/2`, `hello {id_token?}`; a publish is `publish
  {head}` then `items {items}`; `published {version, head: HeadHash}`; the
  `head {}` request and answer and `PUBLISH_BODY_PREFIX` are gone.
- **admin:** `invite.rs` and `ledger.rs` (`issued.json`) are gone; new
  `network.rs` (`wires network`), `remove.rs` (`wires remove <email|node>`,
  `wires restore <email|node>`), `labels.rs` (`labels.json`,
  `label=<id>`). `init` mints nothing and takes no `--ttl`
  (`Ttl::MAX_BADGE`/`badge()` gone; `Ttl::default()` is now the policy
  default). `--host` and `directory add` take a node id, a label or
  `label=<id>`; neither needs the node known first. `issuer rm` is refused
  while a person ban names the issuer. The first-run publish note says to
  `wires policy push` once a directory runs. `Keystore::{read_network,
  save_network, network_root}` replace the membership resolver and
  `preflight`.
- **caller:** `wires login [<network>]` joins first when given the string;
  `wires join <network>` installs `network.json` (refusing another
  network's and the admin's keystore, making the node key if missing) and
  contacts nobody. `directories.json` and `login.json` are gone (both come
  from `network.json`). `Credentials` holds the root, not a badge, and
  refuses to dial with no ID token (`not signed in: run \`wires login\``);
  `--membership`/`--membership-file`/`WIRES_MEMBERSHIP` are gone (and from
  locked mode's lists). `wires call` refreshes a view that is stale (older
  than a day, or a host reported a newer head) before dialing, falling back
  to the held view when no directory answers. `wires inbox` needs a stored
  token. The inbox receiver admits a deliverer only by its being a host in
  the view.
- **host:** `ServicesHost` holds no membership; `admit_caller` (token
  verified under the policy's issuers as `host.json` narrows them, then
  `check_admitted`) is admission for sessions and inbox fetches;
  `admit`/`decide` take a `&Verified` (no `missing`, no `needs_identity`).
  New refusals: `NOT_ADMITTED` = ``not admitted to this network; sign in
  with `wires login` ``, `SIGN_IN_EXPIRED`; `TOKEN_UNVERIFIED` is gone.
  `Identities::record` no longer indexes a node whose token failed.
  `decide_push`/`push_recipients` honour person bans. `serve` runs the
  directory when the held policy, or (holding none) the network string,
  lists the node, serves at once and waits for a policy that passes the
  preflight (`await_assigned`); a host that runs no directory still fetches
  at start and fails with a clear cause. The embedded `Host` reads
  `network.json`.
- **directory:** `Directory::admit` → `Peer { named, principal }`;
  `check_head` / `publish` split a publish so only a root-signed newer head
  makes it read the items; `answer(&Peer, request)` replaces
  `answer`/`answer_caller`; an empty directory answers everything but a
  publish (and every subscription) with `EMPTY`; `holds_whole` excludes
  banned nodes; the view subscription takes the principal verified at the
  hello and empties on a ban instead of ending; the replica and policy
  loops present no credential.
- **gateway:** joins with the network string (`Credentials::resolve` reads
  the root from `network.json`); nothing else changed.
- **bindings:** doc lines and one test message.
- **scripts and the rest:** all three demos, `lib.sh` (`login_as …
  [network]`), the three bench `up.sh` scripts (all three now provision a
  working network: `help/up.sh` ran end to end with calls; `wires-up.sh`
  and `push/up.sh` ran end to end against the mock IdP standing in for
  Google, with curl as the browser, and a `gh` call / the `services` check
  answered), `bench/permission-probe.py` (dropped the two `--membership`
  probes; outside the lane, minimal), `deploy/gateway/compose.yml`
  comments, CLAUDE.md's architecture section.

### Decisions this card left open

- **Session discriminants:** new frame tags (10, 11) on the unchanged ALPN
  `wires/session/1`; the inbox and directory protocols got new ALPNs.
- **Publish authentication:** the admin publishes as a stranger (its node
  is named nowhere). To keep a stranger from making a directory read a
  16 MiB body, a publish is two frames and the items are read only after
  the head verified under the root, is fresh and newer; the publisher then
  takes an admitted slot. `published` carries the head hash, so the admin's
  stale-copy check needs no `head {}` request (removed).
- **Directory admission:** a named node (host or directory, not banned) or
  a verified token; everyone else may only publish. A banned person (or a
  banned node presenting a token) is admitted and cut an **empty view**, as
  the card says; whole-policy requests and subscriptions refuse banned
  nodes.
- **Refusal texts:** one `NOT_ADMITTED` for every admission failure (no
  token, forged, another key's, untrusted issuer, banned node or person),
  so a ban is not told apart from no sign-in; an expired-but-genuine token
  hears ``your sign-in has expired; run `wires login` ``; an unreachable IdP
  keeps its own text. All are stranger refusals (throttled trace, no call
  line).
- **Person ban matching:** issuer exact, verified email ignoring ASCII
  case, stored lowercase; a token without a verified email matches no
  person ban. `remove` and `role set` default `--issuer` to the network
  string's issuer (the login issuer), not hard-coded Google, which makes
  the card's first run verbatim with any IdP; with Google as the login
  issuer it is the same. `remove <email>` naming an untrusted issuer is
  refused.
- **Restore** lifts the ban only: a restored node is not put back into
  services or directories. Removing someone already removed, and restoring
  someone not removed, are refused.
- **Labels:** 1–64 of `[A-Za-z0-9_.-]`, not a node id, no `@`; rebinding a
  label to another node is refused; labels survive `remove` (for
  `restore`).
- **`wires join`** takes the string as a required argument (no bare-join
  id printing; `wires id` does that) and refuses the admin's keystore.
- **`wires network`** on the admin is computed each time from the policy
  and `login-client.json`; with no directory it prints and warns on
  stderr; it fails when the policy trusts no IdP.
- **`wires services`** for a node that never signed in: the directory
  refuses it, so the command errors with the directory's ``not admitted…
  sign in with `wires login` `` (not an empty list).
- **A host that runs no directory and holds no policy** fetches for 8 s at
  start and exits if none answers (it does not wait); a host that runs the
  directory waits for the first publish.
- **The known `HelloAck::assigns` mismatch:** not fixed in the frame;
  bounded instead by `wires call` refreshing views older than a day (§5
  and §9 say so). A removed host still receives a stale-view caller's ID
  token and argv (and stdin if it understates its version) until then.
- **No compatibility** (the owner's instruction): old keystores
  (`membership.json`, `issued.json`, `directories.json`, `login.json`,
  format-3 `policy.json`/`view.json`) are not read; nothing migrates.

### What this gives up (also in protocol.md §9)

As the card lists: the admin no longer approves each machine (a phished
sign-in binding an attacker's key is admitted); a stranger costs a token
check (keys fetched only for trusted issuers, unknown-kid refetch rate
limited); the ID token is the only credential (Google's hourly re-login on
every caller); bans don't expire and accumulate until restored. Beyond the
card: the removed-host window is now bounded by the caller's view age (a
day) rather than a badge's life (30 days); any key can make a directory
check one publish head's signature.

### Narrative-doc statements this card made false (for cards 39/43)

Every line below names badges, invites, `wires join <token>`, the ledger,
`--ttl`, 30-day memberships, `not a member of this network`, node-only
removal (`wires remove agent`), `directories.json`/`login.json`/
`membership.json`, `head {}`, `wires/directory/1`/`wires/inbox/2`, or a
directory that needs an invite carrying the policy:

- `README.md`: 36 (“accepts an invite”); § A quick tour 72–98 (78, 82
  `wires invite`, 85/89 `wires join <token>`, 90 “the invite named the
  IdP”); § Limits 163 (“Badges (30 days)”).
- `docs/usage.md`: § Roles 12, 18; § Where each guarantee lives 24, 28,
  34; § Walkthrough 52, 60, 79–104, 147–154, 188, 251–255, 290–291; § Why
  it's built this way 422, 429; § Giving an agent only `wires` 489; § Known
  trade-offs 509, 524–537; § Not yet 569, 576; § Commands by role 601–628,
  641; § host.json 670, 675; § The keystore 689–700; § Removal 702–711;
  § Reachability / Layout 727–728.
- `docs/fabric.md`: § 1 3, 14, 19, 22; § 2 38–40; § 3 58, 69; § 4 80–83,
  90–91, 107–108, 119–121; § 5 136–149; § 6 181–198; § 7 217–218 (ALPN
  versions); § 8 231; § 9 250–261.
- `docs/deployment.md`: § What you deploy 16, 19; § Running a host 41, 53;
  § Keystore and secrets 88; § Running a directory 132–156 (the invite
  that carries the policy); § Provisioning and removal 188–208; § A web
  gateway 255–287 (invite, badge, `join <token>`).
- `docs/demo.md`: § Cheat sheet 21, 40–41; § Cast 61; § Before recording
  74–128; §§ 2–3 173, 180; § 6 Revoke 304, 314.
- `docs/agent-sandbox.md`: § Locked caller mode 119, 133, 167, 191
  (`--membership[-file]`, `WIRES_MEMBERSHIP`).
- `docs/testing.md`: 18 (the first-run e2e described as invite/join).
- `docs/executive-summary.md`: § What Wires is 24, 26; § Why it's built
  this way 66; § Honest limits 72 (“a hand-issued invite”).
- `docs/blog/introducing-wires.md`: § How it works 17.
- `CLAUDE.md`: 19 and 33 (overview: “Until cards 40–42 merge, the code
  still has … badges”), 48 (“membership, …” in protocol.md's contents);
  its architecture section was updated here.
- `docs/board/README.md`: 13–15 (“Until card 41 merges, the code still has
  badges and invites”); the integrator's to edit.
- Outside the narrative docs and the lane: `bench/state-scale/model.py`
  (models badges and 30-day bans).

### Verified (2026-10-05, on this branch)

- `cargo test --workspace`: 144 library unit tests, 388 wires tests, 3
  bindings tests, 47 + 3 doctests, all green. `cargo clippy --workspace
  --all-targets -- -D warnings` and `cargo fmt --all --check`: clean.
  `uvx --from shellcheck-py shellcheck` and `uvx --from shfmt-py shfmt -d`
  over every tracked `*.sh` and `.githooks/pre-commit`: clean.
- `.scripts/demo-remote-cli.sh --quiet` (68 s) and `.scripts/demo-push.sh
  --quiet` (34 s): pass. `.scripts/demo-native-service.sh --lang python`
  and `--lang node`: pass.
- The first run: `wires/e2e/first_run.rs` runs the eleven commands from
  empty keystores (plus removal by person from a second machine within
  5 s, by node, and `restore`), and the same eleven commands were run by
  hand with the release binary against the stand-in IdP (so `init` adds
  `--issuer <mock> --public-client-secret …`): every one exit 0, none
  repeated.
- `bench/help/up.sh` end to end (and a call, and the 77 refusal);
  `bench/wires-up.sh` and `bench/push/up.sh` end to end with the stand-in
  IdP in place of Google (curl as the browser). No model was called.
- Not covered by a unit test: a push refused at send for a **person** ban
  (`decide_push`); demo-remote-cli's step 8 asserts it end to end.
