# 05 — `serve --require-idp`: gate calls on verified identity

**Lane:** F · **Depends on:** 01, 02, 04 · **Files:** `wires/transport.rs` (authorize), `wires/audit.rs`, `wires/main.rs` (serve args)

## Goal

The responder only runs a tool for callers whose node key is bound to an
acceptable IdP identity — and the audit record names the person, not the key.
Two IdPs on one channel = federation.

## Design

- The responder's topic node (from card 02) keeps an in-memory index
  `NodeId → latest verified Principal`, fed by every `ChannelRecord::Identity`
  on the audit topic (verify on ingest with card 04's `verify_claim`; drop failures
  with a log line).
- `--require-idp 'iss=https://accounts.google.com,email=*@example.com'`
  (repeatable = OR; within one flag, all keys must match). Keys: `iss`, `email`
  (glob on `*@domain` only), `org`, `group`. `--oidc-audience` lists accepted `aud`s.
- In `authorize`: after the roster/grant checks pass, look up the caller. No claim →
  `Denied("no identity claim for <node>; run \`wires login --topic <t>\`")`; expired →
  `Denied("identity claim expired …")`; mismatch → `Denied("identity <email> not allowed …")`.
- `AuditRecord::Started.principal` is filled from the index whenever one exists
  (even without `--require-idp`), so the observer sees names.
- Claims can arrive *after* a caller first dials; the lookup is per call, so the
  next call succeeds once the claim lands — no restart.

## Acceptance

- [x] Unit: policy parser + matcher (proptest over emails/globs), each denial reason.
- [x] e2e (mock issuer): caller without claim denied → logs in → next call allowed; audit
      `Started.principal.email` set; second mock issuer with a different domain allowed by
      a second `--require-idp` (federation) and a third denied.
- [x] `bazel test //...`, `aspect lint //...`, format check green.

## Notes

**Worker, 2026-09-22.** Branch `worktree-agent-a88e6eb27313ac408`.

### Operator: require Google identities

```sh
wires serve --trust-root <root> --audit-topic ops \
  --require-idp 'iss=https://accounts.google.com,email=*@example.com' \
  --oidc-audience '<id>.apps.googleusercontent.com' \
  --expose 'db_query=sqlite3 -safe -readonly orders.db'
# callers, once per ~1 h token:  wires login --topic ops
# observers:                     WIRES_OIDC_AUDIENCE='<id>.apps.googleusercontent.com' wires tail ops
```

- `--require-idp RULE` (repeatable = OR; `requires` `--audit-topic`, since claims arrive there).
  Keys `iss` (exact), `email` (exact or `*@domain`, ASCII case-insensitive, no sub-domains),
  `org` (Google `hd`, case-insensitive), `group` (repeatable, all needed). Unknown keys, empty
  values, a repeated `iss`/`email`/`org`, and any other `*` are startup errors.
- `--oidc-audience` (repeatable/csv) else `$WIRES_OIDC_AUDIENCE` else `$WIRES_OIDC_CLIENT_ID`;
  `--require-idp` with no audience refuses to start. `--oidc-issuer` (repeatable/csv) else
  `$WIRES_OIDC_ISSUER` else Google; every rule's `iss` is trusted in addition. A rule without
  `iss` accepts any trusted issuer.

### What was built

- `wires/idp_policy.rs` — `IdpRule` (`FromStr`/`Display`), `IdpPolicy` (OR of rules), pure.
- `wires/identity.rs` — `Identities`, the `NodeId → latest verified Principal` index, and
  `IdentityGate` (index + policy + topic name) in `ServeConfig.identity`. `authorize` calls
  `gate.admit(caller, now)` **last**, after roster/grant, and now returns
  `Admitted { roster_version, principal }`; `CallAudit::start` takes the principal.
- Denials (sent to the caller and recorded as `Denied`, byte-identical):
  `no identity claim for <node8>; run \`wires login --topic ops\``,
  `no verified identity claim for <node8> (<why>); run …`,
  `identity claim expired for <email> (at <exp>); run …`,
  `identity <email> (from <iss>) not allowed by this responder's --require-idp policy`.
- `Started.principal` is filled whenever the index holds a **fresh** principal, with or without
  `--require-idp` (an expired one is not stamped: the record says who was verified at call time).
- **`wires tail` shows verified identities** (card 04's leftover): `Printer::emit` is now async;
  for an identity claim it calls `Identities::observe` (verify + index) and `render::identity_line`
  prints `🪪 identity 3f2a1b9c is alice@example.com (verified by https://accounts.google.com)` /
  `(expired)` / `UNVERIFIED: <reason>` via `idp_view::describe_identity`. A plain tail trusts
  `IdpTrust::from_env()`; `serve`'s own tail loop shares the gate's index. `--json` skips
  verification. The dead-code allow in `idp_view.rs` is gone (`render_identity` is now
  `#[cfg(test)]`; `name` → `pub(crate) principal_name`). `▶` lines already showed
  `principal.email` via `caller_label` — verified, and now asserted end to end.

### Decisions / deviations

- **A claim counts only from the node it names** (`envelope.sender == claim.node`, new
  `VerifyError::WrongSender`). The nonce binds a token to a *public* node id, so anyone can sign in
  with `nonce = for_node(victim)` and publish "victim is me"; only the key holder can put a claim on
  its own chain. Card 04's observer path had this gap — it is closed for the tail too.
- Index update rule: a verified principal (fresh or expired) replaces the held one iff its `exp`
  is ≥ the held `exp` (re-login wins, replaying an old token can't roll back). Failures never
  displace a verified principal (anyone can publish garbage for any node); the latest failure is
  kept only to explain a refusal when nothing verified.
- Verification is inline in the tail loop (first claim from an issuer = one JWKS fetch, ≤15 s,
  then cached) — ordering of printed lines is preserved. A responder also **primes** the index from
  the whole topic log at startup (`serve` prints no backfill but must know earlier logins).
- Claims that land after a refusal admit the next call: the lookup is per call.
- Off-lane touches: `wires/main.rs` (mods, 3 serve flags, `serve_identities`, `Printer` field +
  async `emit`/`print_new_since`, `run_tail` identity setup — no logging/socket changes);
  `wires/e2e.rs` (`identity: None` + `Printer` literals only); `wires/jwks.rs` (`WrongSender`).
- Tests: `idp_policy` 4 unit + 4 proptests, `identity` 5, `idp_view` +1, `render` +1 (verdict
  lines, hostile email), `audit` principal assertion, e2e
  `require_idp_admits_verified_federated_identities_only` (no claim → denied; login → next call
  runs with `Started.principal`; partner IdP allowed by a 2nd rule; 3rd trusted IdP refused by
  name; every refusal on the channel). After merging `aaron/remote-cli` (card 10; one import
  conflict in `wires/audit.rs`): library 253 + 45 doctests, wires 302, all green; clippy clean
  (`bazel build --config=lint`, exit 0), format check green. The
  `every_call_and_refusal_lands_on_the_audit_topic` flake was not seen in my runs.
- The e2e relays each caller's claim through the observer's mesh (sealed on the caller's own
  chain), so callers need no resident node of their own.
