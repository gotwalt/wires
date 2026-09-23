# 13 — `host.json`: what's exposed, and who may call it

**Lane:** P · **Depends on:** 12 · **Files:** `wires/host/config.rs` (new), `wires/host/policy.rs` (replaces the flag-based `idp_policy`), serve args, audit `Started` (`role` field), docs

## Why

The host is the one place that decides **what** runs and **who** may run it. That
belongs in one readable file, not in six flags. The human wants room for org-grade
rules later ("roles, or even additional logic"): **don't build that now, but make
sure nothing we ship prevents it.**

## Shape (v1)

```json
{
  "version": 1,
  "channel": "ops",
  "identity": {
    "issuers": [
      { "issuer": "https://accounts.google.com",
        "audiences": ["476…apps.googleusercontent.com"] }
    ]
  },
  "roles": {
    "analyst": [ { "email": "*@example.com" }, { "email": "gotwalt@gmail.com" } ],
    "sre":     [ { "issuer": "https://acme.okta.com", "group": "sre" } ]
  },
  "tools": {
    "db_query": {
      "description": "Read-only SQL against the orders database",
      "command": ["sqlite3", "-safe", "-readonly", "orders.db"],
      "allow": ["analyst"]
    }
  }
}
```

- **Matchers** are AND-of-keys (`issuer`, `email` exact or `*@domain`, `org`, `group`); a role is OR-of-matchers. `allow` lists roles. Built-in role `"member"` means any roster member **without** an IdP requirement, and must be written out explicitly (never a default).
- **Default deny.** A tool with no `allow` refuses every call. Unknown keys are an **error** (`deny_unknown_fields`), so a future config is never silently misread by an older host. `version` is required.
- **Extension seams (don't implement, just leave room):**
  - one `trait Policy { fn decide(&self, &CallContext) -> Decision }`, where `CallContext` = verified principal (all claims kept, not just email), caller node, roster version, tool, argv. `Decision { allow, reason, role }`.
  - v1's matcher/role table is one implementation of it. A later `"policy": {"engine": …}` block (CEL, Rego, a webhook) would be another. Mention this in a doc comment plus the README, nothing more.
  - `Principal` keeps the raw verified claim set (for example `serde_json::Map`) so future rules can match any claim (Okta groups, Entra roles) without a wire change.
- `AuditRecord::Started` gains `role: Option<String>` (serde-default), and render shows it: `▶ 3fa2 alice@example.com [analyst] db_query "…"`. Denials say which rule failed.
- `wires serve host.json` is the only form. The flags `--expose`, `--expose-file`, `--require-idp`, `--oidc-*`, `--audit-topic`, `--allow-any-member` and `--trust-root` are removed (the trust root comes from the host's own membership). Keep `--relay-url` as an override.
- `wires serve --check host.json` validates and prints a summary: which roles may run which tools, and which issuers are trusted.

## Acceptance

- [x] Unit + proptest: parse/validate (unknown key, missing version, empty allow → deny), the matcher table, the decision reasons.
- [x] e2e: `analyst` allowed; an authenticated non-analyst denied, with the reason and the denial on the channel; `member` role works without IdP when written out explicitly.
- [x] `demo-remote-cli.sh` uses a `host.json` fixture; still green.
- [x] `bazel test //...`, lint, format check green.

## Notes

*2026-09-22, lane P (worker).* Commits: library (`Principal.claims`,
`Started.role`) → host (config + policy + serve) → demo → docs. The library
commit alone doesn't build `//wires` (new struct fields); the host commit
fixes every literal.

### The schema (v1)

```json
{
  "version": 1,                       // required, must be 1
  "channel": "ops",                   // optional; required as soon as `identity` or any role exists
  "identity": { "issuers": [          // optional
    { "issuer": "https://accounts.google.com",   // exact `iss`; listed once
      "audiences": ["<client id>"] }             // >= 1; accepted from THIS issuer only
  ] },
  "roles": {                          // optional; name = [A-Za-z0-9_.-]{1,64}, never "member"
    "analyst": [ { "email": "*@example.com" }, { "email": "gotwalt@gmail.com" } ],
    "sre":     [ { "issuer": "https://acme.okta.com", "group": "sre" } ]
  },                                  // matcher keys: issuer, email, org, group (>= 1 key; issuer must be in identity.issuers)
  "tools": {                          // >= 1
    "db_query": {
      "description": "Read-only SQL against the orders database",   // optional
      "command": ["sqlite3", "-safe", "-readonly", "orders.db"],     // non-empty argv, no shell
      "allow": ["analyst"]            // defined roles or "member"; missing/empty = nobody
    }
  }
}
```

`deny_unknown_fields` at every level (top, `identity`, issuer, matcher,
tool). Fixture: `.scripts/fixtures/host.json` (the demo seds in the mock
IdP's issuer/client id and runs serve with cwd = the state dir, so
`orders.db` is relative).

### The seam (`wires/host/policy.rs`) — for card 15

```rust
pub(crate) struct CallContext<'a> {
    pub principal: Option<&'a Principal>,   // fresh + verified, every claim in `.claims`
    pub caller: NodeId,
    pub roster_version: Option<u64>,
    pub tool: &'a ToolName,
    pub argv: &'a Argv,
}
pub(crate) struct Decision { pub allow: bool, pub reason: String, pub role: Option<RoleName> }
pub(crate) trait Policy: Send + Sync {
    fn decide(&self, ctx: &CallContext<'_>) -> Decision;
    /// Tools a no-argument call to would be allowed — what to show this member.
    fn allowed_tools(&self, principal: Option<&Principal>, caller: NodeId) -> Vec<ToolName>;
}
pub(crate) struct RoleTable { … }   // impl Policy; HostConfig::policy() builds it
```

`ServeConfig.policy: Arc<dyn Policy>` (required); `ServeConfig.identity`
(`IdentityGate`) now only resolves the principal:
`resolve(caller, now) -> Result<Principal, String>` (the `Err` is the
"no identity claim …; run `wires login --topic ops`" text). For card 15:
`config.policy.allowed_tools(gate.resolve(member, now).ok().as_ref(), member)`,
and `HostConfig.tools[..].description` is there to announce. `allowed_tools`
and `CallContext::{roster_version, argv}` carry `#[allow(dead_code)]` until
a production reader exists. Test-only `policy::AnyMember` admits everything
(the transport tests' old inclusion-only behavior).

### Decisions

- **Grants are not consulted by `serve host.json`** (`require_grant: false`):
  roles replace them. The grant machinery and the `ServeConfig.require_grant`
  field stay (transport tests, `advanced grant`).
- **Trust root = the host's own membership's `fabric`.** The channel preflight
  still checks the channel's fabric equals it.
- **`channel` is optional** so a member-only host (e.g. `bench/wires-up.sh`'s
  `gh`) needs no provisioned channel; validation refuses roles/identity
  without one. Without a channel there's no audit and no principal.
- **Trust comes only from the file.** A host no longer reads
  `WIRES_OIDC_*`; observers (`wires watch`) still do. `IdpTrust` gained
  `by_issuer` (per-issuer audiences; `audiences_for_claim` picks by the
  token's unverified `iss`, then verification pins that same issuer), so an
  audience accepted from one IdP isn't accepted from another.
  `from_flags_or_env`/`trusting` are gone with the flags.
- **Reasons.** Allow: `alice@example.com is in role analyst (email=*@example.com)`.
  Deny with a principal: `identity bob@other.org (from ISS) is in no role
  allowed to run db_query: analyst (email=*@example.com | email=…)`. Deny
  without one: ``<why no principal>; run `wires login --topic ops`; db_query
  needs a verified identity in role analyst (…)`` — it still *starts* with
  `no identity claim for <node8>`, which the demo greps. Empty allow:
  ``tool X allows no role (its host.json `allow` is empty)``. Unknown tool
  (after the credential checks): `unknown tool: X`, unchanged.
- `Principal.claims` is `#[serde(skip)]`: no wire change, and a principal
  read back from a call record has it empty (nothing compares them).
- `--audit-peer` → `--peer` (it no longer has an `--audit-topic` to
  qualify). Kept: `--node-seed[-file]`, `--membership[-file]`,
  `--roster-head[-file]`, `--inclusion-proof[-file]`, `--crl-json/--crl-file`,
  `--relay-url`.
- Render: `▶ 3fa2 alice@example.com (a1b2…) [analyst] db_query "…"` (role
  escaped like every other field).

### Off-lane touches

`wires/channel/idp_view.rs` (`IdpTrust`), `wires/channel/render.rs` (`[role]`),
`wires/e2e/{mod,idp}.rs` (`policy:` in `ServeConfig` literals; the card-05
e2e is now `host_json_roles_admit_verified_federated_identities_only`),
`library/calls/{idp,audit}.rs`, `library/channel/record.rs`. Demo: only the
serve block (plus `--check`) and the 5a `[analyst]` assertion. **Not
touched:** `bench/wires-up.sh` (card 19's lane) — it was already stale
after card 12 (un-prefixed `roster`/`member`/`import`) and now also uses the
removed `serve --trust-root --allow-any-member --expose 'gh=gh'`; its fix is
a two-line host.json: `{"version":1,"tools":{"gh":{"command":["gh"],"allow":["member"]}}}`.
`docs/deployment.md` got one banner sentence; `docs/committed-roster.md`
examples still show `--trust-root` (history).

### Numbers

`wires_test` 322 (was 312), `library_test` 254 (was 253),
`library_doc_test` 45. Lint (`--config=lint`) and `format.check` green.
`demo-remote-cli.sh --quiet` green (~10 s).

