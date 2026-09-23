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

- [ ] Unit + proptest: parse/validate (unknown key, missing version, empty allow → deny), the matcher table, the decision reasons.
- [ ] e2e: `analyst` allowed; an authenticated non-analyst denied, with the reason and the denial on the channel; `member` role works without IdP when written out explicitly.
- [ ] `demo-remote-cli.sh` uses a `host.json` fixture; still green.
- [ ] `bazel test //...`, lint, format check green.

## Notes
