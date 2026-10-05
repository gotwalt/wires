# 42 — One caller identity for every service

**Stage:** 1 (parallel with [40](40-cut-records.md)) · **Depends on:** — · **Status:** backlog · **Files:** `wires/host/{transport,native,embed,service,identity}.rs` (the child's environment, `Call`), `bindings/lib.rs`, `bindings/node/lib.rs`, `bindings/python/examples/`, `bindings/node/examples/`, `wires/examples/kv/`, `wires/e2e/{service_child,native}.rs`, `.scripts/fixtures/`, `docs/protocol.md` §5–6

## Why (the human, 2026-10-05)

"I'd rather just have a clearer idp-sourced auth token that comes along in
both the env and as something that a native service can work with." And:
"the raw id token is available in the env of all processes for simplicity's
sake."

Today a CLI service and a native service see two different things. A native
handler gets the whole verified `Principal` (`call.principal()`). A CLI child
gets a scattering of variables: `WIRES_CALLER_EMAIL` only when the token has
an email, and no issuer, subject, groups or expiry; plus three nobody reads
(`WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`, `WIRES_STATE_VERSION`:
no script, fixture or example in the repo uses them).

## Decisions

- **Every service gets the caller's raw ID token**: `WIRES_ID_TOKEN` in a
  CLI child's environment, `call.id_token()` in the native API (Rust,
  Python, TypeScript). It is the token the host verified for this call: the
  caller's own from `wires call` and `wires mcp`, the web user's from the
  gateway. No opt-in, no per-service switch.
- **And the claims the host verified, in one place**: `WIRES_CALLER`, a JSON
  object with the same fields as `Principal` (`issuer`, `subject`, `email`,
  `org`, `groups`, `not_after`), so a shell script reads `jq -r .email`
  instead of decoding a JWT. The native API keeps `call.principal()`; the
  two are the same value.
- **Kept**: `WIRES_CALLER_NODE` (push addresses it), `WIRES_CALLER_EMAIL`
  (the one-liner case; absent when the token has no verified email),
  `WIRES_SERVICE`, `WIRES_ROLE`, and the push capability variables.
- **Removed**: `WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`,
  `WIRES_STATE_VERSION`, and `Call::state_version()` if nothing uses it.
- **A service never runs without a verified identity.** Every role needs
  one, so the gate has already refused a call with no token. If the code
  still carries `Option<Principal>` past the gate, make the type say what is
  true.
- **The service does not need to verify the token**: the host did (the
  IdP's signature, the audience, the binding to the caller's key). It is
  there to be used: handed to a token exchange, or checked again by a
  service that wants to.

## What to write down honestly (protocol.md §6, and *Notes* for card 39)

- The ID token is a bearer credential until it expires (about an hour with
  Google). Inside wires it is bound to the caller's key and useless from any
  other; outside wires, any relying party that accepts this OAuth client's
  audience would accept it. Every service the caller calls now holds it, as
  the host already did.
- A child's environment is readable by other processes of the same Unix
  user (`/proc/<pid>/environ`), which is one more reason for
  [deployment.md](../../deployment.md)'s separate service user.
- A call through the web gateway carries a token minted under the gateway's
  OAuth client, so its `aud` differs from a `wires login` token's.

## Acceptance

- [ ] A CLI child's environment holds `WIRES_ID_TOKEN` (byte-for-byte the token in the call's `Hello`) and `WIRES_CALLER` (JSON equal to the verified `Principal`), tested in `e2e/service_child.rs`; `host.json`'s `env` still can't set a `WIRES_*` name.
- [ ] `call.id_token()` in Rust, Python and TypeScript, shown in each kv example or its test.
- [ ] The three removed variables appear nowhere (code, comments, docs/protocol.md, help, scripts).
- [ ] `cargo test --workspace`, clippy `-D warnings`, `cargo fmt --all --check` green; the bindings build (`make python`, `make node`) or the reason they couldn't here is in *Notes*.
- [ ] *Notes* lists every statement in the narrative docs this card made false or incomplete (`usage.md` § host.json's environment paragraph, at least).

## Notes
