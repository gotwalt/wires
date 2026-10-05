# 42 — One caller identity for every service

**Stage:** 1 (parallel with [40](40-cut-records.md)) · **Depends on:** — · **Status:** done (merged into `simplify` 2026-10-05) · **Files:** `wires/host/{transport,native,embed,service,identity}.rs` (the child's environment, `Call`), `bindings/lib.rs`, `bindings/node/lib.rs`, `bindings/python/examples/`, `bindings/node/examples/`, `wires/examples/kv/`, `wires/e2e/{service_child,native}.rs`, `.scripts/fixtures/`, `docs/protocol.md` §5–6

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

- [x] A CLI child's environment holds `WIRES_ID_TOKEN` (byte-for-byte the token in the call's `Hello`) and `WIRES_CALLER` (JSON equal to the verified `Principal`), tested in `e2e/service_child.rs`; `host.json`'s `env` still can't set a `WIRES_*` name.
- [x] `call.id_token()` in Rust, Python and TypeScript, shown in each kv example or its test.
- [x] The three removed variables appear nowhere (code, comments, docs/protocol.md, help, scripts).
- [x] `cargo test --workspace`, clippy `-D warnings`, `cargo fmt --all --check` green; the bindings build (`make python`, `make node`) or the reason they couldn't here is in *Notes*.
- [x] *Notes* lists every statement in the narrative docs this card made false or incomplete (`usage.md` § host.json's environment paragraph, at least).

## Notes

**Worker, 2026-10-05 (branch `worker/42-caller-identity`).**

What changed:

- `docs/protocol.md` §5 (the child's environment, native services) and §6
  (a new *What a service gets* paragraph with the three honesty points above)
  first, then the code.
- A CLI child gets `WIRES_ID_TOKEN` (the token from the call's `Hello`, byte
  for byte) and `WIRES_CALLER` (`serde_json` of the verified `Principal`, so
  `email`, `org` and `groups` are omitted when absent, exactly as `Principal`
  serializes; it parses back to an equal `Principal`). Kept:
  `WIRES_CALLER_NODE`, `WIRES_CALLER_EMAIL`, `WIRES_SERVICE`, `WIRES_ROLE`,
  the push pair. Removed: `WIRES_FABRIC_ROOT`, `WIRES_MEMBERSHIP_NOT_AFTER`,
  `WIRES_STATE_VERSION`, and `Call::state_version()` (only the two bindings
  used it; they lose `state_version()` / `stateVersion()` too, and
  `wires::StateVersion` is no longer re-exported, `wires::IdToken` is).
- `Call::id_token() -> &IdToken` (Rust), `Call.id_token() -> str` (Python),
  `call.idToken(): string` (TypeScript). `Call`'s `Debug` is now hand-written
  and never prints the token (unit test).
- Each kv example (Rust, Python, TypeScript) has a `whoami` verb: the
  verified name, then the ID token **without its signature** (so no
  credential lands in stdout, or in the host's call log while that exists).
  Tested in `e2e/native.rs` (Rust: equal to the `Hello`'s token minus its
  signature) and in `.scripts/demo-native-service.sh` (Python and
  TypeScript: equal to `idp-token.jwt` minus its signature).

Decisions:

- **The gate's guarantee is now a type.** It held already: `admits` returns
  false for no principal, so `authorize` (and `admit`) never succeed without
  one. `gate::Admitted` now carries `caller: Verified` (new
  `host::identity::Verified { token: IdToken, principal: Principal }`, Debug
  redacts the token), and `admit` / `ServicesHost::decide` take
  `Option<&Verified>`. The one remaining `let … else` is inside `admit`,
  right after `authorize` succeeded, where it is unreachable; it refuses as
  `NotInRole` rather than panicking. The native path's old runtime check
  ("admitted without a verified principal") is gone. `transport.rs` builds
  the `Verified` from `hello.id_token` and the existing `principal` local, so
  `ServicesHost::principal`'s signature and the audit lines (card 40's) are
  untouched. The bindings' `Principal` records still carry only `issuer`,
  `subject`, `email` (unchanged; not in this card's scope).
- `host.json` `env` already refuses every `WIRES_*` name
  (`config.rs`); added a `WIRES_ID_TOKEN` case to that test.
- Merge with card 40: the env vector and the native `Call` construction sit
  next to the audit lines, but no audit line was changed. Untouched:
  `record_stream.rs`, `audit.rs`, `refuse_member`. `rustfmt` reflowed
  `ServicesHost::decide`'s `admit(...)` call onto one line (the parameter
  rename made it fit). The board README's lane row for 42 still links
  `backlog/`; left for the integrator to avoid a conflict with card 40's
  row edit.

Narrative-doc statements this card made false or incomplete (for 39/43):

- `docs/usage.md` § host.json, the "A service's environment starts empty"
  paragraph (around line 672): lists the three removed variables, lacks
  `WIRES_ID_TOKEN` and `WIRES_CALLER`, and "None of it is taken from the
  caller" is now false (the token is the caller's, verified by the host).
- `docs/usage.md` § native services ("What the handler gets beyond a CLI",
  around line 280): lists `call.principal()`, `call.role()`, `call.id()`;
  incomplete without `call.id_token()`.
- `docs/deployment.md` § Run services as a separate Unix user: says nothing
  about the caller's token in the child's environment (`/proc/<pid>/environ`
  is readable by the same user, one more reason for the section); and its
  `sudo -u svc` example resets the environment by default, so the service
  would not see `WIRES_*` (including `WIRES_ID_TOKEN`, `WIRES_CALLER`, the
  push pair) unless sudo is told to keep them (`--preserve-env=...`). That
  was already true of the old variables; it matters more now.
- `docs/board/README.md` non-negotiables ("a service child is handed none of
  the host's keystore"): still true, but a child is now handed the caller's
  bearer ID token; worth saying wherever the doc lists what a child holds.
- `docs/demo.md`, `README.md`, `fabric.md`, `executive-summary.md`,
  `agent-sandbox.md`, `testing.md`, the blog post: no statement found that
  names the removed variables or `state_version()`; none made false that I
  found.

Verification (run here, results as seen):

- `cargo test --workspace`: green (library 177, wires 441 (437 + 4 new),
  doctests green).
- `cargo clippy --workspace --all-targets -- -D warnings`: green.
- `cargo fmt --all --check`: green.
- `.scripts/build-python.sh` and `.scripts/demo-native-service.sh --lang
  python`: built; all assertions passed (including the new `whoami` one).
- `.scripts/build-node.sh` (Node v22.22.2) and
  `.scripts/demo-native-service.sh --lang node`: built; `kv.mts` typechecks
  against the generated `index.d.ts`; all assertions passed.
- `.scripts/demo-remote-cli.sh --quiet`: exit 0, its summary printed (the loopback demo still passes with the new environment).
- shellcheck and shfmt (via `uvx`) on `.scripts/demo-native-service.sh`:
  clean.
- `git grep` for the three removed names and `state_version()`: only this
  card, `docs/board/done/34-cleanup.md` (history) and `docs/usage.md`
  (narrative, listed above).
