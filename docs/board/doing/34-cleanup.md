# 34 — Cleanup: dead paths, hollow tests, leftovers from earlier designs

**Lane:** C · **Depends on:** 33 (merged at `cee6b0f`) · **Status:** backlog · **Files:** repo-wide (`library/`, `wires/`, `docs/`, `.scripts/`, `bench/`, root config)

## Why (the human, 2026-09-24)

"We've built and rebuilt it several times, and I'm sure it has some build up
of bad smells. Particularly concerned with tautological tests that don't test
anything, redundant paths, useless comments, and references to previous ways
the system worked." Then: "we can be a bit more exhaustive too."

The project is pre-alpha with nothing deployed, so there are no compatibility
shims to keep: an old field name, a `serde(default)` for "records written
before X", or a refusal kept for a retired format is all deletable. Git
history is the archive.

## How this list was made

Four read-only sweeps of `main` at `06ba765` (2026-09-24), just before card 33 merged (`cee6b0f`); each file read in
full: `library/`, `wires/host/`, the rest of `wires/`, and everything that
isn't Rust. Line numbers are from that commit. **Card 33 rewrites `main.rs`
(into `wires/lib.rs`), `transport.rs`, `gate.rs`, `serve.rs`, `config_v2.rs`,
`keystore.rs`, `identity.rs` and `sync.rs`.** So step 0 is to rebase onto 33,
re-find each item by content rather than line, and give the files 33 adds
(`host/native.rs`, `host/embed.rs`, `host/service.rs`, `wires/lib.rs`,
`bindings/`, the `wires-ffi` and `wires-node` crates) the same sweep.

Severity: every item is behavior-neutral unless marked **(bug)** or
**(behavior)**. Nothing here is a security finding.

## Decide first (the human)

These change user-visible surface, so they need a yes or no before a worker
starts:

- **D1. `wires tools` and `tools.json` aliases.** The hidden `Tools` command
  is "the old name of `wires services`" (`main.rs:153`). With no
  subcommand it prints the service list plus aliases (`tools.rs:239-253`).
  Aliases pinned by node id are documented in `protocol.md:136`,
  `usage.md:411/485` and `agent-sandbox.md:185`. Options:
  (a) keep aliases as `wires tools add|list|rm` only, and drop the no-argument
  listing and the "old name" doc; or (b) remove aliases, the command and
  `--tools-file`, and keep `"locked"` (in `tools.json`, or moved elsewhere).
- **D2. "fabric" in user-facing text.** `storytelling.md:34` bans "fabric"
  from any one-liner. But `init` prints `fabric <id>`, and the refusal on
  camera is "not admitted to this fabric", which `demo.md:41/309` says to
  point at. `README.md` and `executive-summary.md:35` also say "a key
  outside the fabric". Rename the strings (e.g. "not a member of this
  network"), or write the exception into storytelling.md. Renaming means
  re-recording the demo (see §E6).
- **D3. Board Lanes table.** `docs/board/README.md:71-107` keeps channel-era
  summaries for 18 done cards, plus a paragraph excusing them. Proposal: list
  only open cards, and link `done/` for the rest.
- **D4. Rename `config_v2` → `config`.** Also `HostConfigV2`, `PushV2` and
  `HOST_CONFIG_V2`, and "v2 host" in prose. There is no v1 left to tell apart
  from. Do it after 33 lands, because 33 edits `config_v2.rs`.

## A. Tautological or hollow tests

Delete, or rewrite so the test can fail for the reason in its name.

1. `library/codec.rs:42-46` `invariant_to_input_key_order`: `json!` builds a
   BTreeMap-backed `Value`, so both inputs are already the same value. The
   "sorts keys" half of `sorts_keys_and_is_compact` (33-39) is vacuous for the
   same reason. Rewrite both over a `#[derive(Serialize)]` struct whose
   fields are declared out of order.
2. `library/services/registry.rs:123-131` `service_and_tool_names_agree`
   exists only because of the duplicate types (§B1). It goes with them.
3. Tests of deleted designs, which clap or the parser would reject anyway:
   - `wires/main.rs:501-515` `the_channel_commands_are_gone`;
   - `wires/host/serve.rs:250-261`, the loop over `--expose`, `--audit-topic`,
     `--peer`, `--roster-head` and `--inclusion-proof`;
   - `library/calls/session.rs:421-431` `retired_handshake_tags_are_bad_frames`
     (`unknown_tag_is_bad_frame` covers it).
4. Tests that `member` isn't built in (the role was dropped in 28; the tests
   only keep the name alive):
   - `library/services/access.rs:321-342` `a_role_named_member_is_an_ordinary_role`;
   - the doctest line in `library/services/role.rs:30-31`;
   - `library/services/state.rs:383-393`;
   - `wires/admin/service.rs:655-670` `member_is_an_ordinary_role_name`;
   - the `member` case in `wires/e2e/services_host.rs:754-762`.

   The generic "undefined role is refused" cases already exist. Also replace
   `member` as a sample role in `capability.rs:395`, `control.rs:602-603` and
   `config_v2.rs:428/437`.
5. Compatibility tests (they go with §D2 below):
   - `library/calls/audit.rs:515-525` `an_old_finished_record_still_parses`;
   - `library/calls/audit.rs:527-554` `started_role_is_optional_on_the_wire`;
   - the v1-refusal tests at `serve.rs:397-404` and `config_v2.rs:426-431`.
6. A test of a test-only path: `wires/caller/hello.rs:58`
   `no_membership_is_an_error` checks an error that production can't reach.
   `build()` is compiled only under `#[cfg_attr(not(test), allow(dead_code))]`.
   Delete `build()`, and have the other test call `with_membership`.
7. Oracles that copy the implementation's own formula:
   - `host/capability.rs:477` (copy of :198);
   - `caller/inbox.rs:1093-1109` `evictions_make_room_oldest_first`;
   - `admin/ttl.rs:84-89` `every_unit_scales`;
   - `caller/lock.rs:438-449`;
   - `gateway/oauth.rs:724-731` `any_generated_verifier_matches_its_own_challenge`.

   Use known-answer cases, or check invariants only.
8. Near-tautologies:
   - `host/gate.rs:681-687`: `admit` returns `authorize`'s role by
     construction. Assert the narrowing property instead: an admitted caller
     is in every `also_require` role.
   - `library/calls/idp.rs:1006` and the doctest at 229 compare
     `for_node(na) == for_node(na)`. Pin a known-answer nonce.
   - `library/membership/membership.rs:186-187` asserts fields that `mint`
     just set.
9. Tests that pass for the wrong reason:
   - `host/transport.rs:1493-1513` `child_is_killed_when_the_dialer_vanishes`
     only checks that the session returns within 5 s. Assert that the child
     was spawned and is gone (a pid file plus `kill -0`).
   - `host/audit.rs:441-444` `an_untallied_stdin_tap_records_nothing` asserts
     nothing.
   - `host/config_v2.rs:445-458` `validation_rules` only asserts `is_err()`,
     and the `version:3` case fails in the `Peek` check, not in `validate`.
     Assert the error text for each case.
   - `gateway/mod.rs:713-722` `a_full_table_evicts_rather_than_resets` also
     passes if the whole table is reset. Assert that a recent over-limit
     address is still refused.
   - `caller/shape.rs:506-512` `head_never_splits_a_char`: the cut always
     lands after an ASCII `\n`. Rename it for what it actually checks (a
     prefix of n lines).
   - `wires/e2e/services_host.rs:809-852` `nothing_is_broadcast_to_a_bystander`:
     no code path would ever dial carol, so this guards the deleted gossip
     design. Delete it, or push to a role carol is in.
   - `host/push.rs:1227` `the_queue_survives_a_round_trip_through_its_file`
     never touches the file. Go through `persisted_queue`/`save`, or rename it.
   - `gateway/sessions.rs:359-369` `tokens_and_codes_are_distinct_and_unguessable`
     never touches codes. Rename or drop.
10. Duplicate or derive-only round trips. Keep the property test and drop the
    example copies:
    - `session.rs:363-371`, `406-411`;
    - `services/sync.rs:205-210`;
    - `invoke.rs:184-194`;
    - `audit.rs:477-482`, `502-513` (keep one of these and the proptest at
      605-612);
    - `identity.rs:265-270`, `286-290`;
    - `calls/push.rs:536-540`;
    - `access.rs:404-443` (`listing_agrees_with_authorize` restates the
      implementation; `refusal_text_says_what_to_do` repeats line 313);
    - `caller/mcp.rs:785-793`, which asserts words in a literal a few lines up.
11. Dead statements in tests:
    - `state/sync.rs:1124` (repeats the timeout above it) and `:1162` (the
      file removal has no effect);
    - `caller/inbox.rs:984`;
    - `e2e/records.rs:592`;
    - `caller/shape.rs:395-400`;
    - `caller/call.rs:1361` (`h2` is the same identity as `h`).
12. Duplicated or misplaced tests:
    - `admin/propagate.rs:147-159` repeats `main.rs:495`;
    - the RFC 7636 PKCE vector is tested at `caller/login.rs:776` and
      `gateway/oauth.rs:667`, and inlined at `e2e/gateway.rs:104-105`;
    - the JWKS cache and rotation tests at `caller/login.rs:1068-1164` belong
      in `caller/jwks.rs`.
13. Test-only code in production modules:
    - `otlp.rs:137-140` `dropped()` is under
      `#[cfg_attr(not(test), allow(dead_code))]`; use `#[cfg(test)]`;
    - `otlp.rs:592-625` exercises multi-host grouping that production never
      produces (§B5).

## B. Redundant, duplicate or dead paths

1. **`ServiceName` and `ToolName` are one type.** Delete `ToolName`,
   `MAX_TOOL_NAME` and `Error::InvalidToolName`, and remove the two
   `expect`ing `From` impls (`registry.rs:18-74`, `invoke.rs:20-84`,
   `error.rs:72-74`). `Invocation.tool` and `AuditRecord::{Started,Denied}.tool`
   become `service: ServiceName`. The wire format changes; that's fine
   pre-alpha. Follow it through `transport.rs:745`, `record_stream.rs:343/354`,
   `caller/tools.rs`, `CallArgs.tool` (`call.rs:530`) and the docs.
2. **The call log's channel forwarding.** `host/call_log.rs:291-360`: every
   production caller passes `start(…, channel: false)`. Drop the parameter,
   the returned `Option<Receiver>`, the forwarding branch in `tee` and the
   per-append `record.clone()`. The tests should check the exporter instead.
3. **Clock helpers.** There are private `now_ms()` wrappers in
   `caller/inbox.rs:361` and `host/push.rs:891` over `host::audit::now_ms`,
   plus `main.rs:208` `now_unix`, which every role imports. Put both in one
   small `clock` module; the caller shouldn't depend on a host module to read
   the time.
4. **Hex newtypes and frame codecs, written more than once:**
   - `CallId` and `PushId` (16 bytes);
   - `OutputDigest` and `EntryHash` (32 bytes);
   - the length-prefixed frame helper, three times (`session.rs:214-236`,
     `services/sync.rs:84-123`, `calls/push.rs:324-366`).

   Use one `hex_id!` macro and one `pub(crate)` framing helper in `codec.rs`.
   Rename `Error::BadKeyLength` → `BadLength`, since ids and digests report it
   too.
5. **Host: dead or unreachable code:**
   - `record_stream.rs:456-471` repeats `ServicesHost::check_member`;
   - `record_stream.rs:86` `NOT_ADMITTED` aliases `gate::NOT_ADMITTED`, and
     its doc ends mid-sentence;
   - "responder configuration error" is written out four times (gate.rs:406,
     push.rs:725, record_stream.rs:453, transport.rs:753); make it one
     constant;
   - `record_stream.rs:598` `preauth: Option<Permit>` is always `Some`;
   - `transport.rs:1098` `verify_target: Option<NodeId>` is `None` only in
     tests;
   - `transport.rs:1171-1176`: the mid-stream `Denied` arm handles "a future
     re-check" that nothing sends;
   - `config_v2.rs:230-235`: `validate()` repeats `parse`'s version check;
   - `otlp.rs:166-191` groups entries by host, though an exporter only has
     one; and `summary` (226-284) is built on every call but only used when
     serialization fails, which can't happen;
   - `identity.rs:81-94,189-202`: `Known.failure` and `Lookup::Unverified`
     are read only by tests; `IdpTrust.issuers` duplicates the keys of
     `by_issuer`;
   - `gate.rs:483`: the `dedup()` after sorting HashMap keys is a no-op;
   - `capability.rs:104` `Grant.service` is written and never read;
   - `push.rs:226-230`: the duplicate-id check can't fire, since ids are
     fresh;
   - `push.rs:311`: `PushHost.me` duplicates `host.me`;
   - `push.rs:442-450`: `authorize` wraps `decide_push` and returns
     `(String, bool)`. Return an enum instead, and rename the bound `roster`
     (594, 743).
   - **(bug)** `record_stream.rs:419`: `let Ok(hash) = entry.hash() else { continue }`
     silently drops an entry, leaving a gap the reader can't explain.
     Propagate the error.
   - `record_stream.rs:187`: the `.max(1)` guards against something that
     can't happen.
   - Make private: control.rs `RUN_DIR`, `SUN_PATH_BYTES`,
     `ControlSocket::serve`, `effective_uid`; push.rs `authorize`,
     `deliver_direct`, `sweep`; config_v2.rs `validate`.
6. **Caller:**
   - The "no membership / no signed state: run `wires join`" lookup appears
     six times (hello.rs:16, services.rs:61, watch_records.rs:581,
     call.rs:289 and 655, inbox.rs:874). Make it one
     `store::require(ks) -> (Membership, SignedState)`. inbox.rs:874 then
     checks again at :877.
   - `call.rs`:
     - the Hello with the `id_token` override is built twice (187, 454), and
       the preflight is run twice (179, 398);
     - `test_endpoint` is inlined again at 934-947;
     - `Route::Alias` carries `Option<Dial>` plus an `unreachable!`
       (590-611); make it `Route::Alias(Dial)`.
   - `inbox.rs:222`: `evictions(…, incoming)` is always passed 0.
   - `inbox.rs:720-750`: `InboxArgs` copies five `CredArgs` fields; flatten
     `CredArgs` instead.
   - Two identical control-character escapers: `inbox.rs:429` `one_line` and
     `watch_records.rs:987` `escape`.
   - Short-id helpers, each a different length: `pick::short` (8),
     `tools::short` (16), `watch_records::short_hex` (4), plus about 8 inline
     `&hex()[..8]`. Make it one `NodeId::short()`.
   - `pick.rs:122`: the relay slot in `Hints` is always `None`.
   - Principal formatting: `host::identity::principal_name` is used by the
     gateway, and there are variants in `services.rs:125` and `login.rs:751`.
     Make it one `Principal::name()`.
   - The wildcard → localhost socket rewrite exists three times
     (`pick.rs:203`, `e2e/mod.rs:43`, `state/sync.rs:997`); the e2e copy's
     doc cites a transport.rs idiom that no longer exists.
   - The URL_SAFE_NO_PAD engine is declared again in 6 files; make it one
     `B64`. The `"jwks"` directory literal appears three times, and
     `is_loopback` twice (`gateway/clients.rs:99`, `caller/jwks.rs:359`).
   - `gateway/mcp_http.rs:42-47` redefines the JSON-RPC error codes from
     `caller/mcp.rs:84-88`; the e2e tests use bare literals.
   - `gateway/mod.rs`:
     - 237 and 562: a hand-written refresh loop duplicates
       `sync::refresh_loop` and `STALE_AFTER_SECS`;
     - 519-528: `resolve()` and `node_identity_in` are called twice;
     - 205-210: the keystore is re-read on every call.
   - `state/sync.rs:407-418`: `refresh_cold` → `refresh_if_stale` checks
     staleness twice; `is_stale`'s `max_age` is always `STALE_AFTER_SECS`.
   - `main.rs`: `refresh_cold` and the command each build their own tokio
     runtime (319, 332); `Mcp` and `Tools` bypass `exit_with` (358-365).
   - `tools.rs:257`: an unreachable `bail!`, with the config loaded before
     `cmd` is checked.
   - Noise: `mcp.rs:778` `schema()` wraps `input_schema()`; `mcp.rs:990`
     `let s = …; let mut s = s;`; `sync.rs:732` has a redundant `.clone()`.
7. **Admin:**
   - `keystore.rs`:
     - `resolve_identity` (200-236) has dead branches (`root.seed`, "wires
       init", unknown file);
     - `force` is only true in tests, and **(bug)** its error at :298 says
       "pass --force", a flag that doesn't exist;
     - `write_text`/`write_secret_overwrite` are one-line wrappers;
     - `preflight` returns `Result<(), String>`, which every caller maps;
     - `ensure_dir` duplicates `store::create_private_dir`;
     - the test-local `temp_dir()` (411-420) duplicates testutil's (as does
       `caller/tools.rs:353` `tmp()`).
   - Edit, then push to hosts: the same glue is written four times (invite,
     remove, service/role, `state push`). `Report` lives in `invite.rs:61`
     but every admin command uses it. Move `Report` (with `Default`) and a
     `run_edit` helper into `admin/mod.rs`.
   - `Ttl::DEFAULT.parse().unwrap()` appears four times; add `impl Default for Ttl`.
   - `service.rs:401-452`: `service_in`/`role_in` return a `SignedState`
     that production ignores; `admin_with` (493) is `pub(crate)` inside a
     private test module.
8. **Library:**
   - `call_log.rs:406-414`: `verify_chain` re-implements `LogEntry::verify`;
   - `state.rs:235`: `SignedState::verify` checks `format`, then `validate()`
     checks it again;
   - unused, so delete them:
     - `lib.rs:176` `version()` (its doc is stale too);
     - `EntryHash::as_bytes`;
     - `Signature::from_bytes`;
     - `Chunk::len`/`is_empty`;
     - `Principal::claims` ("for a later host policy");
     - the `Serialize`/`Deserialize` derives on `IdentityClaim`;
   - exported but used only inside: `LogEntry::sign`,
     `Retention::DEFAULT_DAYS`/`max_age`, `stdin_head`/`STDIN_HEAD_MAX`;
   - `invite.rs:147` `invite_for` rebuilds `root` instead of returning it.
9. **Tests.** Move into `e2e/mod.rs`:
   - the frame reader, three copies (`services_host.rs:311`,
     `records.rs:284`, `service_child.rs:176`);
   - the `World`/`host_json`/`role()`/`service()` fixtures;
   - about 10 `Endpoint::builder(Minimal)…bind()` blocks;
   - three hand-rolled Hello/Invoke `call()`s.

   Also replace `e2e/gateway.rs:619` `futures_join_all` with `JoinSet`.
   `testutil.rs`: drop the `TEST_TMPDIR` fallback.

## C. References to earlier designs (code)

1. **`roster_version` → `state_version: StateVersion`**, required. This
   touches `library/calls/audit.rs:266-271`, `host/audit.rs:112-149,351,363`,
   `otlp.rs:358`, `record_stream.rs:780`, `caller/watch_records.rs:1228,1278`
   and `protocol.md:342`.
2. **The compat shims in `AuditRecord` and `Invocation`:**
   - `role: Option<String>` ("before roles existed") becomes a required
     `RoleName`;
   - the `serde(default)`s on `stdin_bytes`/`stdin_digest` go;
   - the `OutputDigest::empty` doc becomes "the digest of zero bytes";
   - `Invocation.argv` loses its `serde(default)` (invoke.rs:143).

   Optional: make `calls/push.rs:299` `wait_ms` required too.
3. **Retired tags and formats:**
   - `session.rs:25,30,63`: remove the "channel-era" rows and "services-era
     (card 27)";
   - `invite.rs:58-60`: remove the "channel-era `1`" history; rename the
     test `garbage_and_old_tokens_are_refused`;
   - `config_v2.rs:52-53,208-212`: the explicit v1 refusal becomes the
     generic "version N is not supported";
   - `transport.rs:49-51`: remove the "channel-era `/2` handshake" note, and
     optionally reset the ALPN to `/1`.
4. **Bazel:**
   - `caller/mod.rs:37-39` (`//wires:wires_dev`, `//wires`), which should
     say "the `dev-mock-idp` feature build";
   - `caller/lock.rs:140`;
   - `testutil.rs:6,10,24-27,46`;
   - **(bug, doc)** `transport.rs:932`: "`//wires` carries no `thiserror`
     dependency" is false; derive `Denied` with thiserror;
   - `transport.rs:307` `//relay`, which should say "a self-hosted iroh
     relay".
5. **Rename the leftover names:**
   - `library/error.rs:17-20` `TicketDecode` → `TokenDecode`;
   - `error.rs:49` "a proof's member" → "a membership's member";
   - `watch_records.rs:792` and the test at 1270
     `the_record_line_formats_are_the_channel_eras`;
   - `gate.rs:1` "The services-era call gate" → "The call gate";
   - `capability.rs` `Grant`/`PushGrants`/`push_grants` (optional:
     `PushCapabilities`).
6. **Leftover roster, CRL and channel wording:**
   - `codec.rs:15` "(memberships, heads)";
   - `keystore.rs:332-334` "the same head (the admission CAS…)";
   - `membership.rs:19` "a future delegation chain"; `:123` "or revocation";
   - `policy.rs:5-6` "no separate revocation list";
   - `admin/invite.rs:9-10` "no key to rotate";
   - `caller/login.rs:65,201` "the publish" / "claim to publish";
   - `control.rs:494` "two sequence allocators";
   - `transport.rs:944` and `session.rs:148,174,376`: the example reason
     "membership rejected: revoked" (the test at transport.rs:1407 uses it
     too);
   - `transport.rs:1130` "fabric member"/"root-vouched";
   - `services/sync.rs:190`: the fixture `{"type":"gossip"}`;
   - `calls/push.rs:404` "the Notes' example";
   - `role.rs:2` "(card 27; … card 13's `host.json`)";
   - `call_log.rs:12-20`: the "chosen over redb (card 25)" history.
7. **Tool/responder wording** (lower priority):
   - "denied by responder", which the user sees (`main.rs:426`,
     `mcp.rs:514`);
   - "exposed tool" (`audit.rs:264`, `invoke.rs:29,86,133-142`);
   - the docs in `call.rs:17-88`, `mcp.rs:9,273` ("every `tools.json`
     entry"), `tools.rs:39-234`, `keystore.rs:316,393`;
   - `caller/lock.rs:113-121`, which also omits `--verbose`;
   - "The v2 responder" (`transport.rs:659,676`);
   - `jwks.rs:27` "an observer".

## D. Comments

1. **Module indexes that miss a module or test:**
   - `host/mod.rs:9-25` misses `record_stream`;
   - `caller/mod.rs:9-27` misses `watch_records`, and lines 15-16 are
     garbled;
   - the doc indexes in `e2e/records.rs:12-20` and `e2e/gateway.rs:4-14` each
     miss a test.
2. **Noise:**
   - the `// ----- … -----` banners in control.rs, push.rs and transport.rs
     (12 of them);
   - `store.rs:80` "`lock` drops here"; `:104` hard-codes "10 minutes";
   - `join.rs:106` restates `adopt_if_newer`;
   - `use` statements in the middle of the test module (`transport.rs:1235`);
   - `serde(default)` on `Option` fields (`idp.rs:415,417`);
   - `transport.rs:1130` "Credential-only (root-vouched + TTL)" is jargon.
3. **`cargo doc` warnings.** Make `cargo doc --workspace --no-deps` produce
   no warnings:
   - the unresolved `[MAX_STATE_FRAME]` at `state/sync.rs:128`;
   - redundant link targets at `state/sync.rs:1`, `watch_records.rs:6`,
     `admin/invite.rs:5`, `gateway/mcp_http.rs:19`, `host/identity.rs:8`,
     `record_stream.rs:2` and `transport.rs:6`.

## E. Docs, scripts, config

1. **Leftover config:**
   - `rust-toolchain.toml:1` ("The toolchain Bazel pinned");
   - `.gitignore:7-8` (`/bazel-*`);
   - `.gitignore:12-14` un-ignores `.claude/settings.json`, which isn't
     tracked;
   - `.editorconfig` has only Kotlin/ktlint settings;
   - `Cargo.toml:12` `rust-version`: neither crate inherits it;
   - `.clippy.toml` and `.shellcheckrc` contain only comments; delete them
     or say they're placeholders.
2. **Board:**
   - `README.md:3-4,13`: history lines;
   - `:109`: finished order history;
   - `:117`: "the relay package, or anything iOS", neither of which exists;
   - the Lanes table (D3).
   - `backlog/09-witness.md:13-14`: rewrite history;
   - `backlog/29`:
     - `:33` "Update the board" (done);
     - `:84` names the deleted `aaron/web-gateway` branch;
     - `:37` cites a line number that has drifted.
   - `doing/08-demo-two-machine.md:13-85`: mostly the channel-era run
     (`--expose`, `--audit-topic`, bazelisk, re-keys, gossip WARN).
     `:50` narrates a phrase that `demo.md:322` bans. Keep only the lessons
     that still hold (`ssh -o RemoteCommand=none`, the broken x86
     cross-compile, 0 TCP listeners, the n=1 token result, the Safari fix).
3. **protocol.md:**
   - `:95-97`: the "no Merkle-committed roster any more" rationale;
   - `:182`: "the channel-era `Handshake`";
   - `:342`: the `roster_version` aside (goes with C1).
4. **Card 31 status disagrees.** The card and the board say parked, but:
   - README.md:169 says "being reworked";
   - usage.md:305-308 says "agreed and next", and 386-388 says "agreed";
   - protocol.md:334-337 says "the next step";
   - executive-summary.md:75 says "Next (card 31, agreed)".

   Say "designed, parked (card 31)" everywhere.
5. **Content kept in more than one place, and drifting:**
   - Two keystore tables: `usage.md:475-489` and `protocol.md:407-424` each
     have rows the other lacks. Keep the one in protocol.md §9.
   - The limits list, four times: README:143-171, usage:334-368,
     protocol:445-467, exec-summary:70-76. Make usage § Known trade-offs the
     canonical list; the others get a short version that links to it.
   - The admin command reference, twice: `usage.md:396-415` and
     `protocol.md:99-110`.
   - "Run services as a separate Unix user", three times: usage:456,
     protocol:224, deployment:55. Keep it in deployment.md.
   - Role command lists: `board/README.md:57` and exec-summary:24-26 omit
     `id` and `state push`.
   - `usage.md:523` layout omits `gateway/`.
   - CLAUDE.md doesn't mention `.scripts/macos-sign.sh` (plus the
     `.cargo/config.toml` runner), `deploy/gateway/` or `bench/push/`.
   - `Dockerfile:7-8` and CLAUDE.md:124 describe the image as caller-only,
     but it is deployed as `wires gateway`.
6. **Docs that are wrong:**
   - **(bug, doc)** `usage.md:404`: a blank line inside the "Commands by
     role" table, so the rest renders as raw text.
   - The README GIF and MP4 (`5e10073`) show the pre-28 refusal text.
     Re-record after D2.
   - `docs/media/demo-push.*` and `demo-remote-cli.cast`: about 2 MB, and
     nothing links to them. Link or delete them.
   - `README.md:47-52` leads with "no firewall port", which
     `storytelling.md:21` records as already killed by "Tailscale". Lead with
     reach by key, services only.
   - History headers:
     - `executive-summary.md:3` ("Replaces the 2026-08-15 summary…");
     - `storytelling.md:3-5` ("trimmed … card 25").
7. **bench/:**
   - `bench.py:17-18` says `serve --expose gh=gh`; `bench.py:11` and
     `run.sh:5` say four arms (there are five);
   - `REPORT.md:42` and `:240-243` contradict each other about what the
     wires arm ran, and `push/REPORT.md` repeats its setup note;
   - `permission-probe.py:118-119` says "no channel";
   - **(bug)** `permission-probe.py:127-128` probes `--inclusion-proof*`,
     which clap now rejects without the locked-mode text, so `judge()` scores
     them "ran" (a false positive). Delete both probes and fix the count
     ("22 flag and stdin commands") in `agent-sandbox.md:174`.
   - **(bug)** `push/up.sh:52`: `role set … || true` hides a failure that
     every later step depends on.
   - `bench/run.sh:24`: `cp -f` over a signed binary; macOS SIGKILLs it.
     `rm -f` first, as `push/run.sh:20` does.
8. **Scripts, duplicated:**
   - `demo-remote-cli.sh:93-121` and `demo-push.sh:72-107` share about 12
     helpers, the two-build block, mock-IdP startup and login. Move them to
     `.scripts/lib.sh`. `the_line` means different things in the two scripts;
     give the push variant its own name.
   - `bench/wires-up.sh` and `bench/push/up.sh` repeat the provisioning.
   - `push/up.sh:62-73` writes its own copy of
     `.scripts/fixtures/push-host.json` as a heredoc; generate it with `sed`,
     as demo-push.sh does.

## Order

0. Rebase onto 33 and sweep its new files. Get D1–D4 decided.
1. **§C1, C2, B1** (the renames and removals that change the wire format and
   the log format) as one commit, so the log format changes once.
2. **§A** (tests), then **§B** (paths), by crate. These parallelize by
   folder: `library/`, `wires/host/`, `wires/caller/` + `gateway/`,
   `wires/admin/` + `state/` + `e2e/`.
3. **§C3–C7, §D** (wording and comments).
4. **§E** (docs, scripts, config); re-record the demo last.

## Acceptance

- `make lint test` is green; `cargo doc --workspace --no-deps` has 0
  warnings; `make demo` passes.
- `git grep -n -i -E 'roster|channel-era|services-era|bazel|//wires|TEST_TMPDIR|--expose|audit-topic|inclusion-proof|revoc|ticket|gossip|before .* existed|older (logs|records)'`
  outside `docs/board/done/` and `bench/**/results*` returns only lines a
  note on this card justifies.
- No `#[cfg_attr(not(test), allow(dead_code))]` remains.
- No `serde(default)` remains that exists only for records or peers from
  before a change.
- Each deleted test is listed in Notes with its reason. Every rewritten test
  was seen failing against a deliberately broken implementation.
- The four duplicated limit, keystore, admin-command and separate-user
  passages each live in one place.

## Notes

### Decisions (2026-09-24, integrator's recommendations; the human said "go for it")

- **D1 → (a).** Aliases stay, as `wires tools add|list|rm` only. The hidden
  "old name of `wires services`" behaviour (no-subcommand listing) goes.
- **D2 → rename.** User-facing "fabric" becomes "network" (e.g. "not a member
  of this network"); internal type names (`FabricId`) stay. Demo scripts and
  demo.md follow. The GIF/MP4 re-record is card 08's (it records anyway).
- **D3 → yes.** The board table lists open cards; `done/` holds the rest.
- **D4 → yes.** `config_v2` → `config`, `HostConfigV2` → `HostConfig`, etc.

### Phase 1 (done)

The cross-cutting changes the later lanes build on. `make lint`,
`cargo test --workspace`, `make demo` and `.scripts/demo-push.sh` pass.

- **§B1.** `ToolName`, `MAX_TOOL_NAME` and `Error::InvalidToolName` are
  gone; `ServiceName` (with `MAX_SERVICE_NAME`, exported) validates itself.
  `Invocation.service`, `AuditRecord::{Started,Denied}.service`,
  `CallArgs.service`; the two `From` impls and `service_and_tool_names_agree`
  deleted (`tool_name_rules` folded into `registry::name_rules`). The child
  env loses `WIRES_TOOL` (it always equalled `WIRES_SERVICE`), and the OTLP
  attribute `wires.tool` is now `wires.service`. The alias file keeps its
  `remote_tool` key (typed `ServiceName` now); D1's lane decides its shape.
- **§C1/C2.** `Started` carries a required `state_version: StateVersion` and
  `role: RoleName`; the `serde(default)`s on `stdin_bytes`/`stdin_digest` and
  `Invocation.argv` are gone. Deleted `an_old_finished_record_still_parses`
  and `started_role_is_optional_on_the_wire` (compat shims); replaced by
  `started_records_the_service_version_and_role`. protocol.md §8 updated.
  `Push.role` stays optional (a push isn't always role-admitted).
- **§B3.** `wires/clock.rs`: `now_unix()`, `now_ms()`; the wrappers in
  `inbox.rs`, `push.rs`, `lib.rs` and `host::audit::now_ms` are gone.
- **§B4/§C5.** `codec::hex_id!` declares `CallId`, `PushId`, `OutputDigest`,
  `EntryHash` (all now `Hash` + `Display`; `EntryHash::as_bytes` dropped);
  `codec::{length_prefixed, prefix_len, split_frame}` frame the session,
  state-sync and inbox codecs. `BadKeyLength` → `BadLength`,
  `TicketDecode` → `TokenDecode`.
- **§B6 helpers.** `Principal::name()` (replaces
  `host::identity::principal_name`, its test, and the variants in
  `services.rs`/`login.rs`; `wires login` now prints `sub at issuer` when
  there is no email). `NodeId::short()` (8 hex) replaces `pick::short`,
  `tools::short` (was 16) and the inline `&hex()[..8]`/`[..16]` on node ids.
  `library::B64` is the one URL_SAFE_NO_PAD engine. `store::require(ks)` and
  `store::require_state(ks, root)` replace the six "run `wires join`"
  lookups (inbox's duplicate check deleted). One `net::is_loopback` (three
  copies before, counting otlp.rs). The JSON-RPC codes live in
  `caller/mcp.rs` only; the gateway and e2e tests use them.
- **§A6** (it went with `store::require`): `hello::build` and
  `no_membership_is_an_error` deleted; the other test calls `with_membership`.
- **D4/§C3.** `host/config.rs`, `HostConfig`, `Push`, `HOST_CONFIG`; the v1
  refusal is the generic "version N is not supported"; its tests
  (`v1_is_refused_with_the_way_forward`, the v1 case in `serve.rs`) deleted.
  "v2 host" / "The v2 responder" prose is "host". The file's `"version": 2`
  is unchanged.
- **D2.** "not a member of this network", `init` prints `network <id>`,
  `join` says `joined network …`, "network root" in errors; the scripts, demo.md,
  usage.md, protocol.md, deployment.md, executive-summary.md and the board
  README follow.

Deliberately left:

- `wires watch` lines keep 4-hex ids (`short_hex`/`short_node`): the line is
  dense, and usage.md and the recorded casts quote that width.
- `WIRES_FABRIC_ROOT` (a child env name) and the internal `fabric` field and
  helper names stay, per D2 ("internal identifiers stay").
- `gateway/mod.rs` keeps its own "the gateway holds no signed state" lookups
  (different wording, and §B6's gateway items are that lane's).
- `cargo doc` warnings (§D3) are unchanged by this phase; none are new.

### Lane LIB

`library/` items: §A1, A3, A4 (library half), A8 (library half), A10
(library half), B8, C3 (session, invite), C5/C6/C7 (library wording), D2
noise, and the optional `wait_ms`. `make lint` and `cargo test --workspace`
pass; `cargo doc -p library` has no warnings.

- **§A1.** `codec` tests run over a `#[derive(Serialize)]` struct declared
  out of key order (and first assert that plain serde keeps declaration
  order, so the fixture can't go vacuous); `invariant_to_input_key_order` is
  now `invariant_to_input_map_order`, over two `HashMap`s built in opposite
  orders. The `(memberships, heads)` wording is `(memberships, signed
  states)`.
- **§A8.** `OidcNonce::for_node` has a known-answer test (node `[0; 32]`);
  the `for_node(na) == for_node(na)` line is gone from the proptest (now
  `for_node_is_distinct_and_url_safe`) and the doctest. `mint_then_verify_ok`
  no longer asserts the fields `mint` just set.
- **§B8.** `verify_chain` calls `LogEntry::verify` (mapping its errors to
  `BadSignature`/`Malformed`); `SignedState::verify` leaves the format check
  to `validate`. Deleted: `library::version`, `Signature::from_bytes`,
  `Chunk::len`/`is_empty`, `Principal::claims`, the serde derives on
  `IdentityClaim`, `Retention::max_age`. Narrowed: `LogEntry::sign` (private),
  `Retention::DEFAULT_DAYS` (private), `stdin_head` (private) and
  `STDIN_HEAD_MAX` (`pub(crate)`); `stdin_head`'s doctest cases moved into
  `stdin_head_caps_and_splits_on_a_char_boundary`. The test `invite_for`
  returns its `root` instead of rebuilding it.
- **§C3.** `session.rs`: the retired tag rows and "services-era (card 27)"
  are gone ("any other tag is a `BadFrame`"). `invite.rs`: the channel-era
  history is gone from `INVITE_V2`'s doc;
  `garbage_and_old_tokens_are_refused` → `garbage_and_unknown_formats_are_refused`.
- **§C5/C6/C7.** `SubjectMismatch`'s doc names its two real subjects
  (membership member, invite state). Gone: "future delegation chain",
  "or revocation", "no separate revocation list", "the Notes' example",
  `{"type":"gossip"}` (now `subscribe`), role.rs's card history, and every
  done-card reference in `library/` module docs (23, 26a, 26b, 27, 22, 13);
  card 29 (open) and card 18 (open) stay. The example refusal reason is
  "not a member of this network". "responder" is "host" throughout
  `library/` docs. ("exposed tool" was already gone after phase 1.)
- **§D2 noise.** No `serde(default)` on `idp.rs`'s private `Header`
  `Option`s. **`wait_ms` is required** (protocol.md already shows
  `fetch {wait_ms}`); a fetch without it is refused, which the shape test now
  asserts.
- **Also (sweep).** `state::validation_rules` asserted only `is_err()`; it now
  checks each broken rule by its `InvalidState` text, and covers an undefined
  `readers` role and an unknown `format`.

Follow-through outside `library/` (kept small):

- `claims: Default::default(),` removed where a `Principal` is built:
  `wires/host/{otlp,audit,gate,identity,record_stream}.rs`,
  `wires/gateway/{mod,sessions}.rs` (one line each).
- `wires/host/call_log.rs` module doc: "Chosen over redb … (card 25)" is
  now "A plain file fits because: … needs no database dependency" (§C6,
  assigned to this lane).

Deleted tests:

- `session::retired_handshake_tags_are_bad_frames`: `unknown_tag_is_bad_frame` covers it (§A3).
- `session::denied_reason_roundtrips` (proptest): the `roundtrips` proptest already generates every `Denied` reason.
- `session::exit_roundtrips_negative`: the `roundtrips` proptest covers any `i32`.
- `access::a_role_named_member_is_an_ordinary_role`: keeps the retired `member` role alive (§A4); undefined-role refusal is covered.
- `access::listing_agrees_with_authorize` (proptest): restates `allowed_services`'s implementation.
- `access::refusal_text_says_what_to_do`: repeats the "wires login" assert in `no_identity_no_role`.
- `state::validation_rules`, the `member` block: same reason as above (§A4); the `ghost` role case covers it.
- `role.rs` doctest lines for `member` (§A4).
- `identity::from_seed_hex_roundtrips`: the `expose_seed_hex` proptest plus doctest cover the inverse.
- `identity::node_id_hex_is_64_chars`: `node_id_serializes_as_hex_string` and the `generate` doctest pin the width.
- `invoke::invocation_json_round_trips` (proptest): derive-only; the session `roundtrips` proptest carries every `Invoke`.
- `audit::empty_hasher_is_the_digest_of_nothing`: the `OutputDigest::empty` doctest and the chunking proptest cover it.
- `audit::finished_round_trips_with_and_without_stdin`: its round trip is the proptest's; its omission check lives on as `an_absent_stdin_head_is_omitted`.
- `push::push_ids_round_trip` (proptest): derive-only (`hex_id!`).
- `sync::have_round_trips` (proptest): `frames_round_trip` covers `Have`.
- `idp`: the `p.claims[...]` asserts in the principal test went with the field.

Seen red against a broken implementation, then restored: `sorts_keys_and_is_compact`
and `invariant_to_input_map_order` (canonicalization skipped),
`for_node_known_answer` (context changed), `mint_then_verify_ok` (wrong
field signed), `validation_rules` (readers not checked; format not checked),
`an_absent_stdin_head_is_omitted` (`skip_serializing_if` dropped),
`a_fetch_and_a_deliver_have_the_documented_shape` (`wait_ms` defaulted),
`stdin_head_caps_and_splits_on_a_char_boundary` (split char kept), and
`an_unknown_version_does_not_verify` (`verify_chain`'s version mapping).

### Lane DOCS

§E, plus stale narration found on the way. Non-Rust files only.

- **E1.** `rust-toolchain.toml` comment says why 1.91; `.gitignore` drops the
  Bazel lines and ignores all of `.claude/` (`settings.json` isn't tracked);
  `.editorconfig` is now Rust/shell/Markdown (shell = tabs, which is what
  shfmt already produced: `shfmt -d` is clean); the dead `rust-version`
  workspace key is gone; `.clippy.toml` and `.shellcheckrc` (comments only,
  nothing referenced them) deleted, CLAUDE.md says "default settings".
- **E2 / D3.** Board: history lines and the finished order history gone; the
  Lanes table lists open cards only (34, 08, 33, 29, 31, 32, 18, 09) with a
  Status column and a link to `done/`; the disclaimer paragraph is gone;
  "relay package / iOS" rule → "don't merge from `archive/poc-2026-05`";
  caller command list adds `id`. backlog/09 history line gone; backlog/29
  "update the board" (already done), the drifted `login.rs:97` (now named by
  item) and the deleted branch name fixed, "fabric" → "network". doing/08:
  Steps current, Notes cut to the lessons that still hold, plus a Step to
  re-record the README GIF/MP4 (they show pre-28/pre-D2 refusal text).
- **E3.** protocol.md: the Merkle-roster rationale, the retired-tag line
  ("Any other tag decodes as `BadFrame`"), "no revocation list" and
  "`member` is an ordinary role name" gone. Prose "fabric" → "network"
  (field names like `fabric` stay, per D2). **Doc bug:** §8 said the record
  stream refuses with `not admitted to this fabric`; the code sends
  `gate::NOT_ADMITTED` ("not a member of this network"). Fixed.
- **E4.** Card 31 reads "designed, parked" in README, usage (×2),
  protocol, deployment, executive-summary and the board.
- **E5.** One home each: keystore table in protocol.md §9 (gained the
  gateway files row; usage links it and keeps the location/precedence
  notes); limits canonical in usage § Known trade-offs (gained gateway
  listens/tools-only, only-Google-tested, relay, one network per keystore);
  README, exec-summary and protocol §10 are short lists linking there; admin
  command reference only in usage § Commands by role (protocol §3 is a
  paragraph + link); the separate-Unix-user passage is a `###` in
  deployment.md (with the sudo example and the child-socket caveat), linked
  from usage and protocol §5. Role lists aligned (board, exec-summary). usage
  layout adds `gateway/` and `bindings/`. CLAUDE.md: four crates, `lib.sh`,
  `macos-sign.sh` + the `.cargo/config.toml` runner, `bench/push/`,
  `deploy/gateway/`, `docs/media/`; image description includes `wires
  gateway` (also Dockerfile, deployment.md).
- **Dockerfile bug (found):** it copied only `library/` and `wires/`, but
  the workspace now lists `bindings` and `bindings/node`, so cargo couldn't
  load the workspace. It copies `bindings/` too; `.dockerignore` skips
  `node_modules` and `.venv`.
- **E6.** usage.md blank line in the Commands-by-role table removed.
  `docs/media/demo-push.*` and both `.cast` files deleted (unlinked, and they
  show pre-28 text; card 08 re-records). README leads with "reached by key,
  only the services you may call" (no "no firewall port" lead). History
  headers in executive-summary.md and storytelling.md gone; "There is no
  channel" → "Nothing is broadcast" (CLAUDE.md, board, usage); usage
  "Revocation" → "Removal", deployment "Provisioning and removal"; host.json
  `version` row no longer mentions v1.
- **E7.** bench.py/run.sh: five arms, `host.json` not `--expose`;
  REPORT.md: one top note + a setup row that says which runs used which
  responder (card 16: `--expose`; arm 5: member-only `host.json`), the
  contradicting tail note deleted; push/REPORT.md: the repeated setup note
  and a `bazel test` mention reworded. permission-probe.py: "no membership",
  the two `--inclusion-proof*` probes deleted; agent-sandbox.md count is 18
  (9 flag/stdin probes × unlocked/locked). push/up.sh: `role set` fails
  loudly, and each `service add` tolerates only "reached none of its 1
  host(s)". run.sh: `rm -f` before `cp`.
- **E8.** `.scripts/lib.sh`: narration helpers, `wait_for`, `alive`,
  `dump`, `build_wires` (the two-build block), `start_mock_idp`, `login_as`;
  both demos source it (≈120 lines gone). demo-push's `the_line` is now
  `numbered_line`. push/up.sh generates `host.json` from
  `.scripts/fixtures/push-host.json` with sed (analyst → bench).
  `demo-native-service.sh` (card 33's lane) still has its own copies; it can
  source `lib.sh` too.

Skipped, with reasons:

- **Shared bench provisioning** (`wires-up.sh` / `push/up.sh`): both end in a
  real browser `wires login`, so a refactor can't be exercised here; the
  shared part is ~20 lines. Left as is.
- `testing.md` still lists "nothing sent to a bystander" among the e2e
  cases; drop it if §A9 deletes that test.
- `protocol.md` still mentions the hidden `tools` alias in the pull list and
  "denied by responder" appears in usage/demo output: D1 and §C7 are the code
  lanes'; the docs follow whatever they print.
- Remaining acceptance-grep hits in my files are justified: `channel` in
  `rust-toolchain.toml` (TOML key), demo.md's banned-words list,
  agent-sandbox.md's plain-English "channel"; "ticket" in storytelling.md's
  killed-story log; `fabric` as a field/identifier name in protocol.md and
  storytelling.md's register test.

Checks: `make lint`, `make fmt-check`, `cargo test --workspace`, `make demo`
and `.scripts/demo-push.sh --quiet` green; `docker build .` green (it failed
to load the workspace before the `bindings/` copy); `bench/push/up.sh` run
end to end against the mock IdP (an `open` shim played the browser).
### Lane ADMIN

`wires/admin`, `wires/state`, `wires/e2e` (not `native.rs`), `lib.rs`,
`testutil.rs`, `net.rs`.

Deleted tests:

- `lib.rs` `the_channel_commands_are_gone` (§A3): clap rejects any unknown
  command anyway; it only kept the retired names alive.
- `admin/service.rs` `member_is_an_ordinary_role_name` (§A4): "an undefined
  role is refused" is already covered by
  `invalid_edits_are_refused_and_nothing_is_stored`.
- The `member` case in `e2e/services_host.rs`
  `a_fetch_with_a_token_makes_a_caller_reachable_by_role` (§A4); the `staff`
  case stays.
- `e2e/services_host.rs` `nothing_is_broadcast_to_a_bystander` (§A9), with
  its `counting_node` fixture: no code path would ever dial carol, so it
  guarded the deleted gossip design. That a role push reaches nobody the host
  hasn't seen is already asserted in
  `a_fetch_with_a_token_makes_a_caller_reachable_by_role`.
- `admin/propagate.rs` `state_push_parses` (§A12): it repeats
  `lib.rs` `onboarding_commands_parse`.

Rewritten tests, each seen red against a deliberately broken implementation:
`admin/ttl.rs` `every_unit_scales` → `units_agree_with_each_other` (checks
units against each other, not the implementation's table; red with
`'h' => 3601`); keystore `save_refuses_to_clobber_without_force` →
`a_saved_key_is_never_overwritten` (red with `create(true).truncate(true)`);
the two `preflight_*` tests (red with the check disabled);
`store::staleness_and_the_admin_hint` (red with `>=`); the new
`net::wildcard_binds_dial_localhost` (red without the v6 rewrite);
`role_cli`, which now reads the stored state back
(`role_set_names_google_unless_told_otherwise` red with the wrong default
issuer); `concurrent_users_each_call_with_their_own_token` on `JoinSet`
(red when a task's assert fails); the shared e2e `call` (red when it drops an
argument) and `records.rs`'s `call` on top of it (red when inverted).

Done:

- §A7/A11/A12 above; `state/sync.rs`: the dead elapsed-time assert and file
  removal, the redundant `.clone()`; `e2e/records.rs`: the dead `let _`.
- §B7: `resolve_identity` inlined into `node_identity` (the root branches
  were dead); `force` gone (`save_node`/`save_root` never overwrite; the
  error no longer names a nonexistent `--force`); `write_text` and
  `write_secret_overwrite` gone; `preflight` returns `anyhow::Result`;
  `ensure_dir` merged into `keystore::create_private_dir` (the store's copy,
  moved; it makes new directories `0700` and no longer re-chmods an existing
  one, since every file in it is written `0600`/`0644` explicitly); the
  keystore tests use `testutil::temp_dir`. `Report` (now `Default`, with a
  `hint` printed after the notes) and `run_edit` live in `admin/mod.rs`;
  invite, remove, service, role and `state push` all go through it.
  `impl Default for Ttl`. `service_in`/`role_in` return the line only;
  `admin_with` is private; `init.rs` `args()` gone.
- §B6: `refresh_cold` calls `catch_up` (one staleness check); `is_stale`
  takes no `max_age` (always `STALE_AFTER_SECS`). `net::dialable` is the one
  wildcard → localhost rewrite (`caller/pick.rs` `write_own_hint`, the e2e
  `localhost_socks`, the sync tests).
- `lib.rs`: each command runs on one runtime (`refresh_cold` and the command
  in one `block_on`); every error goes through `exit_with` (`serve`, `mcp`,
  `tools`, the offline commands); `print_or_exit` prints nothing for empty
  output; `exit_with_code` for the commands that return a code. D1: `Tools`
  is documented as the alias editor and requires a subcommand.
- §B9: `e2e/mod.rs` holds `bind`/`bind_in`, `read_frame`, `Outcome` and the
  one hand-rolled `call`, and the fixture pieces (`role`, `service`,
  `email_at`, `signed_state`, `membership`, `hello`, `adopt`,
  `host_config`). Each file keeps its own `World` (different casts), built
  from those. `futures_join_all` → `JoinSet`. `testutil.rs`: no
  `TEST_TMPDIR`, no Bazel.
- §C6, §D: "same head (the admission CAS…)", "no key to rotate", "`lock`
  drops here", "10 minutes", `join.rs`'s restating comment; the e2e doc
  indexes (records, gateway) name every test; "fabric" in doc prose →
  "network" in these files; `cargo doc --document-private-items` has no
  warnings in these files, and `lib.rs`'s crate doc no longer links private
  items (8 warnings in plain `cargo doc`).

Outside the lane, kept minimal:

- `caller/tools.rs` (D1): `ToolsArgs.cmd` is required; `tools_cmd` (the
  no-subcommand listing), `render_aliases` and the unreachable `bail!` are
  gone.
- `caller/pick.rs`: `write_own_hint` calls `net::dialable`.
- `save_node`/`save_root` lost their `force` argument at the call sites in
  `host/serve.rs` (test), `host/embed.rs`, `caller/join.rs` and
  `e2e/native.rs`.
- `caller/call.rs` and `caller/inbox.rs` still wrap `preflight`'s error in
  `.map_err(anyhow::Error::msg)`: that still compiles, and lane CALLER can
  drop it.

Left: `e2e/records.rs` keeps `call_log::start(opened, None, false)` (lane
HOST's §B2 changes that signature; the integrator reconciles it). The RFC 7636
vector inlined in `e2e/gateway.rs` stays (§A12 lists it with the caller's
PKCE tests). The sync tests' internal `Fabric` fixture name stays (internal).
### Lane HOST

`wires/host/**` (not `native.rs`, `embed.rs`, `service.rs`, `serve_until`,
or the `TaskProcess`/`in_process` helpers). Every rewritten test was seen
red against a deliberately broken implementation (listed per test below),
then green.

Deleted tests:

- `audit.rs` `an_untallied_stdin_tap_records_nothing`: asserted nothing; a
  `StdinTap` with no audit holds no state to check.
- `serve.rs`, the loop over `--expose`, `--audit-topic`, `--peer`,
  `--roster-head`, `--inclusion-proof` and `-- cat` (§A3): clap rejects
  unknown flags anyway. The test is now `serve_takes_host_json_and_its_flags`.
- `call_log.rs` `the_tee_logs_exports_and_forwards` and
  `the_log_is_kept_without_a_channel_or_exporter`: they tested the channel
  forwarding (§B2), which is gone; replaced by `the_tee_logs_and_exports`
  (red with the export dropped) and `the_log_is_kept_without_an_exporter`.

Rewritten tests (and the break that turned each red):

- §A7 `capability.rs` `only_the_exact_caller_id_is_admitted`: known answers
  (the id in either case admitted, a random string not) instead of the
  implementation's formula. Red with `to != grant.caller.hex()`.
- §A8 `gate.rs` `the_gate_never_widens_the_registry`: asserts that an
  admitted caller is in every `also_require` role (and `status`, which any
  staff may call, now carries the same `also_require`, so the rule has
  something to narrow). Red with `all` → `any`.
- §A9 `transport.rs` `child_is_killed_when_the_dialer_vanishes`: the child
  writes its pid; the test waits for it, checks it is alive, drops the
  dialer, and checks `kill(pid, 0)` fails after the session returns. Red
  with the bridge returning at shutdown without killing.
- §A9 `config.rs` `validation_rules`: every case asserts its own error text
  (plus the missing-version, empty/duplicate-issuer and no-audience rules).
  Red with the duplicate-issuer check off.
- §A9 `push.rs` `the_queue_survives_a_round_trip_through_its_file`: through
  `persisted_queue` and `save` (and the file's `0600`). Red with `save`
  skipping an existing file.
- §A13 `otlp.rs` `one_record_per_entry_in_order` (was `one_record_per_entry`
  over up to three hosts): one host's chain, one resource naming it, records
  in order. Red with the records reversed.
- `identity.rs` `each_state_of_a_node` (it read `Lookup::Unverified`): now
  checks that a failing token marks the node as seen with no principal. Red
  with failures not recorded.

Done:

- §B2: `call_log::start(log, exporter)` → `(AuditSink, JoinHandle)`; no
  `channel` flag, receiver, forwarding branch or per-record clone.
- §B5: `record_stream::authorize` uses `ServicesHost::check_member`; its
  `NOT_ADMITTED` alias is gone (callers use `gate::NOT_ADMITTED`);
  `serve`'s `preauth` is a plain permit; `last_seq` lost its `.max(1)`.
  **(bug)** `View::items` returns `Result` and a hidden entry that can't be
  hashed fails the stream instead of leaving a silent gap. One
  `gate::HOST_MISCONFIGURED` ("responder configuration error"; the text is
  unchanged, protocol.md and an e2e test quote it). `dial_opened(_with)`
  take `target: NodeId`; the mid-stream `Denied` arm is gone.
  `validate_fields` lost its second version check. `otlp::request` builds one
  resource (an exporter carries one host's log); the per-record summary is
  gone. `identity.rs`: `Known.failure`, `Lookup` and `IdpTrust.issuers`
  (now `issuers()`, from `by_issuer`) are gone. `gate.rs`: the no-op
  `dedup`. `capability.rs`: `Grant.service` (and `mint`'s `service`
  argument); the redundant `len() == 64` check. `push.rs`: the duplicate-id
  check, `PushHost.me`; `authorize` is private and returns
  `gate::PushRefusal { NotAMember, Refused }` (so `decide_push` does too),
  and the `roster` bindings are gone. Private now: `control.rs` `RUN_DIR`,
  `SUN_PATH_BYTES`, `ControlSocket::serve`, `effective_uid`; `push.rs`
  `authorize`, `deliver_direct`, `sweep`; `config.rs` `validate`.
  `serde(default)` dropped from `Option` fields in `config.rs`, `push.rs`
  and `record_stream.rs`.
- §C3: `transport::ALPN` is `wires/session/1` (nothing but protocol.md §5
  named `/3`; updated), with no channel-era note.
- §C4: `Denied` derives `thiserror::Error`; "a self-hosted iroh relay".
- §C5/C6/C7: "The call gate"; "two `serve`s on one keystore" for the
  sequence allocators; the "membership rejected: revoked" examples, "fabric
  member", "root-vouched" and "fabric" in host prose and `serve --help` are
  gone; "responder" → "host" in host prose and in two dialer errors (the
  user-facing "denied by responder" stays: `lib.rs`, `mcp.rs` and the docs
  are other lanes'). `call_log.rs`'s "chosen over redb (card 25)" history is
  gone. `member` as a sample role (§A4) is replaced in `capability.rs`,
  `control.rs` and `config.rs`.
- §D1 (`record_stream` in the `host/mod.rs` index), §D2 (the banners in
  `control.rs`, `push.rs`, `transport.rs`; the mid-module `use` in
  `transport.rs`'s tests), §D3 (no `cargo doc --document-private-items`
  warning left in `wires/host`).

Follow-through outside `wires/host`: `wires/Cargo.toml` gains
`thiserror = { workspace = true }` (and `Cargo.lock` the edge);
`wires/e2e/records.rs` calls `call_log::start(opened, None)` and imports
`gate::NOT_ADMITTED`; `docs/protocol.md` §5 names `wires/session/1`;
`serve_until` gets the one-line `call_log::start` change.

Left:

- `serve.rs` `Binding::Endpoint` keeps its `cfg_attr(not(test),
  allow(dead_code))`: making it `#[cfg(test)]` needs `#[cfg(test)]` on two
  match arms in `serve_until` (the card-33 lane's).
- The optional `PushGrants` → `PushCapabilities` rename: it touches
  `serve_until` too.
- The append in `call_log::tee` still clones the record once: `Pending`'s
  answer channel is private to `transport.rs`, so splitting it would add a
  type for one clone per `fsync`.
### Lane CALLER

`wires/caller/**` and `wires/gateway/**`. `make lint`, `cargo test
--workspace` and `make demo` pass. D1's `tools.rs` change (required
subcommand, no listing, `render_aliases`/unreachable `bail!` gone, lib.rs
dispatch) is lane ADMIN's, per the integrator; this lane left those lines
alone.

- **§B6 call.rs.** `Credentials::hello(ks)` runs the preflight and builds the
  `Hello` (with the `presenting` token) once, for `dial` and
  `call_service_with`; `Credentials::{node_id, fabric, bind}` for the
  gateway; `Credentials` is `Clone` (the node key behind an `Arc`).
  `Route::Alias(Dial)` (argv moves into the route; no `Option`, no
  `unreachable!`). `stored_state` is gone (`mcp` reads `store::read`). The
  loopback shaping test uses `test_endpoint`/`loopback`.
- **§B6 inbox.rs.** `InboxArgs` flattens `CredArgs`. `--tools-file` moved
  out of `CredArgs` onto `CallArgs`/`McpArgs`, so inbox doesn't grow a flag
  it ignores; `Lock::check(creds, tools_file)` still refuses it by name.
  `evictions(unread, cap)` (the always-0 `incoming` is gone).
- **One escaper**, `caller::one_line`, for inbox and watch lines (with a
  known-answer test). `Hints` holds addresses only (the relay slot was
  always `None`). `jwks::JWKS_DIR` for the three caller/gateway uses.
  `hello::with_membership` returns `Hello` (it could not fail).
- **Gateway.** One `Keystore` (an `Arc`) and one `Credentials`, resolved at
  start, instead of re-reading both on every call; `node_identity_in` and
  `resolve()` once. The state lookups are `store::require_state`. The
  refresh is `sync::refresh_loop` on the gateway's shared endpoint (first
  tick at start, then every `STALE_AFTER_SECS`); `STATE_REFRESH` is gone.
  `library::B64` used directly; the test-only `oauth::b64` is gone.
- **mock_idp**: the inspection hooks and their `state` field are
  `#[cfg(test)]`, so the `#[cfg_attr(not(test), allow(dead_code))]` on the
  module is gone.
- **Wording.** `wires mcp` says `denied by host: <reason>`; "tool" /
  "responder" → service / host / alias in call.rs, mcp.rs, tools.rs,
  watch_records.rs; locked mode's refusal lists `--verbose` and "the service
  name"; `jwks.rs` "an observer", login.rs "the publish", the Bazel notes in
  `caller/mod.rs` and `lock.rs`, the `wires watch` "channel-era" header.
  `caller/mod.rs` indexes `watch_records`. The `cargo doc` warnings in
  `watch_records.rs` and `gateway/mcp_http.rs` are fixed (and the three
  that this lane's new `Hello` import caused in call.rs).
- **serde(default)**: dropped on `Option` fields (`TokenReply`,
  `RegistrationRequest.client_name`) and on the watch marks' `views`/`labels`
  (always written; an older marks file now loads as empty).

Tests rewritten, each seen failing against a broken implementation:
`inbox::evictions_take_the_oldest_past_the_cap` (new known answer) and
`evictions_make_room_oldest_first` (invariants, not the formula; broke the
count and the sort); `lock::unknown_values_fail_closed` (generates only
non-off values; broke the off list and the stdin policy);
`gateway::a_full_table_evicts_rather_than_resets` (hog is over its limit in
a recent window and stays refused; broke eviction into a reset);
`shape::head_keeps_a_prefix_of_n_lines` (was `head_never_splits_a_char`;
adds "a cut lands right after the Nth `\n`"; broke `head_len` by one);
`oauth::pkce_needs_a_well_formed_verifier_and_its_challenge` and
`a_challenge_admits_no_other_verifier` (broke `pkce_ok`'s length and match
checks); `call::a_service_beats_an_alias…` now checks the alias's pinned
host (broke `Dial::resolve`'s target). Renamed only:
`sessions::issued_tokens_are_long_and_never_repeat` (it never touched
codes), `watch_records::record_line_formats`,
`call::lookup_lists_known_aliases_on_a_miss`. Moved: the JWKS cache,
rotation, expiry and untrusted-issuer tests, login.rs → jwks.rs. The RFC
7636 vector is tested once (`login::pkce_matches_the_rfc_7636_appendix_b_vector`),
from shared `#[cfg(test)]` constants `login::RFC7636_{VERIFIER,CHALLENGE}`.

Deleted:

- `mcp::the_schema_leads_with_args_and_keeps_stdin`: asserted words of the
  literal a few lines above it (§A10); the same for the schema-field loop
  in `descriptions_say_how_to_filter_without_a_shell`.
- `oauth::any_generated_verifier_matches_its_own_challenge`: `pkce_ok`
  calls `Pkce::from_verifier`, so it compared the formula with itself.
- `oauth::pkce_matches_the_rfc_7636_vector`: a second copy of the vector
  (its well-formedness cases live on in the rewritten test).
- Dead statements: `shape.rs`'s repeated `nosuchfn` assertion, inbox's
  `m.from = node(1)` re-set, call.rs's `h2` (same identity as `h`).

For other lanes:

- "denied by responder" is still printed by `lib.rs:434` (ADMIN) and
  `transport::Denied`'s `Display` (HOST), and quoted in usage.md and
  demo.md (docs); `wires mcp` now says "denied by host".
- `e2e/gateway.rs:104-105` can use `login::RFC7636_{VERIFIER,CHALLENGE}`.
- `host/serve.rs` still spells `"jwks"` twice; `caller::jwks::JWKS_DIR`
  exists.
- `run_tools_cmd`'s "no tool named" (inside ADMIN's D1 edit) could say
  "no alias named", as `add`/`validate`/`wires call` now do.

Left: the `// ----- … -----` section banners in inbox.rs and
watch_records.rs (they divide 1,100-line files; §D2 names only the host
ones).
