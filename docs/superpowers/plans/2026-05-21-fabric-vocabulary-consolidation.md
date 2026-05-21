# Fabric Vocabulary Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish "Fabric" as the canonical user-facing term for the unit of organization rooted in one human, retain "Tenant" as host-internal jargon, and remove "Household" from the codebase.

**Architecture:** A pure rename refactor with a clearly-drawn vocabulary boundary. User-facing strings, the iOS data model, and the UniFFI bridge adopt "fabric." Host-internal protocol, on-disk format, and wire-format identifiers stay "tenant" because they are wire-format and renaming them would break compat. No behavior change; tests are expected to keep passing throughout.

**Tech Stack:** Rust (workspace crates + cargo test), Swift (SwiftData + The Composable Architecture + XCUITest snapshot harness), iOS Simulator (iPhone 17 Pro / iOS 26.4) via `scripts/snapshot-ios.sh`.

---

## The vocabulary boundary

This boundary is the contract for the whole plan. Memorize it before touching code.

**Becomes "Fabric" (user-facing layer):**
- All CLI help text, error messages, and stdout strings in `wires-cli`.
- All Rust doc-comments and string literals in `wires-cli`, `wires-mcp`, `wires-ha`, `wires-node` that face users or describe domain concepts. (Module/function/struct names whose internal callers all live below the user surface stay the same — the renames here are about WHAT THE USER READS.)
- The iOS app entirely: `Household` → `Fabric` as a SwiftData `@Model`, `HouseholdClient` → `FabricClient`, all view labels, all test class names, every fixture name.
- The UniFFI bridge module: `crates/wires-uniffi/src/tenant.rs` → `fabric.rs`. Function names stay (`register_with_hosted_service`, etc.) since they are already vocabulary-neutral.
- README user-facing prose.
- CLAUDE.md vocabulary documentation.

**Stays "Tenant" (wire format / host-internal jargon):**
- `crates/wires-host/` in its entirety — table names (`tenants.redb`, `topic_index.redb`), per-tenant on-disk subdir `tenants/<root_hex>/`, ingest index naming `ingest_<root_hex>.redb`, every `TenantRecord` / `TenantRegistry` / `TenantSupervisor` type.
- `crates/wires-net/src/tenant.rs` — the `/wires/tenant/0` ALPN, `TenantClient`, `TenantProtocol`, `TenantRequest` / `TenantResponse` / `TenantErrorCode`. These are wire-format JSON tags and protocol identifiers.
- `crates/wires-store/src/{schema.rs, ingest_index.rs}` references to "tenant" in the context of host-side storage layout.
- `crates/wires-mcp/src/tenants.rs` (`TenantSupervisor`) — the gateway's per-user runtime supervisor mirrors `wires-host`'s vocabulary; this is gateway-internal.
- Historical specs and plans in `docs/superpowers/specs/` and `docs/superpowers/plans/`. They describe past work; don't retroactively rewrite them. New specs use "fabric."

**Removed entirely:** "Household." The term is dropped, not relocated. The iOS model `class Household` becomes `class Fabric`. References in doc-comments become "fabric." Old SwiftData stores keyed by the `Household` schema will need to be wiped on first run after the rename — the iOS app is pre-alpha with no users and the snapshot harness drives an in-memory store, so this is acceptable.

When the boundary is ambiguous, default to the side that minimizes wire-format change. If a string is read by a user, it says "fabric." If a string is part of an ALPN, a redb table name, a JSON tag on the wire, or a directory path on disk, it says "tenant."

---

## File Structure

This plan does not create new modules. It renames and edits strings in place. The files most heavily edited:

- `CLAUDE.md` — vocabulary section added near the top.
- `README.md` — user-facing prose updated; the per-section structure stays.
- `crates/wires-cli/src/main.rs`, `crates/wires-cli/src/cmd/{host,init}.rs`, `crates/wires-cli/src/error.rs` — CLI help and doc-comments.
- `crates/wires-mcp/src/{lib,sign_in,sign_in_endpoint,rate_limit}.rs` — doc-comment updates.
- `crates/wires-uniffi/src/tenant.rs` → `crates/wires-uniffi/src/fabric.rs`; updates in `crates/wires-uniffi/src/{lib,app}.rs`.
- `Wires/Wires/Models/Household.swift` → `Wires/Wires/Models/Fabric.swift` (class + properties renamed).
- `Wires/Wires/Dependencies/HouseholdClient.swift` → `Wires/Wires/Dependencies/FabricClient.swift` (type, DependencyKey, methods renamed).
- `Wires/Wires/Fixtures/Fixtures+Household.swift` → `Wires/Wires/Fixtures/Fixtures+Fabric.swift`.
- Every Swift Feature file that references `Household` / `householdClient` / `loadHousehold` / `saveHousehold` (AppFeature, ConnectFeature, NetworkFeature, ServiceDetailFeature, ApprovalFeature, OnboardingFeature, SettingsFeature, MainFeature).
- Every Swift test file with the same references.
- `Wires/WiresTests/HouseholdClientTests.swift` → `Wires/WiresTests/FabricClientTests.swift`.

---

## Task 1: Lock the vocabulary boundary in CLAUDE.md

The boundary must be documented BEFORE any rename happens, so that the rest of the plan has a written contract to point at.

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add a vocabulary section to CLAUDE.md**

Insert this section directly after the "Status" section in `/home/gotwalt/src/wires/CLAUDE.md` (around line 30, before "Authoritative docs"). The exact text:

````markdown
## Vocabulary boundary: Fabric vs. Tenant

Wires has one user-facing concept for "the unit of organization rooted in one human": **fabric**. The codebase uses two words for it depending on layer:

- **Fabric** is the user-facing term. Every CLI string, error message, MCP OAuth page, iOS UI label, README sentence, and new spec uses "fabric."
- **Tenant** is host-internal jargon. It appears in `wires-host` (which is genuinely multi-tenant infrastructure: one host, many fabrics), in the `/wires/tenant/0` ALPN and `wires-net::tenant` protocol module, in on-disk paths (`host/tenants/<root_hex>/`), in redb table names (`tenants.redb`, `ingest_<root>.redb`), and in the MCP gateway's per-user supervisor (`wires-mcp::tenants::TenantSupervisor`). These are wire-format and on-disk identifiers; renaming them is a breaking change with no user benefit.

"Household" is not used. Earlier iOS and README drafts called the concept a "household"; that vocabulary has been retired in favor of "fabric." If you see "household" in code or docs that aren't historical specs, fix it.

Rule of thumb: if a user reads the string, it says "fabric." If a JSON wire field, an ALPN, a redb table name, or a directory path contains the string, it says "tenant."
````

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: define fabric vs tenant vocabulary boundary"
```

---

## Task 2: Rename CLI user-facing strings

The CLI command shape stays the same (`wires host pair`, `wires host topic-register`, etc. — "host" is the user-facing name for the relay). Only help text and doc-comments change.

**Files:**
- Modify: `crates/wires-cli/src/main.rs`
- Modify: `crates/wires-cli/src/cmd/host.rs`
- Modify: `crates/wires-cli/src/cmd/init.rs`

- [ ] **Step 1: Update `crates/wires-cli/src/main.rs` doc-comments and help strings**

Apply these exact edits:

Line 20-21 currently:
```rust
        /// the household operator (Alice). Without it, `init` writes identity
        /// only and the agent has no household pinning until paired.
```
Becomes:
```rust
        /// the fabric operator (Alice). Without it, `init` writes identity
        /// only and the agent has no fabric pinning until paired.
```

Line 66 currently:
```rust
    /// Tenant control: pair with a host, register topics, view status.
```
Becomes:
```rust
    /// Host control: pair this fabric with a host, register topics, view status.
```

Line 140 currently:
```rust
    /// Pair with a host: decode a HostTicket, register this tenant (signed by
```
Becomes:
```rust
    /// Pair with a host: decode a HostTicket, register this fabric (signed by
```

Lines 152-153 currently:
```rust
    /// Unregister this tenant entirely: the host drops the tenant row, every
    /// topic_index entry for this root, and the on-disk tenant directory.
```
Becomes:
```rust
    /// Unregister this fabric from the host: the host drops its tenant record,
    /// every topic_index entry for this root, and the on-disk tenant directory.
    /// ("Tenant" is the host-internal name for this fabric's footprint; see
    /// `CLAUDE.md`'s vocabulary section.)
```

Line 160 currently:
```rust
    /// Print this tenant's status as the host reports it.
```
Becomes:
```rust
    /// Print this fabric's host-side status.
```

Note: the `TenantUnregister` variant name on the `HostCmd` enum (lines 155, 211–212) stays unchanged — it's an internal Rust identifier that maps to the user-visible command name `tenant-unregister`. The user-visible CLI command name `host tenant-unregister` is acceptable: it accurately says "ask the host to drop the tenant record corresponding to this fabric."

- [ ] **Step 2: Update `crates/wires-cli/src/cmd/host.rs` user-facing strings**

Lines 175-176 currently:
```rust
            "This will tell the host to drop this tenant's record, every \
             topic_index entry, and the on-disk tenant directory.\n\
```
Becomes:
```rust
            "This will tell the host to drop this fabric's tenant record, \
             every topic_index entry, and the on-disk tenant directory \
             (`tenant` is the host-internal name for this fabric's footprint).\n\
```

Line 198 currently:
```rust
                    "Unregistered tenant on host; host dropped {} topic(s)",
```
Becomes:
```rust
                    "Unregistered fabric on host; host dropped {} topic(s)",
```

Line 202 currently:
```rust
                println!("Host did not have a record for this tenant (already gone)");
```
Becomes:
```rust
                println!("Host had no record for this fabric (already gone)");
```

Line 242 currently:
```rust
            println!("Tenant status (as reported by host):");
```
Becomes:
```rust
            println!("Fabric status (as reported by host):");
```

The `tracing::warn!` strings on lines 221 and 227 ("failed to rewrite config.toml after tenant-unregister", etc.) stay as-is — they reference the CLI subcommand name `tenant-unregister`, not the domain concept.

Function names like `tenant_unregister`, `tenant_status` stay unchanged (internal symbols mapped to the existing subcommand naming).

- [ ] **Step 3: Update `crates/wires-cli/src/cmd/init.rs` user-facing strings**

Line 33 currently:
```rust
            "(no root pinned — pair with an operator via `wires pair-listen` to attach to a household)"
```
Becomes:
```rust
            "(no root pinned — pair with an operator via `wires pair-listen` to attach to a fabric)"
```

- [ ] **Step 4: Build and test**

```bash
cargo build -p wires-cli
cargo test -p wires-cli --lib --bins
```
Expected: all green.

- [ ] **Step 5: Run the full workspace test suite**

```bash
cargo test --workspace
```
Expected: all green. The integration tests touch CLI help output but not the prose strings being changed; no test should break.

- [ ] **Step 6: Commit**

```bash
git add crates/wires-cli
git commit -m "wires-cli: replace household/tenant in user-facing strings with fabric"
```

---

## Task 3: Update Rust doc-comment vocabulary in non-CLI crates

These are doc-comments that describe domain concepts and currently say "household" or use "tenant" where they should be saying "fabric." They are user-developer-facing (anyone reading `cargo doc` output or browsing the source).

**Files:**
- Modify: `crates/wires-mcp/src/lib.rs`
- Modify: `crates/wires-mcp/src/sign_in.rs`
- Modify: `crates/wires-mcp/src/sign_in_endpoint.rs`
- Modify: `crates/wires-mcp/src/rate_limit.rs`
- Modify: `crates/wires-mcp/src/main.rs`
- Modify: `crates/wires-ha/src/main.rs`
- Modify: `crates/wires-node/src/{channel,config,pair,topic_names}.rs` (only doc-comments that say "household")
- Modify: `crates/wires-core/src/{channel/derive.rs, signer.rs}` (only doc-comments)

- [ ] **Step 1: Replace "household" → "fabric" in doc-comments and prose only**

For each file listed, scan with:
```bash
grep -n "household" <file>
```

Replace "household" → "fabric" in:
- `//!` and `///` doc-comments
- string literals that produce user-visible output (log lines, error messages, panic messages)

Do NOT replace:
- Identifiers (types, functions, modules, fields)
- redb table name literals (none of these crates own such names, but watch)
- Comments inside function bodies that describe wire-format JSON (none here, but check)

Known specific edits:

`crates/wires-mcp/src/lib.rs:2`:
```rust
//! surface for AI agents to act on a wires household's behalf. See the
```
Becomes:
```rust
//! surface for AI agents to act on a wires fabric's behalf. See the
```

`crates/wires-mcp/src/sign_in.rs:2`:
```rust
//! signs the canonical JSON (with `signature` zeroed) using the household
```
Becomes:
```rust
//! signs the canonical JSON (with `signature` zeroed) using the fabric
```

`crates/wires-mcp/src/sign_in_endpoint.rs:88`:
```rust
    // The household must already have a user record on this gateway.
```
Becomes:
```rust
    // The fabric must already have a user record on this gateway.
```

`crates/wires-mcp/src/rate_limit.rs:56`:
```rust
/// deployment serving a single household: every request is the same source.
```
Becomes:
```rust
/// deployment serving a single fabric: every request is the same source.
```

`crates/wires-mcp/src/main.rs:12`:
```rust
    /// Run the gateway HTTPS service + tenant supervisor.
```
Stays: this references the internal `TenantSupervisor` type, which (per the vocabulary boundary) keeps the tenant name. No change.

For `wires-ha`, `wires-node`, `wires-core`: scan with `grep -n "household" <file>` and replace each prose occurrence with "fabric." There are only a handful of hits. Tenant references in these files (e.g., `wires-node/src/config.rs` references to `NodeConfig.retention` and the gateway's tenant supervisor) are accurate and stay.

- [ ] **Step 2: Build and test**

```bash
cargo build --workspace
cargo test --workspace
```
Expected: all green. Doc-comment changes can't fail tests.

- [ ] **Step 3: Verify no remaining "household" mentions in source**

```bash
grep -rn "household" crates/ --include="*.rs"
```
Expected: zero hits. If anything remains, fix it.

- [ ] **Step 4: Commit**

```bash
git add crates/
git commit -m "rust: replace 'household' with 'fabric' in doc-comments and prose"
```

---

## Task 4: Rename the UniFFI bridge module

The UniFFI module that wraps `wires-net::tenant` for iOS becomes `fabric.rs`. The functions inside it already have vocabulary-neutral names (`register_with_hosted_service`, etc.), so this is a module rename plus three call-site updates.

**Files:**
- Rename: `crates/wires-uniffi/src/tenant.rs` → `crates/wires-uniffi/src/fabric.rs`
- Modify: `crates/wires-uniffi/src/lib.rs`
- Modify: `crates/wires-uniffi/src/app.rs`

- [ ] **Step 1: Rename the file**

```bash
git mv crates/wires-uniffi/src/tenant.rs crates/wires-uniffi/src/fabric.rs
```

- [ ] **Step 2: Update the module's leading doc-comment**

In `crates/wires-uniffi/src/fabric.rs` lines 1-4, currently:
```rust
//! Thin wrappers around `wires-net::tenant` that the iOS app drives.
//! Stateless — each call uses the caller's bound endpoint, registers the
//! host's address hints into the endpoint's address-lookup table, and sends
//! one signed request. Host info reaches these via `parse_host_ticket`
```
Update the first line to:
```rust
//! Fabric-side wrappers around `wires-net::tenant` (the host-internal name
//! for a fabric's host footprint) that the iOS app drives.
```
(The rest of the file's doc-comments stay.)

- [ ] **Step 3: Update `crates/wires-uniffi/src/lib.rs`**

Find the module declaration (look for `pub mod tenant;` or `mod tenant;`) and rename:
```rust
pub mod tenant;
```
Becomes:
```rust
pub mod fabric;
```

- [ ] **Step 4: Update `crates/wires-uniffi/src/app.rs`**

Line 21 currently:
```rust
use crate::tenant as tenant_flow;
```
Becomes:
```rust
use crate::fabric as fabric_flow;
```

Update every subsequent reference to `tenant_flow::` in the file to `fabric_flow::`. (Search the file for `tenant_flow` to catch them all.)

- [ ] **Step 5: Build the crate**

```bash
cargo build -p wires-uniffi
```
Expected: success. If a call site to `tenant_flow::` was missed, the compiler will name the line.

- [ ] **Step 6: Run the UniFFI tests**

```bash
cargo test -p wires-uniffi
```
Expected: all green. The integration test file `crates/wires-uniffi/tests/register_with_host.rs` references `wires_net::tenant::…`, which (per the boundary) stays as-is.

- [ ] **Step 7: Rebuild the Swift xcframework**

The iOS app reads from a pre-built xcframework. After renaming a UniFFI module, regenerate:
```bash
scripts/build-ioskit.sh
```
Expected: successful build. If the script fails because Swift bindings still reference `tenant`, regenerate the bindings as the script does (it shells out to `uniffi-bindgen`).

- [ ] **Step 8: Commit**

```bash
git add crates/wires-uniffi/ Wires/
git commit -m "uniffi: rename tenant module to fabric"
```

(`Wires/` is included because `build-ioskit.sh` regenerates Swift bindings under `Wires/`. Inspect the diff before committing — only generated binding files should appear under `Wires/`.)

---

## Task 5a: Rename the iOS Household SwiftData model to Fabric

The SwiftData `@Model class Household` becomes `class Fabric`. This is a schema-breaking change for any on-device store, which is acceptable: the iOS app has no users and the snapshot harness uses an in-memory store. We migrate by deleting the old class and replacing it with the new one; SwiftData on the dev's simulator will throw a schema-mismatch error on first launch after the rename, and the dev will reset the simulator.

**Files:**
- Rename: `Wires/Wires/Models/Household.swift` → `Wires/Wires/Models/Fabric.swift`

- [ ] **Step 1: Rename the file**

```bash
git mv Wires/Wires/Models/Household.swift Wires/Wires/Models/Fabric.swift
```

- [ ] **Step 2: Update the class declaration and any internal references**

In `Wires/Wires/Models/Fabric.swift`, replace every occurrence of `Household` with `Fabric` and every occurrence of `household` with `fabric`. The file is short (~48 lines). Verify with:

```bash
grep -n "Household\|household" Wires/Wires/Models/Fabric.swift
```
Expected: zero hits after the edit.

- [ ] **Step 3: Build to surface every callsite**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build 2>&1 | tail -40
```
Expected: build fails with compiler errors at every file that references `Household`. These are the call sites the next sub-tasks will fix. Record the list — there should be ~20 files based on the survey.

(No commit here — the next sub-tasks land together with this rename.)

---

## Task 5b: Rename HouseholdClient to FabricClient

`HouseholdClient` is the dependency that wraps SwiftData CRUD on the model. Rename the file, the type, the DependencyKey, and the dependency property accessor.

**Files:**
- Rename: `Wires/Wires/Dependencies/HouseholdClient.swift` → `Wires/Wires/Dependencies/FabricClient.swift`

- [ ] **Step 1: Rename the file**

```bash
git mv Wires/Wires/Dependencies/HouseholdClient.swift Wires/Wires/Dependencies/FabricClient.swift
```

- [ ] **Step 2: Replace identifiers in the file**

In `Wires/Wires/Dependencies/FabricClient.swift`, replace globally:
- `HouseholdClient` → `FabricClient`
- `HouseholdError` → `FabricError`
- `HouseholdStore` → `FabricStore`
- `householdClient` → `fabricClient` (dependency property accessor name)
- `loadHousehold` → `loadFabric`
- `saveHousehold` → `saveFabric`
- `Household` → `Fabric` (type references)
- `household` (variable names, comments) → `fabric`

Verify with:
```bash
grep -n "Household\|household" Wires/Wires/Dependencies/FabricClient.swift
```
Expected: zero hits.

- [ ] **Step 3: Build (will still fail at consumer call sites)**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build 2>&1 | tail -40
```
Expected: build still fails — call sites haven't been updated yet. Continue to Task 5c.

---

## Task 5c: Update Feature files to use the renamed types

Every TCA Feature reducer that touches the `Household` model or the `HouseholdClient` dependency needs its references updated.

**Files (in order of dependency depth, deepest first so each file builds against an updated context):**
- Modify: `Wires/Wires/App/AppFeature.swift`
- Modify: `Wires/Wires/Features/Main/MainFeature.swift`
- Modify: `Wires/Wires/Features/Onboarding/OnboardingFeature.swift`
- Modify: `Wires/Wires/Features/Connect/ConnectFeature.swift`
- Modify: `Wires/Wires/Features/Network/NetworkFeature.swift`
- Modify: `Wires/Wires/Features/Network/ServiceDetailFeature.swift`
- Modify: `Wires/Wires/Features/NodeEnrollment/ApprovalFeature.swift`
- Modify: `Wires/Wires/Features/Settings/SettingsFeature.swift`
- Modify: `Wires/Wires/Models/SignInChallenge.swift`

- [ ] **Step 1: For each file above, replace identifiers**

In each file, replace globally:
- `HouseholdClient` → `FabricClient`
- `HouseholdError` → `FabricError`
- `Household` → `Fabric` (as a type)
- `householdClient` → `fabricClient`
- `loadHousehold` → `loadFabric`
- `saveHousehold` → `saveFabric`
- `household` (variable name, comment) → `fabric`

Use `grep -n "Household\|household" <file>` after editing each to verify zero hits.

- [ ] **Step 2: Build after each file**

After every two or three files, run:
```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build 2>&1 | tail -20
```

It's faster to chip away than to fix every error at the end. The build error count should decrease as each file is updated.

- [ ] **Step 3: Verify a clean build once all Feature files are updated**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build 2>&1 | tail -20
```
Expected: BUILD SUCCEEDED.

If any errors remain, they're in test files (Task 5d) or fixtures (Task 5e); proceed to those.

---

## Task 5d: Rename and update iOS test files

**Files:**
- Rename: `Wires/WiresTests/HouseholdClientTests.swift` → `Wires/WiresTests/FabricClientTests.swift`
- Modify: `Wires/WiresTests/ApprovalFeatureTests.swift`
- Modify: `Wires/WiresTests/ConnectFeatureTests.swift`
- Modify: `Wires/WiresTests/MainFeatureTests.swift`
- Modify: `Wires/WiresTests/NetworkFeatureTests.swift`
- Modify: `Wires/WiresTests/OnboardingFeatureTests.swift`
- Modify: `Wires/WiresTests/SettingsFeatureTests.swift`

- [ ] **Step 1: Rename the test file for FabricClient**

```bash
git mv Wires/WiresTests/HouseholdClientTests.swift Wires/WiresTests/FabricClientTests.swift
```

- [ ] **Step 2: Replace identifiers in every test file**

In each file listed above, apply the same renames as in Task 5c:
- `HouseholdClient` → `FabricClient`
- `HouseholdError` → `FabricError`
- `HouseholdStore` → `FabricStore`
- `Household` → `Fabric`
- `householdClient` → `fabricClient`
- `loadHousehold` → `loadFabric`
- `saveHousehold` → `saveFabric`
- `household` → `fabric`

Also rename test classes/methods if they include `Household`:
- `class HouseholdClientTests` → `class FabricClientTests`
- `func test_loadHousehold_…` → `func test_loadFabric_…`
- `func test_saveHousehold_…` → `func test_saveFabric_…`

After each edit:
```bash
grep -n "Household\|household" <file>
```
Expected: zero hits.

- [ ] **Step 3: Build the test target**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build-for-testing 2>&1 | tail -20
```
Expected: BUILD SUCCEEDED.

- [ ] **Step 4: Run the unit tests**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' test \
    -only-testing:WiresTests 2>&1 | tail -30
```
Expected: TEST SUCCEEDED, every previously-passing test still passing. No new tests; this is a rename refactor.

---

## Task 5e: Rename and update iOS fixtures

The snapshot harness uses fixture files to seed dependency state. The fixture for `HouseholdClient` is renamed; `LaunchFixture` references the renamed type.

**Files:**
- Rename: `Wires/Wires/Fixtures/Fixtures+Household.swift` → `Wires/Wires/Fixtures/Fixtures+Fabric.swift`
- Modify: `Wires/Wires/Fixtures/LaunchFixture.swift`
- Modify: `Wires/Wires/Fixtures/Fixtures+Wires.swift` (verify no residual `Household` references)

- [ ] **Step 1: Rename the fixture file**

```bash
git mv Wires/Wires/Fixtures/Fixtures+Household.swift Wires/Wires/Fixtures/Fixtures+Fabric.swift
```

- [ ] **Step 2: Replace identifiers**

In `Wires/Wires/Fixtures/Fixtures+Fabric.swift`:
- `HouseholdClient` → `FabricClient`
- `Household` → `Fabric`
- `household` → `fabric`
- `HouseholdClient.fixture(` → `FabricClient.fixture(`

In `Wires/Wires/Fixtures/LaunchFixture.swift`:
- Same global replace.
- `HouseholdClient.fixture(…)` call sites become `FabricClient.fixture(…)`.

Verify each:
```bash
grep -n "Household\|household" Wires/Wires/Fixtures/Fixtures+Fabric.swift Wires/Wires/Fixtures/LaunchFixture.swift
```
Expected: zero hits.

- [ ] **Step 3: Build and test**

```bash
xcodebuild -project Wires/Wires.xcodeproj -scheme Wires \
    -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build-for-testing 2>&1 | tail -20
```
Expected: BUILD SUCCEEDED.

- [ ] **Step 4: Final scan for residual references**

```bash
grep -rn "Household\|household" Wires/ --include="*.swift"
```
Expected: zero hits across the entire iOS source tree.

- [ ] **Step 5: Commit the iOS-side rename as a single coherent change**

```bash
git add Wires/
git commit -m "ios: rename Household to Fabric throughout app, tests, and fixtures"
```

---

## Task 6: Re-run the iOS snapshot sweep

The renames in Task 5 changed type names, not view structure, so the rendered UI should be pixel-identical to before — unless a view label explicitly read "Household" / "household." If any did, those labels now read "Fabric" / "fabric" and the snapshot diff catches them.

**Files:**
- Generated: `Wires/screenshots/<run-id>/` (gitignored)

- [ ] **Step 1: Confirm the simulator exists**

```bash
xcrun simctl list devices | grep "iPhone 17 Pro"
```
Expected: an `iPhone 17 Pro` device running iOS 26.x. If missing, create one:
```bash
xcrun simctl create "iPhone 17 Pro - 26.4" \
  "com.apple.CoreSimulator.SimDeviceType.iPhone-17-Pro" \
  "com.apple.CoreSimulator.SimRuntime.iOS-26-4"
```

- [ ] **Step 2: Run the full snapshot sweep**

```bash
./scripts/snapshot-ios.sh
```
Expected: 26 fixtures × 2 appearances = 52 PNGs written to `Wires/screenshots/<run-id>/`. Run time ~6 minutes.

- [ ] **Step 3: Spot-check screens that historically said "Household"**

If any UI string explicitly read "Household" in onboarding, network, service, settings, or connect flows, those screens will now read "Fabric." Visually compare against the previous baseline (the user keeps curated baselines in `docs/ui-baselines/` per CLAUDE.md). Suggested screens to inspect:
- `Wires/screenshots/latest/onboarding/welcome-light.png`
- `Wires/screenshots/latest/onboarding/done-light.png`
- `Wires/screenshots/latest/network/empty-light.png`
- `Wires/screenshots/latest/settings/root-light.png`

If a string change looks wrong (e.g. an awkward grammar shift), fix it in the Swift source and re-run the relevant fixture only:
```bash
./scripts/snapshot-ios.sh --fixture <fixture_name>
```

- [ ] **Step 4: Commit any string adjustments separately**

```bash
git add Wires/
git commit -m "ios: tighten copy after Household → Fabric rename"
```
(Skip this commit if no string adjustments were needed.)

---

## Task 7: Update the README

The README has user-facing prose using "household" and "tenant." Align with the boundary.

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the tagline**

Line 3 currently:
```markdown
End-to-end encrypted gossip substrate for a household's AI agents. Think "a private group chat that machines can read and write to, hosted by a server that cannot."
```
Becomes:
```markdown
End-to-end encrypted gossip substrate for a fabric — your network of agents, services, and devices, rooted in your identity. Think "a private group chat that machines can read and write to, hosted by a server that cannot."
```

- [ ] **Step 2: Update the "Concepts" section**

Around line 39:
```markdown
- **Tenant.** A household paired with a host. Created via the `/wires/tenant/0` ALPN, signed by the root key. One tenant per root pubkey per host.
```
Becomes:
```markdown
- **Fabric.** The unit of organization rooted in one human: identity, all paired agents/services, and the channels they share. The host calls this a "tenant" internally (the ALPN is `/wires/tenant/0`, the on-disk path is `tenants/<root>/`) — same thing, different layer.
```

- [ ] **Step 3: Update walkthrough prose**

Search for remaining "household" mentions in the README walkthrough:
```bash
grep -n "household" README.md
```

For each hit, decide:
- If it's user-facing prose ("Alice is the root-key holder for this household"), replace with "fabric."
- If it's referencing tenant on-disk paths or the `/wires/tenant/0` ALPN, leave the "tenant" reference but reword surrounding prose to make clear the relationship.

Lines to specifically update (current → target):
- Line 35: `Every agent has an Ed25519 signing key…The root key for a household is a separate Ed25519 keypair` → `…The root key for a fabric is a separate Ed25519 keypair`
- Line 52: "Alice is the root-key holder for this household." → "Alice is the root-key holder for this fabric."

- [ ] **Step 4: Verify no remaining user-facing "household" references**

```bash
grep -n "household" README.md
```
Expected: zero hits. (Tenant references in the host data-dir layout stay; they describe on-disk format.)

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "readme: replace household with fabric, clarify tenant boundary"
```

---

## Task 8: Update CLAUDE.md crate descriptions

The CLAUDE.md "Crate layout" table and a few status-section sentences still use "household." Bring them in line.

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update Status section**

Search for "household" in `CLAUDE.md`:
```bash
grep -n "household" CLAUDE.md
```

For each hit in the "Status" section ("MCP gateway joins each household as a normal wires agent" etc.), replace "household" → "fabric."

- [ ] **Step 2: Update the "wires-mcp" crate description**

The crate table description should read:
> Authenticated MCP gateway. Holds one wires-agent data dir per OAuth user (fabric: `users/<root>/`) plus a small `gateway.redb`…

Adjust the actual current wording to use "fabric" where the existing text says "household."

- [ ] **Step 3: Verify no user-developer-facing "household" mentions remain in CLAUDE.md**

```bash
grep -n "household" CLAUDE.md
```
Expected: zero hits, unless one is inside the new vocabulary section that explicitly explains the retired term — that one stays as documentation.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "claude.md: align crate descriptions with fabric vocabulary"
```

---

## Task 9: Final verification sweep

A whole-repo grep to catch anything missed.

- [ ] **Step 1: Verify "household" only appears in expected places**

```bash
grep -rn "household\|Household" \
  --include="*.rs" --include="*.swift" --include="*.md" \
  --include="*.toml" \
  | grep -v "docs/superpowers/specs/" \
  | grep -v "docs/superpowers/plans/" \
  | grep -v "CLAUDE.md.*Vocabulary boundary"
```
Expected: zero hits. The exclusions are:
- Historical specs and plans (which describe past work and are not retroactively rewritten).
- The CLAUDE.md vocabulary section that explicitly documents the retired "household" term.

- [ ] **Step 2: Verify "tenant" only appears in expected places**

```bash
grep -rn "tenant\|Tenant" \
  --include="*.rs" --include="*.swift" \
  | grep -v "wires-host/" \
  | grep -v "wires-net/src/tenant.rs" \
  | grep -v "wires-net/src/error.rs" \
  | grep -v "wires-store/src/" \
  | grep -v "wires-mcp/src/tenants.rs" \
  | grep -v "wires-mcp/src/http.rs.*TenantSupervisor" \
  | grep -v "wires-mcp/src/main.rs.*TenantSupervisor"
```

Inspect each remaining hit. Anything user-facing or in a doc-comment should already be "fabric." Anything that says `wires_net::tenant::*` (imports, type references like `TenantClient`, `TenantResponse`, `TenantErrorCode`) stays — it's the wire-format protocol module name.

Expected outcome: every remaining `tenant` mention is either an import of the protocol module, a reference to an internal type in `wires-host` / `wires-mcp`'s supervisor, or an explicit explanation of the boundary. None should be a user-facing string or a stale doc-comment.

- [ ] **Step 3: Run the full Rust workspace test suite**

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```
Expected: green across the board.

- [ ] **Step 4: Re-run iOS snapshot sweep one more time**

```bash
./scripts/snapshot-ios.sh
```
Expected: 52 PNGs, no errors. Visually spot-check a handful to confirm no rendering regression.

- [ ] **Step 5: Final commit / tag**

If Steps 1-4 surfaced any cleanup edits, commit them:
```bash
git add -A
git commit -m "vocabulary: final pass after fabric consolidation"
```

If everything is already committed, this task is just verification — no new commit needed.

---

## Self-Review notes

- **Spec coverage:** Plan covers the three artifacts that needed renaming: Rust user-facing strings (Task 2-3), UniFFI bridge (Task 4), iOS app + tests + fixtures (Task 5a-e + 6), and the two documentation surfaces (Task 7-8). The vocabulary boundary is locked in Task 1 and re-verified in Task 9.
- **Wire-format compat:** Plan leaves `/wires/tenant/0` ALPN, `tenants.redb` table name, `tenants/<root>/` on-disk path, all `TenantRecord`/`TenantClient`/`TenantResponse` types, and `wires-mcp::tenants::TenantSupervisor` untouched. No protocol break.
- **iOS schema break:** Task 5a notes the SwiftData rename invalidates on-device stores. Acceptable because there are no users and snapshot fixtures use in-memory containers.
- **Test discipline:** No new tests written. Existing tests verify the rename. Test renames in Task 5d mirror the production renames (e.g., `test_loadHousehold_…` → `test_loadFabric_…`); test bodies are unchanged.
- **Frequent commits:** Each task produces one commit (Tasks 2, 3, 4, 5 [single coherent iOS commit], 6, 7, 8, optionally 9), so the rename is bisectable.
