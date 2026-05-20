# Wires iOS — HIG-aligned redesign

**Status:** design • **Created:** 2026-05-19 • **Authors:** Aaron + Claude (brainstorming session)

A from-the-studs visual and information-architecture redesign of the Wires iOS app, optimized to feel like a calm sibling of Apple Passwords and to read as a personal trust network owned by a single user. The goal is a foundation we can grow into the agent-chat product without re-doing the chrome.

This spec supersedes the visual decisions in `2026-05-14-wires-ios-companion-design.md` (which was authored before the hosted-service and OAuth flows landed, and still describes the dropped `HostPairToken` shape). The cap/topic/pair/sign-in mechanics from the substrate, hosted-service, responder-driven-pairing, and MCP-gateway specs are unchanged and remain authoritative for the wire and FFI surfaces.

## 1. Goals

- **Apple-grade first impression.** A user opening the app for the first time should feel they're using something Apple could have shipped — not a developer tool, not a crypto wallet.
- **Plain language end to end.** No "node", "cap", "topic", "endpoint", "addrs", "root pubkey", "tenant", "host", "gateway", or hex on any screen the user is asked to act on.
- **The user is the root of trust, visually.** Onboarding and the connect ceremony should make it obvious that this iPhone is what gates every approval; Face ID is the seal.
- **A foundation that adapts.** Caps, channels, and scope semantics are a moving target. Views render through generic `ScopeDescriptor` values, never `CapRecord` directly, so a schema change is a mapper change in one file.
- **Snapshot-driven.** Every new state has a fixture, light and dark, covered by `scripts/snapshot-ios.sh`. We never regress the visual contract silently.

## 2. Non-goals

- Multi-device or multi-account UX (one iPhone = one account; iCloud Keychain restore is a future spec).
- Household/multi-user sharing. The product is for an individual; "household" comes back later as a separate design.
- Brand logos for real-world services (Chase, PG&E, etc.). We use categorical SF Symbols only — no registry, no fetching, no hosting.
- Channels/conversations UI. The tab bar reserves room for a third tab; designing that tab is out of scope here.
- Verification-code / fingerprint comparison ceremonies. The user owns both ends of every ceremony; cross-verification is security theater for this threat model.
- FFI redesign. The existing `WiresKit` surface stays; one small additive change to `HostTicket` is the only protocol-level touch.

## 3. Design principles

These survive the cap/channel schema churn and govern all future iOS work in this codebase.

1. **The iPhone is the account.** No "sign in", no "sign out", no "log out". The Welcome screen leads only to setup; the Settings tab's destructive footer leads only to permanent deletion.
2. **"Set up", never "sign up".** The user is creating something irreplaceable on this device; Apple's "Set up Apple Pay" / "Set up AirPods" framing fits exactly. The server registers a tenant under the hood, but the user's mental model is *this device*.
3. **Honest framing about the server.** We never say "Wires is your default account host" because the canonical Wires instance isn't built into the app yet. We say "Scan the setup code for the Wires server you want to use." Self-hosting and managed-hosting look identical to the user because they *are* identical in v1.
4. **Trust comes from possession plus Face ID, not from cryptographic display.** No verification codes, no fingerprint comparison, no key material on the trust-approval screen. The user already approved by scanning; Face ID gates the final tap.
5. **Views are scope-shape-agnostic.** Approval and detail screens render `[ScopeDescriptor]` values; `CapRecord` is mapped to descriptors in one place. When the cap shape changes, the mapper changes; views don't.
6. **One brand glyph, categorical SF Symbols for everything else.** No custom artwork beyond the wire-key glyph; no per-service brand assets.
7. **Errors are inline and recoverable.** No system alerts for flow failures. Every error has a clear next action ("Try again", "Choose a different server", "Scan again").
8. **Hex is hidden, not removed.** Every screen has an Advanced disclosure for users who want to see the underlying identifiers; default surfaces never show them.

## 4. Visual system

**Color.**
- Single accent: `indigoPrimary` — a slightly cooler purple than system `.indigo`, calibrated to read as a sibling of Passwords (deep, security-coded purple). Defined in an `Asset` catalog with light/dark variants.
- Status colors: system semantic only.
  - `.green` — connected, healthy, success
  - `.orange` — pending, attention
  - `.red` — revoked, error, destructive
  - `.gray` — disconnected, inert
- Backgrounds: `Color(.systemGroupedBackground)` for grouped surfaces; `.background(.regularMaterial, in: .rect(cornerRadius: 16))` for content cards on grouped backgrounds.

**Surfaces (Liquid Glass, iOS 26).**
- Toolbars: default iOS 26 glass styling — no overrides.
- Sheets: `.presentationBackground(.glass)` on every sheet that's not full-screen-cover.
- Sticky-bottom primary actions: `.buttonStyle(.glassProminent).tint(indigoPrimary)`.
- Secondary actions on the same screen: `.buttonStyle(.glass)` (or `.bordered` if the iOS 26 alternative looks wrong in context — decided per-screen during implementation).

**Typography.**
- SF Pro via system text styles only. No custom point sizes.
- Screen title: `.largeTitle.bold()`
- Section header: `.subheadline.foregroundStyle(.secondary)` with `.textCase(nil)` (mixed case, not all-caps)
- Row primary: `.body`
- Row secondary / caption: `.subheadline.foregroundStyle(.secondary)`
- Monospaced: only inside the Advanced disclosure, never on a primary surface.

**Glyph library.**
- One brand glyph: a vector wire-key motif (two crossing wires forming a stylized key), indigo-tinted, animatable (used in Welcome with a draw-in transition). Lives as a custom SwiftUI `Shape` or imported SVG.
- Per-service categorical SF Symbols, mapped from a `ServiceCategory` enum:
  - `.banking` → `creditcard.fill`
  - `.utilities` → `bolt.fill`
  - `.smartHome` → `house.fill`
  - `.devTool` → `terminal.fill`
  - `.unknown` → `questionmark.app.dashed`
  - (expand as needed; safe fallback is `.unknown`)
- All other UI controls: system SF Symbols.

**Motion.** Default SwiftUI transitions only. One exception: the Welcome glyph has a ~2s draw-in animation on first launch (subsequent launches: instant).

**Spacing.** Standard iOS rhythm — 16pt page margins, 12pt between sections, 8pt within cards. Don't invent a custom scale.

## 5. Information architecture

### Tab structure

Two tabs today, three later.

| Tab | Status | Stack root |
|---|---|---|
| Network | v1 | Service list → service detail |
| Settings | v1 | Grouped Form |
| Conversations | future | (not designed here) |

Adopting `TabView` now means the future Conversations tab is purely additive.

### Top-level TCA state

```
AppFeature.State =
    .launching                          // existing — keychain + WiresClient bootstrap
  | .onboarding(OnboardingFeature.State)// replaces current BootstrapFeature
  | .main(MainFeature.State)            // wraps TabView with Network + Settings
```

`MainFeature` composes `NetworkFeature` (existing `HomeFeature`, renamed) and `SettingsFeature` (new), each scoped through `TabView`. The state name avoids "signed in" so that even internal TCA vocabulary stays aligned with Principle 1 — there is no sign-in concept in this app.

The `OAuthSignInFeature` (single-QR consent dispatch) is presented as a full-screen sheet from `NetworkFeature` — same as today, with the visual treatment from §8.

### State transitions

- First launch → `.launching` → keychain has no root → `.onboarding`
- Subsequent launches → `.launching` → keychain has root → `.signedIn`
- "Delete account" in Settings → wipe keychain + SwiftData → `.launching` → `.onboarding`
- No `.signedOut` intermediate state exists. There is no logout.

## 6. Surfaces

### 6.1 Onboarding (5 screens)

`OnboardingFeature` replaces `BootstrapFeature`. Each step is one screen; back navigation is allowed up to Step 3.

**Step 1 — Welcome.**
- Indigo wire-key glyph, centered, animated draw-in
- Title: *Wires*
- Subtitle: *A private network for the apps and services in your life.*
- Sticky-bottom button: `Get started` (`.glassProminent`)
- No sign-in link, no skip path

**Step 2 — Scan setup code.**
- Full-screen scanner: corner-bracketed reticle, dimmed exterior (mirrors iOS Camera scan UX)
- Above the reticle: title *Set up your Wires* + subtitle *Scan the setup code for the Wires server you want to use.*
- Top-left: `Cancel`. Top-right: torch toggle.
- Bottom: `Paste code` pill (opens a sheet with a `TextEditor` and `Use code` action)
- Reserved layout room above the reticle for a future `Use Wires` card (DNS-TXT-discovery default), which slots in *above* the scanner with no other layout changes.

**Step 3 — Confirm server.**
- Card showing server glyph + server name + server URL + permanence paragraph: *Your Wires account will live here. You can't move it to a different server later, so make sure you trust this one.*
- Two buttons stacked: `Set up account here` (glassProminent, indigo) and `Choose a different server` (plain, secondary)
- Server name comes from a new optional `server_name: Option<String>` field added to `HostTicket` (§9). Fallback: URL host.

**Step 4 — Set up Face ID.**
- `faceid` SF Symbol, large, indigo-tinted
- Title: *Protect your account with Face ID*
- Body: *Your account key lives on this iPhone. Face ID makes sure only you can use it — and protects it if you lose your phone.*
- Buttons: `Set up Face ID` (glassProminent, triggers `LAContext.evaluatePolicy`) and `Set up later` (plain). "Later" stores the keychain item with non-biometric ACL and marks a Settings prompt.

**Step 5 — Done.**
- Green seal checkmark
- Title: *You're set up*
- Subtitle: *Add a service to start using your network.*
- Single button: `Continue` → drops into Network tab

**Errors.** Each step has inline-banner errors with a clear next action. No system alerts. Step 2's parse failure shows *Couldn't read this code — try again.* with `Scan again`. Step 3's network failure shows *Couldn't reach this server.* with `Try again` and `Choose a different server`.

### 6.2 Network tab — service list

The Network tab's stack root. Grouped list, single visible section today (`Connected`); additional sections (`Recently disconnected`, `Pending approval`) appear only when non-empty.

**Row anatomy.**
- Leading: 36pt indigo circle, white categorical SF Symbol
- Primary: service name
- Secondary: *on [device name]* (the device the agent declared at setup time)
- Trailing: `StatusPill` (green dot / gray / red / yellow)
- Chevron, tap → detail

**Empty state.** Indigo wire-key glyph, *No services yet*, *Tap + to add a service to your network.*

**Toolbar.** `+` (glassProminent) — opens connect-ceremony sheet. No filter, no search.

**Swipe actions.** Trailing swipe → `Disconnect` (destructive). Long-press → same destructive prompt (accessibility).

**Pull-to-refresh.** Triggers an FFI cap re-fetch. SwiftData is read-through; refresh updates the source-of-truth.

### 6.3 Service detail

Pushed onto the Network stack. `ScrollView` + `LazyVStack` — not `Form`, so the identity header and destructive footer can be shaped freely.

**Identity header (full-width, no card).**
- 80pt indigo circle, white categorical SF Symbol, centered
- Service name (`.title.bold()`)
- *on [device name]* (`.subheadline.secondary`)
- `StatusPill` below

**About (grouped card).**
- Description row — whatever the agent declared at install time
- Connected on — relative date
- Last activity — relative date if the gateway exposes it; row omitted if not

**What it can do (grouped card).**
- A list of `ScopeRow` components, rendered from `[ScopeDescriptor]`. Each row's collapsed view shows label + summary; tap-expand reveals detail. View is scope-shape-agnostic.

**Advanced (grouped card, collapsed behind a disclosure).**
- Agent key fingerprint (hex, monospaced, long-press to copy)
- Server URL
- Cap ID (hex)

**Destructive footer.**
- `Disconnect [service name]` — red text, no decoration (iOS Settings-style)
- Tap → confirm sheet: *Disconnect [service] from your network?* with `Disconnect` (destructive) / `Cancel`
- On confirm: revoke via FFI, pop to list, row reappears in `Recently disconnected`

**Revoked variant.** Destructive footer becomes `Reconnect…` — routes to the connect ceremony pre-filled with the prior service's identity. Mechanically: re-run the pair flow; the prior cap stays revoked, a fresh cap is minted.

### 6.4 Connect-a-service ceremony

Full-screen sheet presented from the Network tab's `+` action. Mirrors today's `OAuthSignInFeature` state machine, polished. The single-QR consent dispatch (scan → gateway probe → branch to sign-in or pair-approve) is preserved exactly as documented in `2026-05-18-wires-mcp-gateway-design.md`.

**State machine.**
```
.scan → .probing → .signinConfirm | .pairApprove → .done
                                                 ↘ .error(parse | network | alreadyConnected)
```

**Step 1 — Scan.** Same scanner shell as onboarding Step 2. Title: *Add a service*. Subtitle: *Scan the code shown by the service you want to connect.*

**Step 2 — Probing.** Indigo wire-key glyph at 40% opacity with a soft `ProgressView`, *Checking with your server…* Upgrades copy at 2s, reveals a `Cancel` at 5s. Replaces both the current `probing` and `pairLoading` distinct states with a single screen.

**Step 3a — Sign-in confirm** (returning device).
- `faceid` SF Symbol header
- Title: *Sign in to your account?*
- Card: server name + URL
- Sticky-bottom: `Sign in with Face ID` (glassProminent, triggers `LAContext` on tap — no extra confirm)

**Step 3b — Approve service** (new agent — the high-stakes screen).
- **Header** (above the form): `ServiceIdentityHeader` (same component used on Service Detail) — 64pt indigo circle, service name, *on [device name]*
- **About this service** (grouped card): generic key/value rows from the agent's declaration (Role, Description)
- **Access** (grouped card): `[ScopeRow]` driven by `[ScopeDescriptor]`. Each row is collapsed by default with a primary toggle and a summary line; tap-expand reveals individual rights. Healthy default: approve as-requested.
- **Sticky bottom**: `Approve with Face ID` (glassProminent, indigo). Tap triggers Face ID immediately. Secondary `Cancel` above.

**Step 4 — Done.** Green seal checkmark, *Connected*, *[Service name] is now on your network.*, single `Done` button. Returns to Network with the new row briefly highlighted (`.transition(.slide.combined(with: .opacity))`).

**Step 5 — Errors.** Three inline-screen failure modes — `Couldn't read code`, `Couldn't reach server`, `Already connected` (green check, *View [service]* / *Done*). Never system alerts.

### 6.5 Settings tab

Grouped `Form` with a custom identity-card header and a permanence-coded destructive footer.

**Header (above the Form).**
- 56pt indigo circle, brand glyph
- Primary: *Your Wires*
- Secondary: server name
- Chevron → detail sheet with the same info plus an Advanced disclosure (root pubkey hex, long-press to copy)

**Security section.**
- `Face ID protection` — `Toggle`. Off-state shows a yellow attention dot. Toggling triggers `LAContext` and rewrites keychain ACL.
- Future row reserved for iCloud Keychain restore.

**Server section.**
- Server name (read-only)
- Server URL (read-only)
- Caption below the section: *Your account lives on this server. You can't move it to a different server.*

**About section.**
- Version
- Acknowledgments

**Destructive footer (outside the Form).**
- `Delete account` — red text, iOS Settings style
- Tap → full-screen sheet:
  - Title: *Delete your account?*
  - Body: *Your account key will be erased from this iPhone. Every service in your network will lose access. This can't be undone.*
  - Type-to-confirm field: *Type 'delete' to confirm*
  - `Delete account` (red, destructive, disabled until field matches)
  - `Cancel`
- On confirm: wipe keychain, wipe SwiftData, route through existing `appFeature.didReset` → `.launching` → onboarding

The current `#if DEBUG`-only "Reset household" toolbar button is retired.

## 7. Components and types

### Display types

```swift
// View-layer summary, derived from CapRecord by a mapper in the data layer.
struct ServiceSummary: Equatable, Identifiable, Sendable {
    let id: String              // stable id (today: capIdHex)
    let name: String            // user-visible name
    let deviceName: String?     // "on Aaron's Mac mini"
    let category: ServiceCategory
    let status: ServiceStatus
    let scopes: [ScopeDescriptor]
    let connectedAt: Date
    let lastActivityAt: Date?
}

enum ServiceCategory: Equatable, Sendable {
    case banking, utilities, smartHome, devTool, unknown
    // extends as new categories are recognized
}

enum ServiceStatus: Equatable, Sendable {
    case connected, pending, disconnected, revoked
}

// Generic scope rendering — the load-bearing hedge against cap-shape churn.
struct ScopeDescriptor: Equatable, Hashable, Sendable {
    let id: String              // stable id for SwiftUI ForEach
    let label: String           // primary text — e.g. a topic name
    let summary: String         // one-line collapsed-state summary — e.g. "Read messages · Send messages"
    let detail: [ScopeDetailRow]// optional expanded rows
}

struct ScopeDetailRow: Equatable, Hashable, Sendable {
    let label: String
    let granted: Bool
    let kind: ScopeRightKind    // open-coded today; evolves
}

enum ScopeRightKind: Equatable, Hashable, Sendable {
    case read, write, grant, custom(String)
}
```

`CapRecord → ServiceSummary` mapping lives in a single file (`Wires/Wires/Mappers/CapToServiceMapper.swift`, new). Views never import `CapRecord`. When the cap shape changes, this file changes; views don't.

### Reusable views

- `WiresBrandGlyph` — the animated indigo wire-key vector. Variants: `.static`, `.drawIn(duration:)`.
- `ServiceIdentityHeader(summary:)` — used on Service Detail, Connect-Approve, and (smaller) Settings header. Single source of truth for "this is what a service looks like".
- `ServiceListRow(summary:)` — grouped-list row.
- `ScopeRow(descriptor: Binding<ScopeDescriptor>, editable: Bool)` — expandable scope row. `editable: true` on Connect-Approve, `false` on Service Detail. The collapsed state's primary toggle reflects "all detail rows granted" and toggles them in lockstep; the expanded state exposes per-row toggles. When `editable: false`, the row renders read-only with whatever state the descriptor reports.
- `StatusPill(status:)` — green/gray/red/yellow chip with optional text.
- `OnboardingScaffold(step:title:subtitle:content:primary:secondary:)` — shared chrome for all 5 onboarding steps; ensures visual consistency and shared back-navigation behavior.
- `InlineErrorBanner(message:primaryAction:secondaryAction:)` — used everywhere errors render inline.
- `DestructiveFooterButton(title:onTap:)` — the iOS Settings-style red-text destructive affordance.
- `AdvancedDisclosure { rows }` — labeled `DisclosureGroup` styled to match the rest of the design.

### TCA features

- `OnboardingFeature` — replaces `BootstrapFeature`. State carries a step + per-step sub-state. Child reducers: `ScanFeature` (existing, reused).
- `NetworkFeature` — renamed from `HomeFeature`. State carries `[ServiceSummary]` + loading/error.
- `ServiceDetailFeature` — new; child of NetworkFeature via NavigationStack path.
- `SettingsFeature` — new; child of `MainFeature`.
- `MainFeature` — new; composes `NetworkFeature` + `SettingsFeature` with TabView.
- `ConnectFeature` — renamed from `OAuthSignInFeature`. Behavior unchanged; visual treatment is the rewrite. Child reducers: `ScanFeature`, `ApprovalFeature` (existing, reused with view changes).

## 8. Trust ceremony principles

These are codified here so they don't drift across reviews:

- **No verification codes anywhere.** The user owns both ends of every ceremony. Hex is hidden behind an Advanced disclosure only.
- **Face ID is on the primary action, not a separate step.** Apple Pay's "double-click → Face ID → done" rhythm; we do "tap Approve → Face ID → done."
- **Service description is operator-set, displayed verbatim.** We don't verify, prettify, or annotate it. Whitespace-trim only.
- **No app-side service registry.** No favicon fetches, no brand logos, no allow-list. The agent declares its category; we render the SF Symbol.
- **Errors never leak plumbing.** "gateway returned 500" becomes *Couldn't reach your server. Check your connection and try again.* The HTTP status lives in the Advanced disclosure if anywhere.

## 9. FFI / protocol changes

Only one change required outside the iOS app:

- **`HostTicket` gains an optional `server_name: Option<String>` field.** Populated by the operator when generating the ticket on the host side. Onboarding Step 3 displays this verbatim, falling back to the URL host when absent. Adding the field is backward-compatible because all existing tickets omit it.

Everything else — pair flow, OAuth flow, cap mint/revoke, replay, ingest — is unchanged.

## 10. Snapshot harness updates

The redesign adds these fixtures to `Wires/Wires/Fixtures/LaunchFixture.swift`. Each gets a `SnapshotSweep` test method. Old fixtures (`bootstrap_*`, `home_*`, `oauth_*`) are replaced in-place, not deleted before their replacements land.

**Onboarding (replaces `bootstrap_*`):**
- `onboarding_welcome`
- `onboarding_scan`
- `onboarding_scan_error`
- `onboarding_confirm`
- `onboarding_face_id`
- `onboarding_done`

**Network (replaces `home_*`):**
- `network_empty`
- `network_loading`
- `network_one_service`
- `network_three_services_one_revoked`
- `network_load_error`

**Service detail (new):**
- `service_detail_connected`
- `service_detail_revoked`
- `service_detail_advanced_expanded`

**Connect ceremony (replaces `oauth_*`):**
- `connect_scan`
- `connect_probing`
- `connect_signin_confirm`
- `connect_approve_collapsed`
- `connect_approve_expanded`
- `connect_done`
- `connect_error_parse`
- `connect_error_network`
- `connect_already_connected`

**Settings (new):**
- `settings_root`
- `settings_face_id_off`
- `settings_account_detail`
- `settings_delete_confirm`

Final count: ~24 fixtures × light/dark = ~48 PNGs. `LaunchFixtureTests.allCases.count` updates accordingly.

## 11. Implementation strategy (preview)

The full plan will be written in `docs/superpowers/plans/2026-05-19-wires-ios-hig-redesign.md` after this spec is approved. Phasing preview:

1. **Foundation** — color asset, brand glyph, `ServiceSummary` / `ScopeDescriptor` types, mapper from `CapRecord`, `StatusPill`, `OnboardingScaffold`, `ServiceIdentityHeader`. Tests but no UI changes yet.
2. **Onboarding rewrite** — `OnboardingFeature` replaces `BootstrapFeature`; routes through `AppFeature`. New snapshot fixtures land; old `bootstrap_*` fixtures retire.
3. **Network tab rewrite** — `NetworkFeature` rename + service-list rewrite + service-detail page. Old `home_*` fixtures retire.
4. **Connect ceremony rewrite** — `ConnectFeature` rename + visual upgrade. Old `oauth_*` fixtures retire.
5. **Settings tab** — new `SettingsFeature` + `MainFeature` + TabView at AppFeature root. Settings fixtures land.
6. **FFI: `HostTicket.server_name`** — additive change to `wires-core` + `wires-net::ticket`, exposed through `WiresKit`. Wired into onboarding Step 3.

Each phase keeps the snapshot harness green at every merge.

## 12. Out of scope / deferred

- **iCloud Keychain restore.** The single biggest "we should ship that next" item. Spec deferred. Welcome screen reserves layout for the future `Restore from backup` link.
- **Multi-device.** Pairing a second iPhone to the same account. Hard problem — needs key-share ceremony or iCloud Keychain restore. Out of scope.
- **Conversations / agent-chat tab.** Reserved tab slot, no design.
- **DNS-TXT discovery of a canonical Wires instance.** Reserved layout room above the onboarding scanner; no design.
- **Service categories registry.** We ship with ~5 categories; expansion is incremental as new agent types emerge. Not a v1 design problem.
- **Search and filtering on Network.** YAGNI at current scale.
- **Per-service activity feed.** Service Detail's "Last activity" row is optional in v1 (depends on gateway exposing the timestamp); a real per-service log is out of scope.
- **Verification of operator-set descriptions.** Out of scope; we trust what the agent declares.

## 13. Open questions

These were intentionally not resolved during brainstorming because they're best decided during implementation:

- **Exact wire-key glyph design.** A few options to mock once implementation starts; the spec only constrains "indigo, two-wire-as-key, animatable."
- **Exact indigo hue.** Calibrated against Passwords' purple during implementation; the spec calls it `indigoPrimary` and leaves the precise hex to the Asset catalog.
- **Onboarding back navigation specifics.** Whether Step 4 (Face ID) allows back navigation to Step 3 (Confirm server) after a successful keychain write is a small open question; spec leans toward "no, account creation is committed at Step 3 → 4 transition" but implementation may discover a reason to soften it.
- **Whether `ScopeRow`'s expanded view is editable in Service Detail.** Currently spec'd as non-editable. If a future cap shape needs per-scope toggle in detail, we lift the `editable: Bool` parameter to true there.

## 14. References

- `docs/superpowers/specs/2026-05-14-wires-substrate-design.md` — load-bearing on cap semantics, message kinds, AAD construction
- `docs/superpowers/specs/2026-05-14-wires-hosted-service-design.md` — tenant registration model, server blindness contract
- `docs/superpowers/specs/2026-05-15-wires-responder-driven-pairing-design.md` — pair flow, `PairGrant` shape
- `docs/superpowers/specs/2026-05-18-wires-mcp-gateway-design.md` — single-QR consent dispatch
- `docs/superpowers/specs/2026-05-19-wires-ios-snapshot-tooling-design.md` — fixture pattern, runner script
- `docs/superpowers/specs/2026-05-14-wires-ios-companion-design.md` — superseded for visual decisions; preserved for historical context
