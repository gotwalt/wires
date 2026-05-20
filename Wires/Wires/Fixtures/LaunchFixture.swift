import ComposableArchitecture
import Dependencies
import Foundation
import WiresKit

/// Every notable UI state of the app, identified by a stable string the
/// snapshot test target writes into `WIRES_FIXTURE` at launch.
///
/// Adding a fixture:
///   1. Add an enum case + raw value here.
///   2. Add an arm to `applyDependencies(to:)` setting the dependencies
///      the seeded screen relies on.
///   3. Add an arm to `initialAppState` returning the AppFeature.State
///      the app should land in.
///   4. Add a test method in WiresUITests/SnapshotSweep.swift.
///   5. Update the count assertion in WiresTests/LaunchFixtureTests.swift.
enum LaunchFixture: String, CaseIterable {
    case onboardingWelcome          = "onboarding_welcome"
    case onboardingScan             = "onboarding_scan"
    case onboardingScanError        = "onboarding_scan_error"
    case onboardingConfirm          = "onboarding_confirm"
    case onboardingFaceID           = "onboarding_face_id"
    case onboardingDone             = "onboarding_done"
    case homeLoading                = "home_loading"
    case homeEmpty                  = "home_empty"
    case homeOneCap                 = "home_one_cap"
    case homeThreeCapsOneRevoked    = "home_three_caps_one_revoked"
    case oauthScan                  = "oauth_scan"
    case oauthSigninConfirm         = "oauth_signin_confirm"
    case oauthPairApprove           = "oauth_pair_approve"
    case oauthPairApprovePartial    = "oauth_pair_approve_partial"
    case oauthDone                  = "oauth_done"
    case oauthError                 = "oauth_error"
    case settingsRoot               = "settings_root"
    case settingsFaceIDOff          = "settings_face_id_off"
    case settingsAccountDetail      = "settings_account_detail"
    case settingsDeleteConfirm      = "settings_delete_confirm"

    /// Given a raw fixture name (typically
    /// `ProcessInfo.processInfo.environment["WIRES_FIXTURE"]`), installs
    /// the corresponding fixture dependencies and records it as the
    /// active fixture. Called once at app launch by `WiresIOSApp`.
    /// Unknown raw values are recorded in
    /// `FixtureRuntime.shared.malformedFixtureName` and the function
    /// returns without raising.
    static func install(named raw: String) {
        guard let fix = LaunchFixture(rawValue: raw) else {
            FixtureRuntime.shared.malformedFixtureName = raw
            return
        }
        FixtureRuntime.shared.activeFixture = fix
        prepareDependencies { values in
            fix.applyDependencies(to: &values)
        }
    }

    func applyDependencies(to values: inout DependencyValues) {
        // Default placeholder dependencies that work for every fixture:
        // .placeholder camera so no AVCaptureSession spins up.
        values.cameraPreviewKind = .placeholder

        switch self {
        case .onboardingWelcome, .onboardingScan, .onboardingScanError,
             .onboardingConfirm, .onboardingFaceID, .onboardingDone:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture()
            values.mcpGatewayClient = .fixture()

        case .homeLoading:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture(listCapsBehavior: .block)
            values.mcpGatewayClient = .fixture()

        case .homeEmpty:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture(
                household: Household(
                    rootPubkeyHex: String(repeating: "ab", count: 32),
                    hostEndpointIdHex: String(repeating: "cd", count: 32)
                ),
                caps: []
            )
            values.mcpGatewayClient = .fixture()

        case .homeOneCap:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            let cap = CapRecord(
                capIdHex: String(repeating: "11", count: 32),
                nodePubkeyHex: String(repeating: "aa", count: 32),
                nodeAlias: "Aaron's Mac",
                topicNames: ["family"],
                rights: ["read", "write"],
                issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
            )
            values.householdClient = .fixture(
                household: Household(
                    rootPubkeyHex: String(repeating: "ab", count: 32),
                    hostEndpointIdHex: String(repeating: "cd", count: 32)
                ),
                caps: [cap]
            )
            values.mcpGatewayClient = .fixture()

        case .homeThreeCapsOneRevoked:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            let macFamily = CapRecord(
                capIdHex: String(repeating: "11", count: 32),
                nodePubkeyHex: String(repeating: "aa", count: 32),
                nodeAlias: "Aaron's Mac",
                topicNames: ["family"],
                rights: ["read", "write"],
                issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
            )
            let iPadCalendar = CapRecord(
                capIdHex: String(repeating: "22", count: 32),
                nodePubkeyHex: String(repeating: "bb", count: 32),
                nodeAlias: "Kitchen iPad",
                topicNames: ["calendar"],
                rights: ["read"],
                issuedAt: Date(timeIntervalSince1970: 1_715_100_000),
                revokedAt: Date(timeIntervalSince1970: 1_715_200_000)
            )
            let hassMqtt = CapRecord(
                capIdHex: String(repeating: "33", count: 32),
                nodePubkeyHex: String(repeating: "cc", count: 32),
                nodeAlias: nil,
                topicNames: ["mqtt:hass"],
                rights: ["read", "write"],
                issuedAt: Date(timeIntervalSince1970: 1_715_300_000)
            )
            values.householdClient = .fixture(
                household: Household(
                    rootPubkeyHex: String(repeating: "ab", count: 32),
                    hostEndpointIdHex: String(repeating: "cd", count: 32)
                ),
                caps: [macFamily, iPadCalendar, hassMqtt]
            )
            values.mcpGatewayClient = .fixture()

        case .oauthScan,
             .oauthSigninConfirm,
             .oauthPairApprove,
             .oauthPairApprovePartial,
             .oauthDone,
             .oauthError:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture(
                household: Household(
                    rootPubkeyHex: String(repeating: "ab", count: 32),
                    hostEndpointIdHex: String(repeating: "cd", count: 32)
                )
            )
            values.mcpGatewayClient = .fixture()

        case .settingsRoot,
             .settingsFaceIDOff,
             .settingsAccountDetail,
             .settingsDeleteConfirm:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture(
                household: Household(
                    rootPubkeyHex: String(repeating: "ab", count: 32),
                    hostEndpointIdHex: String(repeating: "cd", count: 32),
                    hostRelayURL: "https://wires.example.org"
                )
            )
            values.mcpGatewayClient = .fixture()
        }
    }

    var initialAppState: AppFeature.State {
        switch self {
        case .onboardingWelcome:
            return .onboarding(OnboardingFeature.State(step: .welcome))

        case .onboardingScan:
            var s = OnboardingFeature.State(step: .scan)
            s.scan.cameraPermission = .granted
            return .onboarding(s)

        case .onboardingScanError:
            var s = OnboardingFeature.State(step: .scan)
            s.scan.cameraPermission = .granted
            s.scan.error = .parseFailed("Couldn't read this code")
            return .onboarding(s)

        case .onboardingConfirm:
            var s = OnboardingFeature.State(step: .confirm)
            s.confirmedHost = HostInfo(
                endpointIdHex: String(repeating: "cd", count: 32),
                addrs: ["192.168.1.20:4242"],
                relay: "https://wires.example.org",
                hintExpiresAtMs: 0,
                serverName: "Wires"
            )
            return .onboarding(s)

        case .onboardingFaceID:
            var s = OnboardingFeature.State(step: .faceID)
            s.completed = OnboardingFeature.State.Completed(
                registration: TenantRegistration(
                    capsTopicIdHex: String(repeating: "ee", count: 32),
                    hostEndpointIdHex: String(repeating: "cd", count: 32),
                    serverTimeMs: 0
                ),
                host: HostInfo(
                    endpointIdHex: String(repeating: "cd", count: 32),
                    addrs: [],
                    relay: "https://wires.example.org",
                    hintExpiresAtMs: 0,
                    serverName: "Wires"
                ),
                rootPubkeyHex: String(repeating: "ab", count: 32)
            )
            return .onboarding(s)

        case .onboardingDone:
            var s = OnboardingFeature.State(step: .done)
            s.completed = OnboardingFeature.State.Completed(
                registration: TenantRegistration(
                    capsTopicIdHex: String(repeating: "ee", count: 32),
                    hostEndpointIdHex: String(repeating: "cd", count: 32),
                    serverTimeMs: 0
                ),
                host: HostInfo(
                    endpointIdHex: String(repeating: "cd", count: 32),
                    addrs: [],
                    relay: "https://wires.example.org",
                    hintExpiresAtMs: 0,
                    serverName: "Wires"
                ),
                rootPubkeyHex: String(repeating: "ab", count: 32)
            )
            return .onboarding(s)

        case .homeLoading:
            var s = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            s.loading = true
            return .main(MainFeature.State(
                home: s,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .homeEmpty, .homeOneCap, .homeThreeCapsOneRevoked:
            // HomeFeature.onAppear will call householdClient.listCaps which the
            // per-fixture override returns immediately. The effect then
            // overwrites caps from the client.
            return .main(MainFeature.State(
                home: HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32)),
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .oauthScan:
            var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            var oauth = OAuthSignInFeature.State.initial()
            if case .scan(var scanState) = oauth {
                scanState.cameraPermission = .granted
                oauth = .scan(scanState)
            }
            home.oauthSignIn = oauth
            return .main(MainFeature.State(
                home: home,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .oauthSigninConfirm:
            var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            let ticket = SessionTicket(
                version: 1,
                kind: SessionTicket.kindV1,
                gatewayURL: "https://wires-mcp.example.org",
                sessionID: "fixture-session-id-abc"
            )
            let challenge = SignInChallenge(
                version: 1,
                kind: SignInChallenge.kindV1,
                gatewayURL: "https://wires-mcp.example.org",
                sessionID: "fixture-session-id-abc",
                nonce: String(repeating: "0", count: 64),
                issuedAt: 0,
                expires: 0
            )
            home.oauthSignIn = .signinConfirm(ticket: ticket, challenge: challenge)
            return .main(MainFeature.State(
                home: home,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .oauthPairApprove:
            // Pair-approve embeds ApprovalFeature.State directly with the full
            // scope set granted. The "partial" variant is a sibling fixture
            // (oauthPairApprovePartial) that mutates one scope.
            return .main(MainFeature.State(
                home: homeWithPairApprove(modifier: { _ in }),
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .oauthPairApprovePartial:
            // Same preview as oauthPairApprove but the user has dropped .write
            // from "family" and toggled "calendar" entirely off. Captures the
            // partial-grant UX that the unified OAuth flow inherited from the
            // (now-removed) enroll flow.
            return .main(MainFeature.State(
                home: homeWithPairApprove { approve in
                    if var fam = approve.decisions[id: "family"] {
                        fam.grantedRights = [.read]
                        approve.decisions[id: "family"] = fam
                    }
                    if var cal = approve.decisions[id: "calendar"] {
                        cal.granted = false
                        approve.decisions[id: "calendar"] = cal
                    }
                },
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .oauthDone:
            var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            home.oauthSignIn = .done(message: "Signed in")
            return .main(MainFeature.State(
                home: home,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .oauthError:
            var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            home.oauthSignIn = .error(message: "gateway returned 500")
            return .main(MainFeature.State(
                home: home,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .settingsRoot:
            return mainStateOnSettings(faceIDEnabled: true)

        case .settingsFaceIDOff:
            return mainStateOnSettings(faceIDEnabled: false)

        case .settingsAccountDetail:
            var main = mainStateOnSettings(faceIDEnabled: true)
            if case .main(var s) = main {
                s.settings.showingAccountDetail = true
                main = .main(s)
            }
            return main

        case .settingsDeleteConfirm:
            var main = mainStateOnSettings(faceIDEnabled: true)
            if case .main(var s) = main {
                s.settings.deleteSheet = DeleteAccountFeature.State()
                main = .main(s)
            }
            return main
        }
    }

    /// Shared scaffold for every settings_* fixture: lands the app in the
    /// Settings tab with a populated SettingsFeature.State that mirrors what
    /// `SettingsFeature.onAppear` would have produced from a populated
    /// household. Bypasses the on-appear effect so the fixture renders
    /// the loaded-state directly.
    private func mainStateOnSettings(faceIDEnabled: Bool) -> AppFeature.State {
        let home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
        var settings = SettingsFeature.State()
        settings.loading = false
        settings.serverName = "Wires"
        settings.serverURL = "https://wires.example.org"
        settings.rootPubkeyHex = String(repeating: "ab", count: 32)
        settings.faceIDEnabled = faceIDEnabled
        return .main(MainFeature.State(
            home: home,
            settings: settings,
            selectedTab: .settings
        ))
    }

    /// Builds a Home state seeded with an OAuth pair-approve sheet showing
    /// two requested scopes (family read+write, calendar read). The
    /// `modifier` closure can mutate the approval decisions to capture
    /// partial-grant states.
    private func homeWithPairApprove(
        modifier: (inout ApprovalFeature.State) -> Void
    ) -> HomeFeature.State {
        let host = HostInfo(
            endpointIdHex: String(repeating: "cd", count: 32),
            addrs: [],
            relay: nil,
            hintExpiresAtMs: 0,
            serverName: nil
        )
        var home = HomeFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
        let preview = PairRequestPreview(
            handle: PendingPairHandle(id: "fixture-pair"),
            agentPubkeyHex: String(repeating: "ef", count: 32),
            role: "agent",
            description: "Aaron's Mac",
            issuedAtMs: 0,
            expiresAtMs: 0,
            requestedScopes: [
                RequestedScopePreview(topicName: "family", rights: [.read, .write]),
                RequestedScopePreview(topicName: "calendar", rights: [.read])
            ],
            dialSummary: ""
        )
        var approve = ApprovalFeature.State(preview: preview, host: host)
        modifier(&approve)
        home.oauthSignIn = .pairApprove(approve)
        return home
    }

    /// Maps each fixture to a (flow folder, short filename) tuple. Used
    /// by `SnapshotSweep` to compute the output path.
    var flowAndShortName: (flow: String, short: String) {
        let raw = rawValue
        if let underscore = raw.firstIndex(of: "_") {
            let flow = String(raw[..<underscore])
            let rest = raw[raw.index(after: underscore)...]
                .replacingOccurrences(of: "_", with: "-")
            return (flow, rest)
        }
        return ("misc", raw)
    }
}
