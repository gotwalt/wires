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
    case onboardingWelcome                   = "onboarding_welcome"
    case onboardingScan                      = "onboarding_scan"
    case onboardingScanError                 = "onboarding_scan_error"
    case onboardingConfirm                   = "onboarding_confirm"
    case onboardingFaceID                    = "onboarding_face_id"
    case onboardingDone                      = "onboarding_done"
    case networkEmpty                        = "network_empty"
    case networkLoading                      = "network_loading"
    case networkOneService                   = "network_one_service"
    case networkThreeServicesOneRevoked      = "network_three_services_one_revoked"
    case networkLoadError                    = "network_load_error"
    case serviceDetailConnected              = "service_detail_connected"
    case serviceDetailRevoked                = "service_detail_revoked"
    case serviceDetailAdvancedExpanded       = "service_detail_advanced_expanded"
    case connectScan                         = "connect_scan"
    case connectProbing                      = "connect_probing"
    case connectSigninConfirm                = "connect_signin_confirm"
    case connectApproveCollapsed             = "connect_approve_collapsed"
    case connectDone                         = "connect_done"
    case connectErrorParse                   = "connect_error_parse"
    case connectErrorNetwork                 = "connect_error_network"
    case connectAlreadyConnected             = "connect_already_connected"
    case settingsRoot                        = "settings_root"
    case settingsFaceIDOff                   = "settings_face_id_off"
    case settingsAccountDetail               = "settings_account_detail"
    case settingsDeleteConfirm               = "settings_delete_confirm"

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

        case .networkLoading:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture(listCapsBehavior: .block)
            values.mcpGatewayClient = .fixture()

        case .networkEmpty,
             .networkOneService,
             .networkThreeServicesOneRevoked,
             .serviceDetailConnected,
             .serviceDetailRevoked,
             .serviceDetailAdvancedExpanded:
            // Services are seeded directly into `NetworkFeature.State.services`
            // by `initialAppState`, so listCaps doesn't need to round-trip
            // through CapToServiceMapper. Returning `[]` keeps onAppear's
            // refresh-effect from overwriting the seeded list.
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

        case .networkLoadError:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture(
                household: Household(
                    rootPubkeyHex: String(repeating: "ab", count: 32),
                    hostEndpointIdHex: String(repeating: "cd", count: 32)
                ),
                listCapsBehavior: .failing("Couldn't reach your server. Check your connection and try again.")
            )
            values.mcpGatewayClient = .fixture()

        case .connectScan,
             .connectProbing,
             .connectSigninConfirm,
             .connectApproveCollapsed,
             .connectDone,
             .connectErrorParse,
             .connectErrorNetwork,
             .connectAlreadyConnected:
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

        case .networkEmpty:
            return mainStateOnNetwork(services: [])

        case .networkLoading:
            var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            network.loading = true
            return .main(MainFeature.State(
                network: network,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .networkOneService:
            return mainStateOnNetwork(services: [
                ServiceSummary(
                    id: "1", name: "Chase",
                    deviceName: "Aaron's Mac mini",
                    category: .banking, status: .connected,
                    scopes: [
                        ScopeDescriptor(
                            id: "family",
                            label: "family",
                            summary: "Read messages · Send messages",
                            detail: [
                                .init(label: "Read messages", granted: true, kind: .read),
                                .init(label: "Send messages", granted: true, kind: .write)
                            ]
                        )
                    ],
                    connectedAt: Date(timeIntervalSince1970: 1_715_000_000),
                    lastActivityAt: nil
                )
            ])

        case .networkThreeServicesOneRevoked:
            return mainStateOnNetwork(services: [
                ServiceSummary(
                    id: "1", name: "Chase", deviceName: "Aaron's Mac mini",
                    category: .banking, status: .connected, scopes: [],
                    connectedAt: Date(timeIntervalSince1970: 1_715_000_000), lastActivityAt: nil
                ),
                ServiceSummary(
                    id: "2", name: "Home Assistant", deviceName: "Kitchen iPad",
                    category: .smartHome, status: .connected, scopes: [],
                    connectedAt: Date(timeIntervalSince1970: 1_715_100_000), lastActivityAt: nil
                ),
                ServiceSummary(
                    id: "3", name: "Calendar", deviceName: "Kitchen iPad",
                    category: .unknown, status: .revoked, scopes: [],
                    connectedAt: Date(timeIntervalSince1970: 1_715_200_000), lastActivityAt: nil
                )
            ])

        case .networkLoadError:
            var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            network.loadError = "Couldn't reach your server. Check your connection and try again."
            return .main(MainFeature.State(
                network: network,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .serviceDetailConnected:
            let summary = ServiceSummary(
                id: "1", name: "Chase", deviceName: "Aaron's Mac mini",
                category: .banking, status: .connected,
                scopes: [
                    ScopeDescriptor(
                        id: "family",
                        label: "family",
                        summary: "Read messages · Send messages",
                        detail: [
                            .init(label: "Read messages", granted: true, kind: .read),
                            .init(label: "Send messages", granted: true, kind: .write)
                        ]
                    )
                ],
                connectedAt: Date(timeIntervalSince1970: 1_715_000_000),
                lastActivityAt: nil
            )
            var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            network.path.append(ServiceDetailFeature.State(summary: summary))
            return .main(MainFeature.State(
                network: network,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .serviceDetailRevoked:
            let summary = ServiceSummary(
                id: "3", name: "Calendar", deviceName: "Kitchen iPad",
                category: .unknown, status: .revoked, scopes: [],
                connectedAt: Date(timeIntervalSince1970: 1_715_200_000),
                lastActivityAt: nil
            )
            var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            network.path.append(ServiceDetailFeature.State(summary: summary))
            return .main(MainFeature.State(
                network: network,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .serviceDetailAdvancedExpanded:
            // Same as serviceDetailConnected but with the Advanced
            // disclosure forced open via ServiceDetailFeature.State.
            let summary = ServiceSummary(
                id: "1", name: "Chase", deviceName: "Aaron's Mac mini",
                category: .banking, status: .connected,
                scopes: [
                    ScopeDescriptor(
                        id: "family",
                        label: "family",
                        summary: "Read messages · Send messages",
                        detail: [
                            .init(label: "Read messages", granted: true, kind: .read),
                            .init(label: "Send messages", granted: true, kind: .write)
                        ]
                    )
                ],
                connectedAt: Date(timeIntervalSince1970: 1_715_000_000),
                lastActivityAt: nil
            )
            var detail = ServiceDetailFeature.State(summary: summary)
            detail.advancedInitiallyExpanded = true
            var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
            network.path.append(detail)
            return .main(MainFeature.State(
                network: network,
                settings: SettingsFeature.State(),
                selectedTab: .network
            ))

        case .connectScan:
            var connect = ConnectFeature.State.initial()
            if case .scan(var scanState) = connect {
                scanState.cameraPermission = .granted
                connect = .scan(scanState)
            }
            return mainStateWithConnect(connect)

        case .connectProbing:
            let ticket = SessionTicket(
                version: 1, kind: SessionTicket.kindV1,
                gatewayURL: "https://wires-mcp.example.org",
                sessionID: "fixture-session-id"
            )
            return mainStateWithConnect(
                .probing(ticket: ticket, rootPubkeyHex: String(repeating: "ab", count: 32))
            )

        case .connectSigninConfirm:
            let ticket = SessionTicket(
                version: 1, kind: SessionTicket.kindV1,
                gatewayURL: "https://wires-mcp.example.org",
                sessionID: "fixture-session-id"
            )
            let challenge = SignInChallenge(
                version: 1, kind: SignInChallenge.kindV1,
                gatewayURL: "https://wires-mcp.example.org",
                sessionID: "fixture-session-id",
                nonce: String(repeating: "0", count: 64),
                issuedAt: 0, expires: 0
            )
            return mainStateWithConnect(.signinConfirm(ticket: ticket, challenge: challenge))

        case .connectApproveCollapsed:
            return mainStateWithConnect(.pairApprove(approvalStateForFixture()))

        case .connectDone:
            return mainStateWithConnect(.done(message: "Chase is now on your network."))

        case .connectErrorParse:
            return mainStateWithConnect(.error(message: "Couldn't read this code. Try again."))

        case .connectErrorNetwork:
            return mainStateWithConnect(.error(message: "Couldn't reach your server."))

        case .connectAlreadyConnected:
            return mainStateWithConnect(.done(message: "Chase is already connected."))

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

    /// Shared scaffold for every network_* fixture that just wants a
    /// populated services list. Leaves `loading=false` and `loadError=nil`
    /// so the view renders the populated list directly.
    private func mainStateOnNetwork(services: [ServiceSummary]) -> AppFeature.State {
        var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
        network.services = services
        network.loading = false
        return .main(MainFeature.State(
            network: network,
            settings: SettingsFeature.State(),
            selectedTab: .network
        ))
    }

    /// Shared scaffold for every settings_* fixture: lands the app in the
    /// Settings tab with a populated SettingsFeature.State that mirrors what
    /// `SettingsFeature.onAppear` would have produced from a populated
    /// household. Bypasses the on-appear effect so the fixture renders
    /// the loaded-state directly.
    private func mainStateOnSettings(faceIDEnabled: Bool) -> AppFeature.State {
        let network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
        var settings = SettingsFeature.State()
        settings.loading = false
        settings.serverName = "Wires"
        settings.serverURL = "https://wires.example.org"
        settings.rootPubkeyHex = String(repeating: "ab", count: 32)
        settings.faceIDEnabled = faceIDEnabled
        return .main(MainFeature.State(
            network: network,
            settings: settings,
            selectedTab: .settings
        ))
    }

    /// Shared scaffold for every connect_* fixture: presents the Network
    /// tab with the connect sheet hosting the given ConnectFeature.State.
    private func mainStateWithConnect(_ connect: ConnectFeature.State) -> AppFeature.State {
        var network = NetworkFeature.State(rootPubkeyHex: String(repeating: "ab", count: 32))
        network.connect = connect
        return .main(MainFeature.State(
            network: network,
            settings: SettingsFeature.State(),
            selectedTab: .network
        ))
    }

    /// Canned ApprovalFeature.State used by connect_approve_* fixtures.
    /// Models a node request from "Chase" asking for read+write on
    /// `family` and read on `calendar`.
    private func approvalStateForFixture() -> ApprovalFeature.State {
        let host = HostInfo(
            endpointIdHex: String(repeating: "cd", count: 32),
            addrs: [],
            relay: nil,
            hintExpiresAtMs: 0,
            serverName: "Wires"
        )
        let preview = PairRequestPreview(
            handle: PendingPairHandle(id: "fixture-pair"),
            agentPubkeyHex: String(repeating: "ef", count: 32),
            role: "agent",
            description: "Chase",
            issuedAtMs: 0,
            expiresAtMs: 0,
            requestedScopes: [
                RequestedScopePreview(topicName: "family", rights: [.read, .write]),
                RequestedScopePreview(topicName: "calendar", rights: [.read])
            ],
            dialSummary: ""
        )
        return ApprovalFeature.State(preview: preview, host: host)
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
