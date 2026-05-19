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
enum LaunchFixture: String, CaseIterable {
    case bootstrapScanDenied        = "bootstrap_scan_denied"
    case bootstrapScanGranted       = "bootstrap_scan_granted"
    case bootstrapConfirm           = "bootstrap_confirm"
    case bootstrapDone              = "bootstrap_done"
    case homeLoading                = "home_loading"
    case homeEmpty                  = "home_empty"
    case homeOneCap                 = "home_one_cap"
    case homeThreeCapsOneRevoked    = "home_three_caps_one_revoked"
    case enrollScan                 = "enroll_scan"
    case enrollApprovePristine      = "enroll_approve_pristine"
    case enrollApprovePartial       = "enroll_approve_partial"
    case enrollDone                 = "enroll_done"
    case oauthScan                  = "oauth_scan"
    case oauthSigninConfirm         = "oauth_signin_confirm"
    case oauthPairApprove           = "oauth_pair_approve"
    case oauthDone                  = "oauth_done"
    case oauthError                 = "oauth_error"

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

    /// (filled in by Task 3 + 4a–4d)
    func applyDependencies(to values: inout DependencyValues) {
        // Default placeholder dependencies that work for every fixture:
        // .placeholder camera so no AVCaptureSession spins up.
        values.cameraPreviewKind = .placeholder

        switch self {
        case .bootstrapScanDenied:
            values.cameraPermissionClient = .fixture(.denied)
            values.wiresClient = .fixture()
            values.householdClient = .fixture()
            values.mcpGatewayClient = .fixture()

        case .bootstrapScanGranted:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture()
            values.mcpGatewayClient = .fixture()

        case .bootstrapConfirm:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture()
            values.mcpGatewayClient = .fixture()

        case .bootstrapDone:
            values.cameraPermissionClient = .fixture(.granted)
            values.wiresClient = .fixture()
            values.householdClient = .fixture()
            values.mcpGatewayClient = .fixture()

        case .homeLoading, .homeEmpty, .homeOneCap, .homeThreeCapsOneRevoked,
             .enrollScan, .enrollApprovePristine, .enrollApprovePartial, .enrollDone,
             .oauthScan, .oauthSigninConfirm, .oauthPairApprove, .oauthDone, .oauthError:
            break  // filled in by Tasks 4b–4d
        }
    }

    /// (filled in by Task 4a–4d)
    var initialAppState: AppFeature.State {
        switch self {
        case .bootstrapScanDenied:
            var s = BootstrapFeature.State()
            s.scan.cameraPermission = .denied
            return .bootstrap(s)

        case .bootstrapScanGranted:
            var s = BootstrapFeature.State()
            s.scan.cameraPermission = .granted
            return .bootstrap(s)

        case .bootstrapConfirm:
            var s = BootstrapFeature.State()
            s.scan.cameraPermission = .granted
            s.confirmedHost = HostInfo(
                endpointIdHex: String(repeating: "ab", count: 32),
                addrs: ["192.168.1.20:4242"],
                relay: "https://relay.example.org",
                hintExpiresAtMs: 0
            )
            return .bootstrap(s)

        case .bootstrapDone:
            var s = BootstrapFeature.State()
            s.scan.cameraPermission = .granted
            let host = HostInfo(
                endpointIdHex: String(repeating: "ab", count: 32),
                addrs: ["192.168.1.20:4242"],
                relay: "https://relay.example.org",
                hintExpiresAtMs: 0
            )
            s.completed = BootstrapFeature.State.Completed(
                registration: TenantRegistration(
                    capsTopicIdHex: String(repeating: "cd", count: 32),
                    hostEndpointIdHex: host.endpointIdHex,
                    serverTimeMs: 0
                ),
                host: host,
                rootPubkeyHex: String(repeating: "ab", count: 32)
            )
            return .bootstrap(s)

        case .homeLoading, .homeEmpty, .homeOneCap, .homeThreeCapsOneRevoked,
             .enrollScan, .enrollApprovePristine, .enrollApprovePartial, .enrollDone,
             .oauthScan, .oauthSigninConfirm, .oauthPairApprove, .oauthDone, .oauthError:
            return .launching  // filled in by Tasks 4b–4d
        }
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
