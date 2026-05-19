import ComposableArchitecture
import Dependencies
import Foundation

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
        // Per-fixture overrides land in switch arms below as tasks 4a-4d
        // are implemented.
        switch self {
        case .bootstrapScanDenied, .bootstrapScanGranted, .bootstrapConfirm, .bootstrapDone,
             .homeLoading, .homeEmpty, .homeOneCap, .homeThreeCapsOneRevoked,
             .enrollScan, .enrollApprovePristine, .enrollApprovePartial, .enrollDone,
             .oauthScan, .oauthSigninConfirm, .oauthPairApprove, .oauthDone, .oauthError:
            break  // filled in by Task 4
        }
    }

    /// (filled in by Task 4a–4d)
    var initialAppState: AppFeature.State {
        // Stub — every case returns .launching until Task 4 fills it.
        return .launching
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
