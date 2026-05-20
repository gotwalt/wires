import XCTest

/// Snapshot sweep. One test method per LaunchFixture; each method
/// relaunches the app once per Appearance, screenshots, and writes the
/// PNG to `$WIRES_SCREENSHOT_DIR/<flow>/<short>-<appearance>.png`.
///
/// Driven by scripts/snapshot-ios.sh — when invoked from xcodebuild
/// directly, `WIRES_SCREENSHOT_DIR` defaults to a tmp dir.
@MainActor
final class SnapshotSweep: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = true  // collect every fixture per run
    }

    // MARK: - Test methods (one per LaunchFixture)

    func test_onboarding_welcome()           throws { try snap("onboarding_welcome",    flow: "onboarding", short: "welcome") }
    func test_onboarding_scan()              throws { try snap("onboarding_scan",       flow: "onboarding", short: "scan") }
    func test_onboarding_scan_error()        throws { try snap("onboarding_scan_error", flow: "onboarding", short: "scan-error") }
    func test_onboarding_confirm()           throws { try snap("onboarding_confirm",    flow: "onboarding", short: "confirm") }
    func test_onboarding_face_id()           throws { try snap("onboarding_face_id",    flow: "onboarding", short: "face-id") }
    func test_onboarding_done()              throws { try snap("onboarding_done",       flow: "onboarding", short: "done") }

    func test_network_empty()                      throws { try snap("network_empty",                      flow: "network", short: "empty") }
    func test_network_loading()                    throws { try snap("network_loading",                    flow: "network", short: "loading") }
    func test_network_one_service()                throws { try snap("network_one_service",                flow: "network", short: "one-service") }
    func test_network_three_services_one_revoked() throws { try snap("network_three_services_one_revoked", flow: "network", short: "three-services-one-revoked") }
    func test_network_load_error()                 throws { try snap("network_load_error",                 flow: "network", short: "load-error") }
    func test_service_detail_connected()           throws { try snap("service_detail_connected",           flow: "service", short: "detail-connected") }
    func test_service_detail_revoked()             throws { try snap("service_detail_revoked",             flow: "service", short: "detail-revoked") }
    func test_service_detail_advanced_expanded()   throws { try snap("service_detail_advanced_expanded",   flow: "service", short: "detail-advanced-expanded") }

    func test_oauth_scan()                   throws { try snap("oauth_scan",                   flow: "oauth",    short: "scan") }
    func test_oauth_signin_confirm()         throws { try snap("oauth_signin_confirm",         flow: "oauth",    short: "signin-confirm") }
    func test_oauth_pair_approve()           throws { try snap("oauth_pair_approve",           flow: "oauth",    short: "pair-approve") }
    func test_oauth_pair_approve_partial()   throws { try snap("oauth_pair_approve_partial",   flow: "oauth",    short: "pair-approve-partial") }
    func test_oauth_done()                   throws { try snap("oauth_done",                   flow: "oauth",    short: "done") }
    func test_oauth_error()                  throws { try snap("oauth_error",                  flow: "oauth",    short: "error") }

    func test_settings_root()                throws { try snap("settings_root",                flow: "settings", short: "root") }
    func test_settings_face_id_off()         throws { try snap("settings_face_id_off",         flow: "settings", short: "face-id-off") }
    func test_settings_account_detail()      throws { try snap("settings_account_detail",      flow: "settings", short: "account-detail") }
    func test_settings_delete_confirm()      throws { try snap("settings_delete_confirm",      flow: "settings", short: "delete-confirm") }

    // MARK: - Helper

    private enum Appearance: String, CaseIterable {
        case light
        case dark
    }

    @MainActor
    private func snap(_ fixture: String, flow: String, short: String) throws {
        let outputRoot = ProcessInfo.processInfo.environment["WIRES_SCREENSHOT_DIR"]
            ?? NSTemporaryDirectory() + "wires-screenshots/default"
        let flowDir = URL(fileURLWithPath: outputRoot).appendingPathComponent(flow)
        try FileManager.default.createDirectory(at: flowDir, withIntermediateDirectories: true)

        for appearance in Appearance.allCases {
            let app = XCUIApplication()
            app.launchEnvironment = [
                "WIRES_FIXTURE": fixture,
                "WIRES_APPEARANCE": appearance.rawValue,
            ]
            app.launch()
            XCTAssertTrue(app.wait(for: .runningForeground, timeout: 10),
                          "fixture \(fixture)/\(appearance.rawValue): did not reach foreground")
            // Settle interval — empirically enough for the seeded
            // AppFeature.State to mount and the first frame to render.
            Thread.sleep(forTimeInterval: 0.6)

            let png = XCUIScreen.main.screenshot().pngRepresentation
            let url = flowDir.appendingPathComponent("\(short)-\(appearance.rawValue).png")
            try png.write(to: url)

            app.terminate()
        }
    }
}
