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

    func test_bootstrap_scan_denied()        throws { try snap("bootstrap_scan_denied",        flow: "bootstrap", short: "scan-denied") }
    func test_bootstrap_scan_granted()       throws { try snap("bootstrap_scan_granted",       flow: "bootstrap", short: "scan-granted") }
    func test_bootstrap_confirm()            throws { try snap("bootstrap_confirm",            flow: "bootstrap", short: "confirm") }
    func test_bootstrap_done()               throws { try snap("bootstrap_done",               flow: "bootstrap", short: "done") }

    func test_home_loading()                 throws { try snap("home_loading",                 flow: "home",     short: "loading") }
    func test_home_empty()                   throws { try snap("home_empty",                   flow: "home",     short: "empty") }
    func test_home_one_cap()                 throws { try snap("home_one_cap",                 flow: "home",     short: "one-cap") }
    func test_home_three_caps_one_revoked()  throws { try snap("home_three_caps_one_revoked",  flow: "home",     short: "three-caps-one-revoked") }

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
