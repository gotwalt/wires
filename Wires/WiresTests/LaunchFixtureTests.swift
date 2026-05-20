import Foundation
import Testing
@testable import Wires

@Suite
struct LaunchFixtureTests {

    /// Catches typo regressions: every case's rawValue must round-trip
    /// through the failable initializer. This is the contract the env
    /// var system relies on.
    @Test
    func rawValue_roundTrips_for_every_case() {
        for fixture in LaunchFixture.allCases {
            let resolved = LaunchFixture(rawValue: fixture.rawValue)
            #expect(resolved == fixture,
                    "LaunchFixture(rawValue: \(fixture.rawValue)) did not round-trip")
        }
    }

    /// Catches accidental case drops. v1 ships exactly 17 fixtures per
    /// the spec §4.4. Update this number deliberately if the fixture
    /// catalogue changes.
    @Test
    func allCases_count_matches_spec() {
        #expect(LaunchFixture.allCases.count == 17)
    }

    /// `flowAndShortName` is consumed by the snapshot harness to derive
    /// per-screenshot file paths. Wrong tuples → screenshots write to the
    /// wrong folder. Spot-check the two non-trivial cases the spec calls
    /// out and confirm the no-underscore fallback.
    @Test
    func flowAndShortName_splits_at_first_underscore() {
        let bootstrap = LaunchFixture.bootstrapScanDenied.flowAndShortName
        #expect(bootstrap.flow == "bootstrap")
        #expect(bootstrap.short == "scan-denied")

        let home = LaunchFixture.homeThreeCapsOneRevoked.flowAndShortName
        #expect(home.flow == "home")
        #expect(home.short == "three-caps-one-revoked")

        let oauth = LaunchFixture.oauthSigninConfirm.flowAndShortName
        #expect(oauth.flow == "oauth")
        #expect(oauth.short == "signin-confirm")
    }
}
