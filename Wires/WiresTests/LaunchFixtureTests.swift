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

    /// Catches accidental case drops. After the NodeEnrollment scanner
    /// was unified into the OAuth/SessionTicket flow (commit 4057e29),
    /// the 4 enroll fixtures were dropped and one oauth_pair_approve_partial
    /// fixture was added to preserve partial-grant coverage. Net 14
    /// fixtures. Update this number deliberately if the catalogue changes.
    @Test
    func allCases_count_matches_spec() {
        #expect(LaunchFixture.allCases.count == 14)
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
