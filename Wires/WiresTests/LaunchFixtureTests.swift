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
    /// fixture was added to preserve partial-grant coverage. Phase 3 of
    /// the iOS HIG redesign added the 4 settings_* fixtures. Phase 5
    /// replaced the 4 bootstrap_* fixtures with 6 onboarding_* fixtures
    /// (welcome + scan + scan-error + confirm + face-id + done). Phase 6
    /// retired the 4 home_* fixtures and added 5 network_* + 3
    /// service_detail_* fixtures (net +4 → 24). Update this number
    /// deliberately if the catalogue changes.
    @Test
    func allCases_count_matches_spec() {
        #expect(LaunchFixture.allCases.count == 24)
    }

    /// `flowAndShortName` is consumed by the snapshot harness to derive
    /// per-screenshot file paths. Wrong tuples → screenshots write to the
    /// wrong folder. Spot-check the two non-trivial cases the spec calls
    /// out and confirm the no-underscore fallback.
    @Test
    func flowAndShortName_splits_at_first_underscore() {
        let onboarding = LaunchFixture.onboardingScanError.flowAndShortName
        #expect(onboarding.flow == "onboarding")
        #expect(onboarding.short == "scan-error")

        let network = LaunchFixture.networkThreeServicesOneRevoked.flowAndShortName
        #expect(network.flow == "network")
        #expect(network.short == "three-services-one-revoked")

        let oauth = LaunchFixture.oauthSigninConfirm.flowAndShortName
        #expect(oauth.flow == "oauth")
        #expect(oauth.short == "signin-confirm")
    }
}
