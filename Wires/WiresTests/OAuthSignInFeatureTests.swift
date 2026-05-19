import ComposableArchitecture
import Foundation
import Testing
@testable import Wires

@MainActor
@Suite
struct OAuthSignInFeatureTests {

    // Convenience: a minimal SessionTicket.
    private func makeTicket(sessionID: String = "sid") -> SessionTicket {
        SessionTicket(
            version: 1,
            kind: SessionTicket.kindV1,
            gatewayURL: "https://mcp.example.com",
            sessionID: sessionID
        )
    }

    // Convenience: a minimal SignInChallenge.
    private func makeChallenge(sessionID: String = "sid") -> SignInChallenge {
        SignInChallenge(
            version: 1,
            kind: SignInChallenge.kindV1,
            gatewayURL: "https://mcp.example.com",
            sessionID: sessionID,
            nonce: "00",
            issuedAt: 1,
            expires: 2
        )
    }

    // MARK: - Test 1: probe dispatches to signin branch

    @Test
    func probe_signin_branch_renders_confirm_state() async throws {
        let ticket = makeTicket()
        let challenge = makeChallenge()
        // The server encodes the challenge as URL-safe base64 of canonical JSON.
        // We feed the same canonical bytes back so SignInChallenge.decode round-trips.
        let challengeB64 = challenge.signingBytes().base64URLEncodedNoPad()

        let store = TestStore(
            initialState: OAuthSignInFeature.State.probing(ticket: ticket, rootPubkeyHex: "ab")
        ) {
            OAuthSignInFeature()
        } withDependencies: {
            $0.mcpGatewayClient.probe = { _, _, _ in
                .signin(challengeB64: challengeB64)
            }
        }

        await store.send(.probeStarted)
        await store.receive(\.probeResolvedSignin) {
            $0 = .signinConfirm(ticket: ticket, challenge: challenge)
        }
    }

    // MARK: - Test 2: probe dispatches to pair branch

    @Test
    func probe_pair_branch_transitions_to_approval() async throws {
        let ticket = makeTicket()

        let store = TestStore(
            initialState: OAuthSignInFeature.State.probing(ticket: ticket, rootPubkeyHex: "ab")
        ) {
            OAuthSignInFeature()
        } withDependencies: {
            $0.mcpGatewayClient.probe = { _, _, _ in
                .pair(pairTokenB64: "PAIR_TOKEN")
            }
            // parsePairRequest is called in the background after state transitions;
            // return a failure so the test ends cleanly without needing a full
            // WiresKit environment. The assertion below only checks the initial
            // state transition into .pairApprove — the parse effect completion
            // is exercised by integration tests in Task 14.
            $0.wiresClient.parsePairRequest = { _ in
                throw NSError(domain: "test", code: 0, userInfo: [NSLocalizedDescriptionKey: "deferred"])
            }
        }

        await store.send(.probeStarted)

        // Confirm the state transitions into .pairApprove with the right token.
        await store.receive(\.probeResolvedPair) { newState in
            if case let .pairApprove(branch) = newState {
                #expect(branch.pairTokenB64 == "PAIR_TOKEN")
                #expect(branch.ticket == ticket)
            } else {
                Issue.record("Expected .pairApprove state, got \(newState)")
            }
        }

        // The background parsePairRequest throws, producing a pairParseFailed
        // action. Exhaust it so TCA's strict matcher doesn't flag an unchecked
        // received action.
        await store.receive(\.pairParseFailed) { _ in }
    }

    // MARK: - Test 3: signin assertion post succeeds → .done

    @Test
    func signin_assertion_post_succeeds_marks_done() async throws {
        let ticket = makeTicket()
        let challenge = makeChallenge()

        let store = TestStore(
            initialState: OAuthSignInFeature.State.signinConfirm(ticket: ticket, challenge: challenge)
        ) {
            OAuthSignInFeature()
        } withDependencies: {
            $0.keychainClient.signWithBiometric = { _, _ in Data(repeating: 0xAA, count: 64) }
            $0.mcpGatewayClient.postAssertion = { _, _, _, _ in () }
            $0.householdClient.loadHousehold = {
                Household(rootPubkeyHex: String(repeating: "ab", count: 32))
            }
        }

        await store.send(.signinApproveTapped) {
            $0 = .signingIn(ticket: ticket, challenge: challenge)
        }
        await store.receive(\.signinSucceeded) {
            $0 = .done(message: "Signed in")
        }
    }
}
