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
    func probe_pair_branch_transitions_to_pair_loading() async throws {
        let ticket = makeTicket()

        let store = TestStore(
            initialState: OAuthSignInFeature.State.probing(ticket: ticket, rootPubkeyHex: "ab")
        ) {
            OAuthSignInFeature()
        } withDependencies: {
            $0.mcpGatewayClient.probe = { _, _, _ in
                .pair(pairTokenB64: "PAIR_TOKEN")
            }
            // Background work after .pairLoading: parsePairRequest throws,
            // householdClient.loadHousehold returns nil. Either failure path
            // surfaces as .pairLoadFailed and ends the test cleanly.
            $0.wiresClient.parsePairRequest = { _ in
                throw NSError(domain: "test", code: 0, userInfo: [NSLocalizedDescriptionKey: "deferred"])
            }
            $0.householdClient.loadHousehold = { nil }
        }

        await store.send(.probeStarted)

        // Confirm the state transitions into .pairLoading with the right token.
        await store.receive(\.probeResolvedPair) { newState in
            if case let .pairLoading(t, token) = newState {
                #expect(token == "PAIR_TOKEN")
                #expect(t == ticket)
            } else {
                Issue.record("Expected .pairLoading state, got \(newState)")
            }
        }

        // Background async block fails (parsePairRequest throws), producing
        // pairLoadFailed → .error. Exhaust both transitions.
        await store.receive(\.pairLoadFailed) { newState in
            if case .error = newState { /* ok */ } else {
                Issue.record("Expected .error state after pairLoadFailed")
            }
        }
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
