import ComposableArchitecture
import Foundation
import Testing
@testable import Wires

@MainActor
@Suite
struct ConnectFeatureTests {

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
            initialState: ConnectFeature.State.probing(ticket: ticket, rootPubkeyHex: "ab")
        ) {
            ConnectFeature()
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

    // MARK: - Test 2: probe dispatches to pair branch and surfaces failures

    /// The pair branch now stays in `.probing` while it parses the pair
    /// preview and loads the household's HostInfo. A failed parse should
    /// surface as `.error` without ever leaving `.probing`.
    @Test
    func probe_pair_branch_stays_in_probing_then_surfaces_error() async throws {
        struct DeferredError: Error {}
        let ticket = makeTicket()

        let store = TestStore(
            initialState: ConnectFeature.State.probing(ticket: ticket, rootPubkeyHex: "ab")
        ) {
            ConnectFeature()
        } withDependencies: {
            $0.mcpGatewayClient.probe = { _, _, _ in
                .pair(pairTokenB64: "PAIR_TOKEN")
            }
            // Background work after .probing: parsePairRequest throws,
            // surfacing as .pairLoadFailed and transitioning to .error.
            $0.wiresClient.parsePairRequest = { _ in throw DeferredError() }
            $0.householdClient.loadHousehold = { nil }
        }

        await store.send(.probeStarted)

        // No state change on the pair probe response — we remain in
        // `.probing` while the preview + host load runs.
        await store.receive(\.probeResolvedPair)

        await store.receive(\.pairLoadFailed) {
            $0 = .error(message: "DeferredError()")
        }
    }

    // MARK: - Test 3: signin assertion post succeeds → .done

    @Test
    func signin_assertion_post_succeeds_marks_done() async throws {
        let ticket = makeTicket()
        let challenge = makeChallenge()

        let store = TestStore(
            initialState: ConnectFeature.State.signinConfirm(ticket: ticket, challenge: challenge)
        ) {
            ConnectFeature()
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
