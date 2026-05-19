import ComposableArchitecture
import Foundation
import WiresKit

/// Drives the wires-mcp OAuth consent flow on iOS.
///
/// Flow:
///   .scan                   →  user scans a SessionTicket QR
///   .probing(ticket, root)  →  POST /oauth/session/probe
///       └ signin branch →  .signinConfirm  →  biometric sign + POST  →  .done
///       └ pair branch   →  .pairApprove (delegates to ApprovalFeature) →  .done
///
/// Manual `Reducer` conformance — same pattern as ScanFeature (the @Reducer
/// macro doesn't play nicely with the `.ifCaseLet` over a non-payload-generic
/// state enum we need here).
struct OAuthSignInFeature: Reducer {
    @ObservableState
    enum State: Equatable {
        case scan(ScanFeature<SessionTicket>.State)
        case probing(ticket: SessionTicket, rootPubkeyHex: String)
        case signinConfirm(ticket: SessionTicket, challenge: SignInChallenge)
        case signingIn(ticket: SessionTicket, challenge: SignInChallenge)
        case pairApprove(PairBranchState)
        case done(message: String)
        case error(message: String)

        struct PairBranchState: Equatable {
            let ticket: SessionTicket
            let pairTokenB64: String
            // ApprovalFeature.State is not embedded here in v1; this feature
            // hands off to ApprovalFeature via a `pairTokenParsed` action
            // after parsing the token. Kept as a simple holder for now.
            var preview: PairRequestPreview?
            var error: String?
        }

        static func initial() -> Self {
            .scan(ScanFeature<SessionTicket>.State())
        }
    }

    @CasePathable
    enum Action: Equatable {
        case scan(ScanFeature<SessionTicket>.Action)
        /// Internal: carries ticket + resolved root pubkey hex from scan step.
        case probeBegin(ticket: SessionTicket, rootPubkeyHex: String)
        /// Fires once we enter .probing; triggers the network probe.
        case probeStarted
        case probeResolvedSignin(SignInChallenge)
        case probeResolvedPair(String) // pair_token_b64
        case probeFailed(String)
        case signinApproveTapped
        case signinSucceeded
        case signinFailed(String)
        case pairTokenParsed(PairRequestPreview)
        case pairParseFailed(String)
        case dismissTapped
    }

    @Dependency(\.wiresClient) var wires
    @Dependency(\.mcpGatewayClient) var gateway
    @Dependency(\.keychainClient) var keychain
    @Dependency(\.householdClient) var household

    func reduce(into state: inout State, action: Action) -> Effect<Action> {
        switch action {

        // MARK: Scan step

        case let .scan(.decodedPayload(ticket)):
            // Look up the household's root pubkey from SwiftData (already a hex
            // string on Household — no encoding needed).
            let household = self.household
            return .run { send in
                let rootHex: String?
                do { rootHex = try await household.loadHousehold()?.rootPubkeyHex } catch { rootHex = nil }
                guard let rootHex, !rootHex.isEmpty else {
                    await send(.probeFailed("no household — bootstrap first"))
                    return
                }
                await send(.probeBegin(ticket: ticket, rootPubkeyHex: rootHex))
            }

        case .scan:
            return .none

        // MARK: Probe step

        case let .probeBegin(ticket, rootHex):
            state = .probing(ticket: ticket, rootPubkeyHex: rootHex)
            return .send(.probeStarted)

        case .probeStarted:
            guard case let .probing(ticket, rootHex) = state else { return .none }
            let gateway = self.gateway
            return .run { send in
                do {
                    let result = try await gateway.probe(ticket.gatewayURL, ticket.sessionID, rootHex)
                    switch result {
                    case let .pair(token):
                        await send(.probeResolvedPair(token))
                    case let .signin(b64):
                        let challenge = try SignInChallenge.decode(urlSafeBase64: b64)
                        await send(.probeResolvedSignin(challenge))
                    }
                } catch {
                    await send(.probeFailed(String(describing: error)))
                }
            }

        case let .probeResolvedSignin(challenge):
            guard case let .probing(ticket, _) = state else { return .none }
            state = .signinConfirm(ticket: ticket, challenge: challenge)
            return .none

        case let .probeResolvedPair(token):
            guard case let .probing(ticket, _) = state else { return .none }
            state = .pairApprove(State.PairBranchState(ticket: ticket, pairTokenB64: token))
            let wires = self.wires
            return .run { send in
                do {
                    let preview = try await wires.parsePairRequest(token)
                    await send(.pairTokenParsed(preview))
                } catch {
                    await send(.pairParseFailed(String(describing: error)))
                }
            }

        case let .probeFailed(message):
            state = .error(message: message)
            return .none

        // MARK: Sign-in branch

        case .signinApproveTapped:
            guard case let .signinConfirm(ticket, challenge) = state else { return .none }
            state = .signingIn(ticket: ticket, challenge: challenge)
            let keychain = self.keychain
            let gateway = self.gateway
            let household = self.household
            return .run { send in
                do {
                    let sig = try await keychain.signWithBiometric(
                        KeychainBackedRootSigner.Account.signingKey,
                        challenge.signingBytes()
                    )
                    // Root pubkey hex comes from the household (already stored as hex).
                    let rootHex = (try? await household.loadHousehold()?.rootPubkeyHex) ?? ""
                    try await gateway.postAssertion(
                        ticket.gatewayURL,
                        ticket.sessionID,
                        rootHex,
                        sig.wiresHex()
                    )
                    await send(.signinSucceeded)
                } catch {
                    await send(.signinFailed(String(describing: error)))
                }
            }

        case .signinSucceeded:
            state = .done(message: "Signed in")
            return .none

        case let .signinFailed(message):
            state = .error(message: message)
            return .none

        // MARK: Pair branch

        case let .pairTokenParsed(preview):
            if case var .pairApprove(p) = state {
                p.preview = preview
                state = .pairApprove(p)
            }
            return .none

        case let .pairParseFailed(message):
            state = .error(message: message)
            return .none

        // MARK: Dismiss

        case .dismissTapped:
            return .none
        }
    }

    var body: some Reducer<State, Action> {
        Reduce(self.reduce)
            .ifCaseLet(\.scan, action: \.scan) {
                Scope(state: \.self, action: \.self) {
                    ScanFeature<SessionTicket>(parse: { payload in
                        try SessionTicket.decode(urlSafeBase64: payload)
                    })
                }
            }
    }
}
