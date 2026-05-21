import ComposableArchitecture
import Foundation
import WiresKit

/// Drives the wires-mcp Connect ceremony on iOS.
///
/// Flow:
///   .scan                    →  user scans a SessionTicket QR
///   .probing                 →  POST /oauth/session/probe
///       └ signin branch  →  .signinConfirm  →  biometric sign + POST  →  .done
///       └ pair branch    →  (still .probing while parsing PairRequest preview
///                            and loading HostInfo)   →  .pairApprove  →  .done
@Reducer
struct ConnectFeature {
    @ObservableState
    enum State: Equatable {
        case scan(ScanFeature<SessionTicket>.State)
        case probing(ticket: SessionTicket, rootPubkeyHex: String)
        case signinConfirm(ticket: SessionTicket, challenge: SignInChallenge)
        case signingIn(ticket: SessionTicket, challenge: SignInChallenge)
        case pairApprove(ApprovalFeature.State)
        case done(message: String)
        case error(message: String)

        static func initial() -> Self {
            .scan(ScanFeature<SessionTicket>.State())
        }
    }

    @CasePathable
    enum Action {
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
        /// Fired once both PairRequest parsing and fabric → HostInfo lookup
        /// complete. Carries the data ApprovalFeature needs.
        case pairReadyToApprove(PairRequestPreview, HostInfo)
        case pairLoadFailed(String)
        case approve(ApprovalFeature.Action)
        case dismissTapped
    }

    @Dependency(\.wiresClient) var wires
    @Dependency(\.mcpGatewayClient) var gateway
    @Dependency(\.keychainClient) var keychain
    @Dependency(\.fabricClient) var fabric

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {

            // MARK: Scan step

            case let .scan(.decodedPayload(ticket)):
                // Look up the fabric's root pubkey from SwiftData (already a
                // hex string on Fabric — no encoding needed).
                let fabric = self.fabric
                return .run { send in
                    let rootHex: String?
                    do { rootHex = try await fabric.loadFabric()?.rootPubkeyHex } catch { rootHex = nil }
                    guard let rootHex, !rootHex.isEmpty else {
                        await send(.probeFailed("Set up your account first"))
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
                // Stay in `.probing` while the pair preview + HostInfo load;
                // the spec collapses the prior `.pairLoading` substate into
                // `.probing` so the spinner copy doesn't flicker.
                guard case .probing = state else { return .none }
                let wires = self.wires
                let fabric = self.fabric
                return .run { send in
                    do {
                        // Parse the pair request preview (FFI) and fetch the
                        // fabric's HostInfo (SwiftData) in parallel.
                        async let previewTask = wires.parsePairRequest(token)
                        async let hostTask = loadHostInfo(fabric: fabric)
                        let preview = try await previewTask
                        guard let host = try await hostTask else {
                            await send(.pairLoadFailed("no host — bootstrap first"))
                            return
                        }
                        await send(.pairReadyToApprove(preview, host))
                    } catch {
                        await send(.pairLoadFailed(String(describing: error)))
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
                let fabric = self.fabric
                return .run { send in
                    do {
                        let sig = try await keychain.signWithBiometric(
                            KeychainBackedRootSigner.Account.signingKey,
                            challenge.signingBytes()
                        )
                        let rootHex = (try? await fabric.loadFabric()?.rootPubkeyHex) ?? ""
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

            case let .pairReadyToApprove(preview, host):
                state = .pairApprove(ApprovalFeature.State(preview: preview, host: host))
                return .none

            case let .pairLoadFailed(message):
                state = .error(message: message)
                return .none

            case .approve(.approveCompleted):
                state = .done(message: "Connected to gateway")
                return .none

            case .approve:
                return .none

            // MARK: Dismiss

            case .dismissTapped:
                return .none
            }
        }
        .ifCaseLet(\.scan, action: \.scan) {
            ScanFeature<SessionTicket>(parse: { payload in
                try SessionTicket.decode(urlSafeBase64: payload)
            })
        }
        .ifCaseLet(\.pairApprove, action: \.approve) {
            ApprovalFeature()
        }
    }
}

/// Read the fabric once and convert its host columns to a `HostInfo` on
/// `MainActor` (SwiftData `@Model` properties require it).
private func loadHostInfo(fabric: FabricClient) async throws -> HostInfo? {
    guard let hh = try await fabric.loadFabric() else { return nil }
    return await MainActor.run {
        guard let endpointIdHex = hh.hostEndpointIdHex else { return nil as HostInfo? }
        return HostInfo(
            endpointIdHex: endpointIdHex,
            addrs: hh.hostDirectAddrs,
            relay: hh.hostRelayURL,
            hintExpiresAtMs: hh.hostHintExpiresAtMs ?? 0,
            serverName: nil
        )
    }
}
