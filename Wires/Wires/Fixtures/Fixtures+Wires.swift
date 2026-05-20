import Foundation
import WiresKit

extension WiresClient {
    /// No-op fixture. Every method returns a stub value or no-op
    /// completes. Suitable for any fixture screen that doesn't actually
    /// invoke FFI — which is all of them, because fixture mode skips
    /// `prepareWiresApp` and the seeded AppFeature.State puts the user
    /// past any view that would dispatch a Wires effect on its own.
    static func fixture() -> WiresClient {
        WiresClient(
            bootstrap: { _, _ in },
            parseHostTicket: { _ in
                HostInfo(
                    endpointIdHex: String(repeating: "ab", count: 32),
                    addrs: ["10.0.0.1:4242"],
                    relay: nil,
                    hintExpiresAtMs: 0,
                    serverName: nil
                )
            },
            registerWithHostedService: { _ in
                TenantRegistration(
                    capsTopicIdHex: String(repeating: "cd", count: 32),
                    hostEndpointIdHex: String(repeating: "ab", count: 32),
                    serverTimeMs: 0
                )
            },
            registerTopic: { _, _ in },
            unregisterTenant: { _ in
                UnregisterResult(ok: true, topicsRemoved: 0)
            },
            parsePairRequest: { _ in
                PairRequestPreview(
                    handle: PendingPairHandle(id: "fixture-pending-pair"),
                    agentPubkeyHex: String(repeating: "ef", count: 32),
                    role: "agent",
                    description: "Aaron's Mac",
                    issuedAtMs: 0,
                    expiresAtMs: 0,
                    requestedScopes: [],
                    dialSummary: ""
                )
            },
            generateTopicIdAndEpoch0: {
                NewTopic(topicIdHex: String(repeating: "00", count: 32), epoch0Key: Data(repeating: 0, count: 32))
            },
            approvePairRequest: { _, _, _ in
                PairAckRecord(
                    installedCapIdHex: String(repeating: "11", count: 32),
                    installedAtMs: 0
                )
            },
            discardPairRequest: { _ in },
            reset: { }
        )
    }
}
