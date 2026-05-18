import ComposableArchitecture
import Foundation
import Testing
import WiresKit
@testable import Wires

@MainActor
struct NodeEnrollmentFeatureTests {
    static let host = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: ["127.0.0.1:11204"],
        relay: nil,
        hintExpiresAtMs: 0
    )

    static let samplePreview = PairRequestPreview(
        handle: PendingPairHandle(id: "pp-1"),
        agentPubkeyHex: String(repeating: "ee", count: 32),
        role: "chat",
        description: "Bob's laptop",
        issuedAtMs: 1_700_000_000_000,
        expiresAtMs: 1_700_000_300_000,
        requestedScopes: [
            RequestedScopePreview(topicName: "home.chat", rights: [.read, .write])
        ],
        dialSummary: "127.0.0.1:8001"
    )

    @Test
    func scan_decodedPayload_transitionsToApprove() async {
        let store = TestStore(initialState: NodeEnrollmentFeature.State.initial(host: Self.host)) {
            NodeEnrollmentFeature()
        }

        await store.send(.scan(.decodedPayload(Self.samplePreview))) {
            $0 = .approve(ApprovalFeature.State(preview: Self.samplePreview, host: Self.host))
        }
    }

    @Test
    func approveCompleted_transitionsToDone() async {
        let initialApprove = ApprovalFeature.State(preview: Self.samplePreview, host: Self.host)
        let store = TestStore(initialState: NodeEnrollmentFeature.State.approve(initialApprove)) {
            NodeEnrollmentFeature()
        }

        let ack = PairAckRecord(installedCapIdHex: String(repeating: "aa", count: 16), installedAtMs: 1_700_000_001_000)
        await store.send(.approve(.approveCompleted(ack))) {
            $0 = .done(NodeEnrollmentFeature.DoneStepState(ack: ack, preview: Self.samplePreview))
        }
    }

    @Test
    func continueTapped_fromDone_emitsCompleted() async {
        let ack = PairAckRecord(installedCapIdHex: String(repeating: "aa", count: 16), installedAtMs: 1_700_000_001_000)
        let store = TestStore(initialState: NodeEnrollmentFeature.State.done(.init(ack: ack, preview: Self.samplePreview))) {
            NodeEnrollmentFeature()
        }

        await store.send(.continueTapped)
        await store.receive(\.completed, ack)
    }
}
