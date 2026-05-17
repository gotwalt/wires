import Foundation
import Testing
import WiresKit
@testable import Wires

/// Deterministic-without-network tests for the live WiresClient. Live network
/// calls (register..., approve...) are exercised in WiresApp-side Rust tests
/// and in feature-level reducer tests via testValue.
struct WiresClientLiveTests {
    @Test func bootstrapEnablesSyncCalls() async {
        let client = WiresClient.liveValue
        let secret = Data(repeating: 0xAB, count: 32)
        let signer = FakeSigner()
        await client.bootstrap(secret, signer)

        let topic = await client.generateTopicIdAndEpoch0()
        #expect(topic.topicIdHex.count == 64)
        #expect(topic.epoch0Key.count == 32)
    }

    @Test func parseHostTicketRejectsGarbage() async {
        let client = WiresClient.liveValue
        let signer = FakeSigner()
        await client.bootstrap(Data(repeating: 0x00, count: 32), signer)

        await #expect(throws: Error.self) {
            _ = try await client.parseHostTicket("not a ticket")
        }
    }

    @Test func parsePairRequestRejectsGarbage() async {
        let client = WiresClient.liveValue
        let signer = FakeSigner()
        await client.bootstrap(Data(repeating: 0x00, count: 32), signer)

        await #expect(throws: Error.self) {
            _ = try await client.parsePairRequest("nope")
        }
    }
}

/// Minimal `SwiftRootSigner` for tests — returns a fixed pubkey and signs
/// with a deterministic signature stub.
private final class FakeSigner: SwiftRootSigner, @unchecked Sendable {
    func pubkey() -> Data {
        Data(repeating: 0xFE, count: 32)
    }
    func sign(message: Data) throws -> Data {
        Data(repeating: 0x55, count: 64)
    }
}
