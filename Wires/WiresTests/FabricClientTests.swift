import Foundation
import SwiftData
import Testing
@testable import Wires

@MainActor
struct FabricClientTests {
    @Test func saveAndLoadFabric() async throws {
        let container = FabricClient.makeInMemoryContainer()
        let client = FabricClient.live(container: container)

        try await client.saveFabric(
            Fabric(
                rootPubkeyHex: String(repeating: "ab", count: 32),
                hostEndpointIdHex: String(repeating: "cd", count: 32),
                hostDirectAddrs: ["127.0.0.1:11204"],
                hostRelayURL: "https://relay.example/",
                hostHintExpiresAtMs: 1_700_000_000_000
            )
        )

        let loaded = try await client.loadFabric()
        #expect(loaded != nil)
        #expect(loaded?.rootPubkeyHex == String(repeating: "ab", count: 32))
        #expect(loaded?.hostEndpointIdHex == String(repeating: "cd", count: 32))
        #expect(loaded?.hostDirectAddrs == ["127.0.0.1:11204"])
        #expect(loaded?.hostHintExpiresAtMs == 1_700_000_000_000)
    }

    @Test func saveAndListTopics() async throws {
        let container = FabricClient.makeInMemoryContainer()
        let client = FabricClient.live(container: container)

        try await client.saveTopic(
            TopicRecord(topicIdHex: String(repeating: "04", count: 32), name: "home.notes")
        )
        let topics = try await client.listTopics()
        #expect(topics.count == 1)
        #expect(topics.first?.name == "home.notes")
        #expect(topics.first?.registeredWithHost == false)

        try await client.markTopicRegistered(String(repeating: "04", count: 32))
        let reloaded = try await client.listTopics()
        #expect(reloaded.first?.registeredWithHost == true)
    }

    @Test func saveAndListCaps() async throws {
        let container = FabricClient.makeInMemoryContainer()
        let client = FabricClient.live(container: container)

        try await client.saveCap(
            CapRecord(
                capIdHex: String(repeating: "11", count: 16),
                nodePubkeyHex: String(repeating: "22", count: 32),
                nodeAlias: "chat-node: Bob",
                topicNames: ["home.notes"],
                rights: ["read", "write"]
            )
        )
        let caps = try await client.listCaps()
        #expect(caps.count == 1)
        #expect(caps.first?.nodeAlias == "chat-node: Bob")
        #expect(caps.first?.rights == ["read", "write"])
    }

    @Test func refreshHostInfoUpdatesPersistedFields() async throws {
        let container = FabricClient.makeInMemoryContainer()
        let client = FabricClient.live(container: container)

        try await client.saveFabric(
            Fabric(rootPubkeyHex: String(repeating: "ab", count: 32))
        )
        try await client.refreshHostInfo(
            String(repeating: "cd", count: 32),
            ["10.0.0.5:11204"],
            nil,
            1_800_000_000_000
        )

        let loaded = try await client.loadFabric()
        #expect(loaded?.hostEndpointIdHex == String(repeating: "cd", count: 32))
        #expect(loaded?.hostDirectAddrs == ["10.0.0.5:11204"])
        #expect(loaded?.hostRelayURL == nil)
        #expect(loaded?.hostHintExpiresAtMs == 1_800_000_000_000)
    }
}
