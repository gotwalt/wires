import ComposableArchitecture
import Dependencies
import Foundation
import SwiftData

/// Errors `FabricClient` operations can surface.
enum FabricError: Error, Equatable {
    case notFound
    case persistenceFailed(String)
}

/// Persistence facade for the fabric root, topic registry, and cap
/// registry. The `liveValue` is backed by a `ModelContainer`; reducers stay
/// I/O-free and exercise this client through `withDependencies`.
@DependencyClient
struct FabricClient {
    var loadFabric: @Sendable () async throws -> Fabric?
    var saveFabric: @Sendable (_ fabric: Fabric) async throws -> Void
    var refreshHostInfo: @Sendable (
        _ endpointIdHex: String,
        _ addrs: [String],
        _ relay: String?,
        _ hintExpiresAtMs: Int64
    ) async throws -> Void
    var listTopics: @Sendable () async throws -> [TopicRecord]
    var saveTopic: @Sendable (_ topic: TopicRecord) async throws -> Void
    var markTopicRegistered: @Sendable (_ topicIdHex: String) async throws -> Void
    var listCaps: @Sendable () async throws -> [CapRecord]
    var saveCap: @Sendable (_ cap: CapRecord) async throws -> Void
    /// Mark a cap as locally revoked. Thin wrapper that sets
    /// `revokedAt = .now` on the matching CapRecord row. The
    /// substrate-level revoke broadcast lands in a later phase.
    var revokeCap: @Sendable (_ capIdHex: String) async throws -> Void
    /// Delete every Fabric, TopicRecord, and CapRecord row.
    var wipeAll: @Sendable () async throws -> Void
}

extension FabricClient: DependencyKey {
    static let liveValue: FabricClient = .live()

    static func live(
        container: ModelContainer = FabricClient.makeDefaultContainer()
    ) -> FabricClient {
        let store = FabricStore(container: container)
        return FabricClient(
            loadFabric: { try await store.loadFabric() },
            saveFabric: { try await store.save($0) },
            refreshHostInfo: { eid, addrs, relay, hint in
                try await store.refreshHostInfo(
                    endpointIdHex: eid,
                    addrs: addrs,
                    relay: relay,
                    hintExpiresAtMs: hint
                )
            },
            listTopics: { try await store.listTopics() },
            saveTopic: { try await store.save($0) },
            markTopicRegistered: { try await store.markTopicRegistered(topicIdHex: $0) },
            listCaps: { try await store.listCaps() },
            saveCap: { try await store.save($0) },
            revokeCap: { try await store.revokeCap(capIdHex: $0) },
            wipeAll: { try await store.wipeAll() }
        )
    }

    static func makeDefaultContainer() -> ModelContainer {
        do {
            let schema = Schema([Fabric.self, TopicRecord.self, CapRecord.self])
            let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false)
            return try ModelContainer(for: schema, configurations: [config])
        } catch {
            fatalError("Failed to create ModelContainer: \(error)")
        }
    }

    static func makeInMemoryContainer() -> ModelContainer {
        do {
            let schema = Schema([Fabric.self, TopicRecord.self, CapRecord.self])
            let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
            return try ModelContainer(for: schema, configurations: [config])
        } catch {
            fatalError("Failed to create in-memory ModelContainer: \(error)")
        }
    }
}

extension DependencyValues {
    var fabricClient: FabricClient {
        get { self[FabricClient.self] }
        set { self[FabricClient.self] = newValue }
    }
}

/// Concrete SwiftData-backed implementation. Each method opens a fresh
/// `ModelContext` on the main actor, performs the read/write, and returns
/// detached value snapshots so callers don't hold long-lived model refs.
@MainActor
private final class FabricStore {
    let container: ModelContainer

    init(container: ModelContainer) {
        self.container = container
    }

    func loadFabric() throws -> Fabric? {
        let ctx = ModelContext(container)
        let descriptor = FetchDescriptor<Fabric>()
        let all = try ctx.fetch(descriptor)
        return all.first
    }

    func save(_ fabric: Fabric) throws {
        let ctx = ModelContext(container)
        ctx.insert(fabric)
        try ctx.save()
    }

    func refreshHostInfo(
        endpointIdHex: String,
        addrs: [String],
        relay: String?,
        hintExpiresAtMs: Int64
    ) throws {
        let ctx = ModelContext(container)
        let descriptor = FetchDescriptor<Fabric>()
        guard let h = try ctx.fetch(descriptor).first else {
            throw FabricError.notFound
        }
        h.hostEndpointIdHex = endpointIdHex
        h.hostDirectAddrs = addrs
        h.hostRelayURL = relay
        h.hostHintExpiresAtMs = hintExpiresAtMs
        try ctx.save()
    }

    func listTopics() throws -> [TopicRecord] {
        let ctx = ModelContext(container)
        let descriptor = FetchDescriptor<TopicRecord>(sortBy: [SortDescriptor(\.createdAt)])
        return try ctx.fetch(descriptor)
    }

    func save(_ topic: TopicRecord) throws {
        let ctx = ModelContext(container)
        ctx.insert(topic)
        try ctx.save()
    }

    func markTopicRegistered(topicIdHex: String) throws {
        let ctx = ModelContext(container)
        let descriptor = FetchDescriptor<TopicRecord>(
            predicate: #Predicate { $0.topicIdHex == topicIdHex }
        )
        guard let t = try ctx.fetch(descriptor).first else {
            throw FabricError.notFound
        }
        t.registeredWithHost = true
        try ctx.save()
    }

    func listCaps() throws -> [CapRecord] {
        let ctx = ModelContext(container)
        let descriptor = FetchDescriptor<CapRecord>(sortBy: [SortDescriptor(\.issuedAt)])
        return try ctx.fetch(descriptor)
    }

    func save(_ cap: CapRecord) throws {
        let ctx = ModelContext(container)
        ctx.insert(cap)
        try ctx.save()
    }

    func revokeCap(capIdHex: String) throws {
        let ctx = ModelContext(container)
        let descriptor = FetchDescriptor<CapRecord>(
            predicate: #Predicate { $0.capIdHex == capIdHex }
        )
        guard let cap = try ctx.fetch(descriptor).first else {
            throw FabricError.notFound
        }
        cap.revokedAt = .now
        try ctx.save()
    }

    func wipeAll() throws {
        let ctx = ModelContext(container)
        // Delete in dependency-free order. The schema has no cascades wired
        // up, so each entity is dropped independently.
        for h in try ctx.fetch(FetchDescriptor<Fabric>()) {
            ctx.delete(h)
        }
        for t in try ctx.fetch(FetchDescriptor<TopicRecord>()) {
            ctx.delete(t)
        }
        for c in try ctx.fetch(FetchDescriptor<CapRecord>()) {
            ctx.delete(c)
        }
        try ctx.save()
    }
}
