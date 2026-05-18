import ComposableArchitecture
import Dependencies
import Foundation
import SwiftData

/// Errors `HouseholdClient` operations can surface.
enum HouseholdError: Error, Equatable {
    case notFound
    case persistenceFailed(String)
}

/// Persistence facade for the household root, topic registry, and cap
/// registry. The `liveValue` is backed by a `ModelContainer`; reducers stay
/// I/O-free and exercise this client through `withDependencies`.
@DependencyClient
struct HouseholdClient {
    var loadHousehold: @Sendable () async throws -> Household?
    var saveHousehold: @Sendable (_ household: Household) async throws -> Void
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
    /// Delete every Household, TopicRecord, and CapRecord row.
    var wipeAll: @Sendable () async throws -> Void
}

extension HouseholdClient: DependencyKey {
    static let liveValue: HouseholdClient = .live()

    static func live(
        container: ModelContainer = HouseholdClient.makeDefaultContainer()
    ) -> HouseholdClient {
        let store = HouseholdStore(container: container)
        return HouseholdClient(
            loadHousehold: { try await store.loadHousehold() },
            saveHousehold: { try await store.save($0) },
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
            wipeAll: { try await store.wipeAll() }
        )
    }

    static func makeDefaultContainer() -> ModelContainer {
        do {
            let schema = Schema([Household.self, TopicRecord.self, CapRecord.self])
            let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: false)
            return try ModelContainer(for: schema, configurations: [config])
        } catch {
            fatalError("Failed to create ModelContainer: \(error)")
        }
    }

    static func makeInMemoryContainer() -> ModelContainer {
        do {
            let schema = Schema([Household.self, TopicRecord.self, CapRecord.self])
            let config = ModelConfiguration(schema: schema, isStoredInMemoryOnly: true)
            return try ModelContainer(for: schema, configurations: [config])
        } catch {
            fatalError("Failed to create in-memory ModelContainer: \(error)")
        }
    }
}

extension DependencyValues {
    var householdClient: HouseholdClient {
        get { self[HouseholdClient.self] }
        set { self[HouseholdClient.self] = newValue }
    }
}

/// Concrete SwiftData-backed implementation. Each method opens a fresh
/// `ModelContext` on the main actor, performs the read/write, and returns
/// detached value snapshots so callers don't hold long-lived model refs.
@MainActor
private final class HouseholdStore {
    let container: ModelContainer

    init(container: ModelContainer) {
        self.container = container
    }

    func loadHousehold() throws -> Household? {
        let ctx = ModelContext(container)
        let descriptor = FetchDescriptor<Household>()
        let all = try ctx.fetch(descriptor)
        return all.first
    }

    func save(_ household: Household) throws {
        let ctx = ModelContext(container)
        ctx.insert(household)
        try ctx.save()
    }

    func refreshHostInfo(
        endpointIdHex: String,
        addrs: [String],
        relay: String?,
        hintExpiresAtMs: Int64
    ) throws {
        let ctx = ModelContext(container)
        let descriptor = FetchDescriptor<Household>()
        guard let h = try ctx.fetch(descriptor).first else {
            throw HouseholdError.notFound
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
            throw HouseholdError.notFound
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

    func wipeAll() throws {
        let ctx = ModelContext(container)
        // Delete in dependency-free order. The schema has no cascades wired
        // up, so each entity is dropped independently.
        for h in try ctx.fetch(FetchDescriptor<Household>()) {
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
