import Foundation
import WiresKit

extension FabricClient {
    /// Canned in-memory fabric for snapshot fixtures. Returns
    /// fully-constructed (but never persisted) SwiftData @Model
    /// instances. Writes are no-ops. Use the `block` flag on
    /// `listCapsBehavior` to simulate the loading spinner, or
    /// `.failing(_)` to surface a load-error banner.
    static func fixture(
        fabric: Fabric? = nil,
        caps: [CapRecord] = [],
        topics: [TopicRecord] = [],
        listCapsBehavior: ListBehavior = .return
    ) -> FabricClient {
        FabricClient(
            loadFabric: { fabric },
            saveFabric: { _ in },
            refreshHostInfo: { _, _, _, _ in },
            listTopics: { topics },
            saveTopic: { _ in },
            markTopicRegistered: { _ in },
            listCaps: {
                switch listCapsBehavior {
                case .return:
                    return caps
                case .block:
                    try? await Task.sleep(for: .seconds(60))
                    return caps
                case .failing(let message):
                    throw FixtureError(message: message)
                }
            },
            saveCap: { _ in },
            revokeCap: { _ in },
            wipeAll: { }
        )
    }

    enum ListBehavior: Sendable {
        /// Return `caps` immediately.
        case `return`
        /// Sleep 60 s before returning. Use for the loading
        /// spinner fixture so the reducer's loading=true state
        /// is captured.
        case block
        /// Surface the supplied message as a load error.
        case failing(String)
    }

    struct FixtureError: Error, CustomStringConvertible, Sendable {
        let message: String
        var description: String { message }
    }
}
