import Foundation
import WiresKit

extension HouseholdClient {
    /// Canned in-memory household for snapshot fixtures. Returns
    /// fully-constructed (but never persisted) SwiftData @Model
    /// instances. Writes are no-ops. Use the `block` flag on
    /// `listCapsBehavior` to simulate the loading spinner.
    static func fixture(
        household: Household? = nil,
        caps: [CapRecord] = [],
        topics: [TopicRecord] = [],
        listCapsBehavior: ListBehavior = .return
    ) -> HouseholdClient {
        HouseholdClient(
            loadHousehold: { household },
            saveHousehold: { _ in },
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
                }
            },
            saveCap: { _ in },
            wipeAll: { }
        )
    }

    enum ListBehavior: Sendable {
        /// Return `caps` immediately.
        case `return`
        /// Sleep 60 s before returning. Use for `home_loading` so the
        /// reducer's loading=true state is captured.
        case block
    }
}
