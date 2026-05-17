import Foundation
import SwiftData

@Model
final class TopicRecord {
    @Attribute(.unique) var topicIdHex: String
    var name: String
    var createdAt: Date
    var currentEpoch: Int  // SwiftData prefers Int over UInt32
    var registeredWithHost: Bool

    init(
        topicIdHex: String,
        name: String,
        createdAt: Date = .now,
        currentEpoch: Int = 0,
        registeredWithHost: Bool = false
    ) {
        self.topicIdHex = topicIdHex
        self.name = name
        self.createdAt = createdAt
        self.currentEpoch = currentEpoch
        self.registeredWithHost = registeredWithHost
    }
}
