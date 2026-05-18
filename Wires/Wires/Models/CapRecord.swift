import Foundation
import SwiftData

@Model
final class CapRecord {
    @Attribute(.unique) var capIdHex: String
    var nodePubkeyHex: String
    var nodeAlias: String?
    var topicNames: [String]
    var rights: [String]
    var issuedAt: Date
    var expiresAt: Date?
    var revokedAt: Date?

    init(
        capIdHex: String,
        nodePubkeyHex: String,
        nodeAlias: String? = nil,
        topicNames: [String] = [],
        rights: [String] = [],
        issuedAt: Date = .now,
        expiresAt: Date? = nil,
        revokedAt: Date? = nil
    ) {
        self.capIdHex = capIdHex
        self.nodePubkeyHex = nodePubkeyHex
        self.nodeAlias = nodeAlias
        self.topicNames = topicNames
        self.rights = rights
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
    }
}
