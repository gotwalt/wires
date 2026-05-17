import Foundation
import SwiftData

@Model
final class CapRecord {
    @Attribute(.unique) var capIdHex: String
    var agentPubkeyHex: String
    var agentAlias: String?
    var topicNames: [String]
    var rights: [String]
    var issuedAt: Date
    var expiresAt: Date?
    var revokedAt: Date?

    init(
        capIdHex: String,
        agentPubkeyHex: String,
        agentAlias: String? = nil,
        topicNames: [String] = [],
        rights: [String] = [],
        issuedAt: Date = .now,
        expiresAt: Date? = nil,
        revokedAt: Date? = nil
    ) {
        self.capIdHex = capIdHex
        self.agentPubkeyHex = agentPubkeyHex
        self.agentAlias = agentAlias
        self.topicNames = topicNames
        self.rights = rights
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
    }
}
