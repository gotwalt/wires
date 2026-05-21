import Foundation
import SwiftData

@Model
final class Fabric {
    @Attribute(.unique) var rootPubkeyHex: String
    var createdAt: Date

    // Host info, populated from the scanned/pasted HostTicket at bootstrap
    // step 1. hostEndpointIdHex is permanent; addrs / relay are short-TTL
    // hints that iroh re-resolves. hostHintExpiresAtMs is recorded for future
    // re-scan UX but not enforced in v1. hostServerName is the operator-set
    // friendly label from HostTicket.server_name (nil for legacy hosts).
    var hostEndpointIdHex: String?
    var hostServerName: String?
    var hostDirectAddrs: [String]
    var hostRelayURL: String?
    var hostHintExpiresAtMs: Int64?
    var capsTopicIdHex: String?
    var tenantRegisteredAt: Date?

    @Relationship(deleteRule: .cascade) var topics: [TopicRecord]
    @Relationship(deleteRule: .cascade) var caps: [CapRecord]

    init(
        rootPubkeyHex: String,
        createdAt: Date = .now,
        hostEndpointIdHex: String? = nil,
        hostServerName: String? = nil,
        hostDirectAddrs: [String] = [],
        hostRelayURL: String? = nil,
        hostHintExpiresAtMs: Int64? = nil,
        capsTopicIdHex: String? = nil,
        tenantRegisteredAt: Date? = nil
    ) {
        self.rootPubkeyHex = rootPubkeyHex
        self.createdAt = createdAt
        self.hostEndpointIdHex = hostEndpointIdHex
        self.hostServerName = hostServerName
        self.hostDirectAddrs = hostDirectAddrs
        self.hostRelayURL = hostRelayURL
        self.hostHintExpiresAtMs = hostHintExpiresAtMs
        self.capsTopicIdHex = capsTopicIdHex
        self.tenantRegisteredAt = tenantRegisteredAt
        self.topics = []
        self.caps = []
    }
}
