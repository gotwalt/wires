import Foundation
import Testing
@testable import Wires

@Suite("CapToServiceMapper")
struct CapToServiceMapperTests {
    @Test("active cap maps to .connected status")
    func activeStatus() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "bb",
            nodeAlias: "Aaron's Mac",
            topicNames: ["family"],
            rights: ["read", "write"],
            issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.status == .connected)
        #expect(s.id == "aa")
        #expect(s.name == "Aaron's Mac")
        #expect(s.deviceName == nil)  // alias used as name when device unknown
    }

    @Test("revoked cap maps to .revoked status")
    func revokedStatus() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "bb",
            nodeAlias: "Aaron's Mac",
            topicNames: ["family"],
            rights: ["read"],
            issuedAt: Date(timeIntervalSince1970: 1_715_000_000),
            revokedAt: Date(timeIntervalSince1970: 1_715_100_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.status == .revoked)
    }

    @Test("rights produce a ScopeDescriptor per topic with detail rows")
    func scopeMapping() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "bb",
            nodeAlias: "Mac",
            topicNames: ["family"],
            rights: ["read", "write"],
            issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.scopes.count == 1)
        let scope = s.scopes[0]
        #expect(scope.id == "family")
        #expect(scope.detail.contains { $0.kind == .read && $0.granted })
        #expect(scope.detail.contains { $0.kind == .write && $0.granted })
    }

    @Test("nil nodeAlias falls back to a generic name")
    func anonymousNode() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "cccccccc",
            nodeAlias: nil,
            topicNames: ["mqtt:hass"],
            rights: ["read", "write"],
            issuedAt: Date(timeIntervalSince1970: 1_715_300_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.name == "Service")
    }

    @Test("default category is .unknown")
    func defaultCategory() {
        let cap = CapRecord(
            capIdHex: "aa",
            nodePubkeyHex: "bb",
            nodeAlias: "Mac",
            topicNames: ["family"],
            rights: ["read"],
            issuedAt: Date(timeIntervalSince1970: 1_715_000_000)
        )
        let s = CapToServiceMapper.summary(from: cap)
        #expect(s.category == .unknown)
    }
}
