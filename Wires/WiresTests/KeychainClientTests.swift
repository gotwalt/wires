import Foundation
import Testing
@testable import Wires

/// Non-biometric paths only — biometric signing requires real hardware and is
/// exercised in WiresUITests / manual acceptance. Each test scopes its work
/// to a unique service so accidental cross-test bleed is impossible.
struct KeychainClientTests {
    private func makeClient(_ service: String) -> KeychainClient {
        KeychainClient.live(service: service)
    }

    @Test func setGetRoundTrip() async throws {
        let service = "wires.test.\(UUID().uuidString)"
        let client = makeClient(service)
        let payload = Data([0x01, 0x02, 0x03, 0x04])
        try client.setData("rootpub", payload, .afterFirstUnlockThisDeviceOnly)
        let got = try client.getData("rootpub")
        #expect(got == payload)
        try client.deleteData("rootpub")
    }

    @Test func deleteRemovesItem() async throws {
        let service = "wires.test.\(UUID().uuidString)"
        let client = makeClient(service)
        try client.setData("foo", Data([0xAA]), .afterFirstUnlockThisDeviceOnly)
        try client.deleteData("foo")
        let got = try client.getData("foo")
        #expect(got == nil)
    }

    @Test func missingItemReturnsNil() async throws {
        let service = "wires.test.\(UUID().uuidString)"
        let client = makeClient(service)
        let got = try client.getData("never-written")
        #expect(got == nil)
    }

    @Test func setTwiceOverwrites() async throws {
        let service = "wires.test.\(UUID().uuidString)"
        let client = makeClient(service)
        try client.setData("k", Data([0x01]), .afterFirstUnlockThisDeviceOnly)
        try client.setData("k", Data([0x02, 0x03]), .afterFirstUnlockThisDeviceOnly)
        let got = try client.getData("k")
        #expect(got == Data([0x02, 0x03]))
        try client.deleteData("k")
    }
}
