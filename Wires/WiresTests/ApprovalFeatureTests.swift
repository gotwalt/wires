import ComposableArchitecture
import Foundation
import Testing
import WiresKit
@testable import Wires

@MainActor
struct ApprovalFeatureTests {
    static let host = HostInfo(
        endpointIdHex: String(repeating: "cd", count: 32),
        addrs: ["127.0.0.1:11204"],
        relay: nil,
        hintExpiresAtMs: 0,
        serverName: nil
    )

    static let nodePubkey = String(repeating: "ee", count: 32)
    static let topicIdHex = String(repeating: "11", count: 32)
    static let secondTopicIdHex = String(repeating: "22", count: 32)
    static let epoch0 = Data(repeating: 0x77, count: 32)

    static func preview(scopes: [RequestedScopePreview]) -> PairRequestPreview {
        PairRequestPreview(
            handle: PendingPairHandle(id: "pp-1"),
            agentPubkeyHex: nodePubkey,
            role: "chat",
            description: "Bob's laptop",
            issuedAtMs: 1_700_000_000_000,
            expiresAtMs: 1_700_000_300_000,
            requestedScopes: scopes,
            dialSummary: "127.0.0.1:8001"
        )
    }

    static let ack = PairAckRecord(
        installedCapIdHex: String(repeating: "aa", count: 16),
        installedAtMs: 1_700_000_010_000
    )

    // MARK: - Happy path: new topic, full rights

    @Test
    func approve_newTopic_persistsTopicAndCap() async {
        let savedTopics = LockIsolated<[TopicRecord]>([])
        let savedCaps = LockIsolated<[CapRecord]>([])
        let savedEpochAccounts = LockIsolated<[String]>([])
        let approveCalled = LockIsolated(0)

        let preview = Self.preview(scopes: [
            RequestedScopePreview(topicName: "home.chat", rights: [.read, .write])
        ])
        let store = TestStore(
            initialState: ApprovalFeature.State(preview: preview, host: Self.host)
        ) {
            ApprovalFeature()
        } withDependencies: {
            $0.wiresClient.generateTopicIdAndEpoch0 = {
                NewTopic(topicIdHex: Self.topicIdHex, epoch0Key: Self.epoch0)
            }
            $0.wiresClient.registerTopic = { _, _ in }
            $0.wiresClient.approvePairRequest = { _, _, _ in
                approveCalled.withValue { $0 += 1 }
                return Self.ack
            }
            $0.fabricClient.saveTopic = { t in savedTopics.withValue { $0.append(t) } }
            $0.fabricClient.saveCap = { c in savedCaps.withValue { $0.append(c) } }
            $0.keychainClient.setData = { account, _, _ in
                savedEpochAccounts.withValue { $0.append(account) }
            }
        }

        await store.send(.approveTapped) {
            $0.submitting = true
        }
        await store.receive(\.approveSucceeded) {
            $0.submitting = false
        }
        await store.receive(\.approveCompleted, Self.ack)

        #expect(savedTopics.value.count == 1)
        #expect(savedTopics.value.first?.topicIdHex == Self.topicIdHex)
        #expect(savedTopics.value.first?.name == "home.chat")
        #expect(savedEpochAccounts.value == ["wires.topic.\(Self.topicIdHex).epoch.0"])
        #expect(savedCaps.value.count == 1)
        #expect(savedCaps.value.first?.capIdHex == Self.ack.installedCapIdHex)
        #expect(savedCaps.value.first?.nodePubkeyHex == Self.nodePubkey)
        #expect(savedCaps.value.first?.topicNames == ["home.chat"])
        #expect(savedCaps.value.first?.rights == ["read", "write"])
        #expect(approveCalled.value == 1)
    }

    // MARK: - Narrow rights — turning off write before approve

    @Test
    func toggleRight_off_narrowsGrantedRights() async {
        let savedCaps = LockIsolated<[CapRecord]>([])

        let preview = Self.preview(scopes: [
            RequestedScopePreview(topicName: "home.chat", rights: [.read, .write])
        ])
        let store = TestStore(
            initialState: ApprovalFeature.State(preview: preview, host: Self.host)
        ) {
            ApprovalFeature()
        } withDependencies: {
            $0.wiresClient.generateTopicIdAndEpoch0 = {
                NewTopic(topicIdHex: Self.topicIdHex, epoch0Key: Self.epoch0)
            }
            $0.wiresClient.registerTopic = { _, _ in }
            $0.wiresClient.approvePairRequest = { _, scopes, _ in
                #expect(scopes.count == 1)
                #expect(scopes.first?.rights == [.read])
                return Self.ack
            }
            $0.fabricClient.saveTopic = { _ in }
            $0.fabricClient.saveCap = { c in savedCaps.withValue { $0.append(c) } }
            $0.keychainClient.setData = { _, _, _ in }
        }

        await store.send(.toggleRight(id: "home.chat", right: .write, on: false)) {
            $0.decisions[id: "home.chat"]?.grantedRights = [.read]
        }
        await store.send(.approveTapped) { $0.submitting = true }
        await store.receive(\.approveSucceeded) { $0.submitting = false }
        await store.receive(\.approveCompleted, Self.ack)

        #expect(savedCaps.value.first?.rights == ["read"])
    }

    // MARK: - Deny a scope — multi-scope request, one denied

    @Test
    func toggleScope_off_skipsRegistrationForThatScope() async {
        let registered = LockIsolated<[String]>([])
        let granted = LockIsolated<[GrantedScope]>([])
        var generatedCount = 0

        let preview = Self.preview(scopes: [
            RequestedScopePreview(topicName: "home.chat", rights: [.read, .write]),
            RequestedScopePreview(topicName: "home.notes", rights: [.read]),
        ])
        let store = TestStore(
            initialState: ApprovalFeature.State(preview: preview, host: Self.host)
        ) {
            ApprovalFeature()
        } withDependencies: {
            $0.wiresClient.generateTopicIdAndEpoch0 = {
                generatedCount += 1
                let id = generatedCount == 1 ? Self.topicIdHex : Self.secondTopicIdHex
                return NewTopic(topicIdHex: id, epoch0Key: Self.epoch0)
            }
            $0.wiresClient.registerTopic = { _, topicId in
                registered.withValue { $0.append(topicId.map { String(format: "%02x", $0) }.joined()) }
            }
            $0.wiresClient.approvePairRequest = { _, scopes, _ in
                granted.withValue { $0 = scopes }
                return Self.ack
            }
            $0.fabricClient.saveTopic = { _ in }
            $0.fabricClient.saveCap = { _ in }
            $0.keychainClient.setData = { _, _, _ in }
        }

        await store.send(.toggleScope(id: "home.notes", granted: false)) {
            $0.decisions[id: "home.notes"]?.granted = false
        }
        await store.send(.approveTapped) { $0.submitting = true }
        await store.receive(\.approveSucceeded) { $0.submitting = false }
        await store.receive(\.approveCompleted, Self.ack)

        #expect(registered.value == [Self.topicIdHex])
        #expect(granted.value.count == 1)
        #expect(granted.value.first?.topicName == "home.chat")
    }

    // MARK: - Topic-register failure → error → retry → success

    @Test
    func registerTopicFails_surfacesError_retrySucceeds() async {
        let attempt = LockIsolated(0)
        let preview = Self.preview(scopes: [
            RequestedScopePreview(topicName: "home.chat", rights: [.read]),
        ])
        let store = TestStore(
            initialState: ApprovalFeature.State(preview: preview, host: Self.host)
        ) {
            ApprovalFeature()
        } withDependencies: {
            $0.wiresClient.generateTopicIdAndEpoch0 = {
                NewTopic(topicIdHex: Self.topicIdHex, epoch0Key: Self.epoch0)
            }
            $0.wiresClient.registerTopic = { _, _ in
                let n = attempt.withValue { $0 += 1; return $0 }
                if n == 1 { throw WiresError.TopicRegisterRejected(message: "transient") }
            }
            $0.wiresClient.approvePairRequest = { _, _, _ in Self.ack }
            $0.fabricClient.saveTopic = { _ in }
            $0.fabricClient.saveCap = { _ in }
            $0.keychainClient.setData = { _, _, _ in }
        }

        await store.send(.approveTapped) { $0.submitting = true }
        await store.receive(\.approveFailed) {
            $0.submitting = false
            $0.error = #"TopicRegisterRejected(message: "transient")"#
        }

        await store.send(.retryTapped) {
            $0.submitting = true
            $0.error = nil
        }
        await store.receive(\.approveSucceeded) { $0.submitting = false }
        await store.receive(\.approveCompleted, Self.ack)
    }

    // MARK: - Pair-deliver reject

    @Test
    func pairDeliverRejected_surfacesError() async {
        let preview = Self.preview(scopes: [
            RequestedScopePreview(topicName: "home.chat", rights: [.read]),
        ])
        let store = TestStore(
            initialState: ApprovalFeature.State(preview: preview, host: Self.host)
        ) {
            ApprovalFeature()
        } withDependencies: {
            $0.wiresClient.generateTopicIdAndEpoch0 = {
                NewTopic(topicIdHex: Self.topicIdHex, epoch0Key: Self.epoch0)
            }
            $0.wiresClient.registerTopic = { _, _ in }
            $0.wiresClient.approvePairRequest = { _, _, _ in
                throw WiresError.PairRejected(message: "node refused")
            }
            $0.fabricClient.saveTopic = { _ in }
            $0.fabricClient.saveCap = { _ in }
            $0.keychainClient.setData = { _, _, _ in }
        }

        await store.send(.approveTapped) { $0.submitting = true }
        await store.receive(\.approveFailed) {
            $0.submitting = false
            $0.error = #"PairRejected(message: "node refused")"#
        }
    }

    // MARK: - Pair-request expired

    @Test
    func pairRequestExpired_surfacesError() async {
        let preview = Self.preview(scopes: [
            RequestedScopePreview(topicName: "home.chat", rights: [.read]),
        ])
        let store = TestStore(
            initialState: ApprovalFeature.State(preview: preview, host: Self.host)
        ) {
            ApprovalFeature()
        } withDependencies: {
            $0.wiresClient.generateTopicIdAndEpoch0 = {
                NewTopic(topicIdHex: Self.topicIdHex, epoch0Key: Self.epoch0)
            }
            $0.wiresClient.registerTopic = { _, _ in }
            $0.wiresClient.approvePairRequest = { _, _, _ in
                throw WiresError.PairRequestExpired(message: "ttl elapsed")
            }
            $0.fabricClient.saveTopic = { _ in }
            $0.fabricClient.saveCap = { _ in }
            $0.keychainClient.setData = { _, _, _ in }
        }

        await store.send(.approveTapped) { $0.submitting = true }
        await store.receive(\.approveFailed) {
            $0.submitting = false
            $0.error = #"PairRequestExpired(message: "ttl elapsed")"#
        }
    }
}
