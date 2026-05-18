import ComposableArchitecture
import Foundation
import WiresKit

@Reducer
struct ApprovalFeature {
    @ObservableState
    struct State: Equatable {
        let preview: PairRequestPreview
        let host: HostInfo
        var decisions: IdentifiedArrayOf<ScopeDecision>
        var submitting = false
        var error: String?

        init(preview: PairRequestPreview, host: HostInfo) {
            self.preview = preview
            self.host = host
            self.decisions = IdentifiedArray(
                uniqueElements: preview.requestedScopes.map { scope in
                    ScopeDecision(
                        id: scope.topicName,
                        topicName: scope.topicName,
                        requestedRights: scope.rights,
                        grantedRights: scope.rights,
                        granted: true
                    )
                }
            )
        }
    }

    struct ScopeDecision: Equatable, Identifiable, Sendable {
        let id: String
        let topicName: String
        let requestedRights: [Right]
        var grantedRights: [Right]
        var granted: Bool
    }

    @CasePathable
    enum Action {
        case toggleScope(id: String, granted: Bool)
        case toggleRight(id: String, right: Right, on: Bool)
        case approveTapped
        case retryTapped
        case dismissErrorTapped
        case approveSucceeded(PairAckRecord)
        case approveFailed(String)

        /// Delegate: fires once after the approve effect chain has
        /// persisted the CapRecord. The parent (`NodeEnrollmentFeature`)
        /// listens for this.
        case approveCompleted(PairAckRecord)
    }

    @Dependency(\.wiresClient) var wires
    @Dependency(\.householdClient) var household
    @Dependency(\.keychainClient) var keychain

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case let .toggleScope(id, granted):
                state.decisions[id: id]?.granted = granted
                return .none

            case let .toggleRight(id, right, on):
                guard var d = state.decisions[id: id] else { return .none }
                if on {
                    if !d.grantedRights.contains(right) {
                        d.grantedRights.append(right)
                    }
                } else {
                    d.grantedRights.removeAll { $0 == right }
                }
                state.decisions[id: id] = d
                return .none

            case .approveTapped, .retryTapped:
                state.submitting = true
                state.error = nil
                let preview = state.preview
                let host = state.host
                let decisions = Array(state.decisions)
                let wires = self.wires
                let household = self.household
                let keychain = self.keychain
                return .run { send in
                    do {
                        var granted: [GrantedScope] = []
                        for d in decisions where d.granted && !d.grantedRights.isEmpty {
                            let newTopic = await wires.generateTopicIdAndEpoch0()
                            guard let topicId = Data(wiresHex: newTopic.topicIdHex) else {
                                await send(.approveFailed("FFI returned malformed topic id"))
                                return
                            }
                            try await wires.registerTopic(host, topicId)
                            try await household.saveTopic(TopicRecord(
                                topicIdHex: newTopic.topicIdHex,
                                name: d.topicName,
                                registeredWithHost: true
                            ))
                            try keychain.setData(
                                account: "wires.topic.\(newTopic.topicIdHex).epoch.0",
                                value: newTopic.epoch0Key,
                                accessibility: .afterFirstUnlockThisDeviceOnly
                            )
                            granted.append(GrantedScope(
                                topicIdHex: newTopic.topicIdHex,
                                topicName: d.topicName,
                                rights: d.grantedRights,
                                epochs: [EpochKey(epoch: 0, key: newTopic.epoch0Key)]
                            ))
                        }
                        let ack = try await wires.approvePairRequest(preview.handle, granted, host)
                        try await household.saveCap(CapRecord(
                            capIdHex: ack.installedCapIdHex,
                            nodePubkeyHex: preview.agentPubkeyHex,
                            nodeAlias: preview.description.isEmpty ? nil : preview.description,
                            topicNames: granted.map(\.topicName),
                            rights: Array(Set(granted.flatMap { $0.rights.map(wiresRightString) })).sorted(),
                            issuedAt: Date(timeIntervalSince1970: TimeInterval(ack.installedAtMs) / 1000)
                        ))
                        await send(.approveSucceeded(ack))
                    } catch {
                        await send(.approveFailed(String(describing: error)))
                    }
                }

            case let .approveSucceeded(ack):
                state.submitting = false
                return .send(.approveCompleted(ack))

            case let .approveFailed(message):
                state.submitting = false
                state.error = message
                return .none

            case .dismissErrorTapped:
                state.error = nil
                return .none

            case .approveCompleted:
                return .none
            }
        }
    }
}
