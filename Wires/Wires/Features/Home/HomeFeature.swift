import ComposableArchitecture
import Foundation
import WiresKit

@Reducer
struct HomeFeature {
    @ObservableState
    struct State: Equatable {
        var rootPubkeyHex: String
        var caps: [CapSummary] = []
        var host: HostInfo?
        var loading = false
        var loadError: String?
        @Presents var nodeEnrollment: NodeEnrollmentFeature.State?
    }

    /// Equatable value snapshot of `CapRecord`. We don't pass SwiftData
    /// `@Model` instances across actor boundaries — the snapshot lets the
    /// reducer stay Sendable-friendly.
    struct CapSummary: Equatable, Identifiable, Sendable {
        let id: String  // capIdHex
        let nodePubkeyHex: String
        let nodeAlias: String?
        let topicNames: [String]
        let rights: [String]
        let issuedAt: Date
        let revokedAt: Date?
    }

    struct LoadedSnapshot: Equatable, Sendable {
        let caps: [CapSummary]
        let host: HostInfo?
    }

    @CasePathable
    enum Action {
        case onAppear
        case loaded(LoadedSnapshot)
        case loadFailed(String)
        case approveNodeTapped
        case nodeEnrollment(PresentationAction<NodeEnrollmentFeature.Action>)
    }

    @Dependency(\.householdClient) var household

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                state.loading = true
                state.loadError = nil
                let household = self.household
                return .run { send in
                    do {
                        let records = try await household.listCaps()
                        let hh = try await household.loadHousehold()
                        let snapshot = await MainActor.run {
                            LoadedSnapshot(
                                caps: records.map { rec in
                                    CapSummary(
                                        id: rec.capIdHex,
                                        nodePubkeyHex: rec.nodePubkeyHex,
                                        nodeAlias: rec.nodeAlias,
                                        topicNames: rec.topicNames,
                                        rights: rec.rights,
                                        issuedAt: rec.issuedAt,
                                        revokedAt: rec.revokedAt
                                    )
                                },
                                host: hh.flatMap(hostInfo(from:))
                            )
                        }
                        await send(.loaded(snapshot))
                    } catch {
                        await send(.loadFailed(String(describing: error)))
                    }
                }

            case let .loaded(snapshot):
                state.loading = false
                state.caps = snapshot.caps
                state.host = snapshot.host
                return .none

            case let .loadFailed(message):
                state.loading = false
                state.loadError = message
                return .none

            case .approveNodeTapped:
                guard let host = state.host else { return .none }
                state.nodeEnrollment = .initial(host: host)
                return .none

            // Enrollment completed: dismiss the sheet and refresh caps so
            // the newly-installed cap shows up.
            case .nodeEnrollment(.presented(.completed)):
                state.nodeEnrollment = nil
                return .send(.onAppear)

            case .nodeEnrollment(.presented(.dismissTapped)),
                 .nodeEnrollment(.dismiss):
                state.nodeEnrollment = nil
                return .none

            case .nodeEnrollment:
                return .none
            }
        }
        .ifLet(\.$nodeEnrollment, action: \.nodeEnrollment) {
            NodeEnrollmentFeature()
        }
    }
}

/// MainActor-only because it reads SwiftData @Model properties.
@MainActor
private func hostInfo(from household: Household) -> HostInfo? {
    guard let endpointIdHex = household.hostEndpointIdHex else { return nil }
    return HostInfo(
        endpointIdHex: endpointIdHex,
        addrs: household.hostDirectAddrs,
        relay: household.hostRelayURL,
        hintExpiresAtMs: household.hostHintExpiresAtMs ?? 0
    )
}
