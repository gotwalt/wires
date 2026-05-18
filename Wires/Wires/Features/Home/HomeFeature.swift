import ComposableArchitecture
import Foundation

@Reducer
struct HomeFeature {
    @ObservableState
    struct State: Equatable {
        var rootPubkeyHex: String
        var caps: [CapSummary] = []
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

    @CasePathable
    enum Action {
        case onAppear
        case capsLoaded([CapSummary])
        case capsLoadFailed(String)
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
                        let summaries = await MainActor.run {
                            records.map { rec in
                                CapSummary(
                                    id: rec.capIdHex,
                                    nodePubkeyHex: rec.nodePubkeyHex,
                                    nodeAlias: rec.nodeAlias,
                                    topicNames: rec.topicNames,
                                    rights: rec.rights,
                                    issuedAt: rec.issuedAt,
                                    revokedAt: rec.revokedAt
                                )
                            }
                        }
                        await send(.capsLoaded(summaries))
                    } catch {
                        await send(.capsLoadFailed(String(describing: error)))
                    }
                }

            case let .capsLoaded(summaries):
                state.loading = false
                state.caps = summaries
                return .none

            case let .capsLoadFailed(message):
                state.loading = false
                state.loadError = message
                return .none

            case .approveNodeTapped:
                state.nodeEnrollment = NodeEnrollmentFeature.State()
                return .none

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
