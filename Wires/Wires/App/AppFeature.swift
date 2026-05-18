import ComposableArchitecture
import Foundation

@Reducer
struct AppFeature {
    @ObservableState
    enum State: Equatable {
        case launching
        case bootstrap(BootstrapFeature.State)
        case home(HomeFeature.State)
    }

    enum Action {
        case onAppear
        case householdLoaded(HouseholdSummary?)
        case bootstrap(BootstrapFeature.Action)
        case home(HomeFeature.Action)
    }

    struct HouseholdSummary: Equatable, Sendable {
        let rootPubkeyHex: String
        let tenantRegisteredAt: Date?
    }

    @Dependency(\.householdClient) var household

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                return .run { send in
                    let snapshot: HouseholdSummary?
                    if let h = try? await household.loadHousehold() {
                        snapshot = await MainActor.run {
                            HouseholdSummary(
                                rootPubkeyHex: h.rootPubkeyHex,
                                tenantRegisteredAt: h.tenantRegisteredAt
                            )
                        }
                    } else {
                        snapshot = nil
                    }
                    await send(.householdLoaded(snapshot))
                }
            case let .householdLoaded(summary):
                if let summary, summary.tenantRegisteredAt != nil {
                    state = .home(HomeFeature.State(rootPubkeyHex: summary.rootPubkeyHex))
                } else {
                    state = .bootstrap(BootstrapFeature.State())
                }
                return .none
            case .bootstrap, .home:
                return .none
            }
        }
        .ifCaseLet(\.bootstrap, action: \.bootstrap) { BootstrapFeature() }
        .ifCaseLet(\.home, action: \.home) { HomeFeature() }
    }
}
