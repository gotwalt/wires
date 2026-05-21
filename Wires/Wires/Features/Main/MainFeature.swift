import ComposableArchitecture
import Foundation

@Reducer
struct MainFeature {
    @ObservableState
    struct State: Equatable {
        var network: NetworkFeature.State
        var settings: SettingsFeature.State
        var selectedTab: Tab

        enum Tab: Hashable { case network, settings }
    }

    enum Action {
        case network(NetworkFeature.Action)
        case settings(SettingsFeature.Action)
        case tabSelected(State.Tab)
        /// Delegate fired when Settings (delete-account) wipes the
        /// fabric. AppFeature observes this and transitions back
        /// to `.launching`.
        case didReset
    }

    var body: some Reducer<State, Action> {
        Scope(state: \.network, action: \.network) { NetworkFeature() }
        Scope(state: \.settings, action: \.settings) { SettingsFeature() }
        Reduce { state, action in
            switch action {
            case let .tabSelected(tab):
                state.selectedTab = tab
                return .none
            case .settings(.accountDeleted):
                return .send(.didReset)
            case .network, .settings, .didReset:
                return .none
            }
        }
    }
}
