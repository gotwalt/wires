import ComposableArchitecture
import Foundation

@Reducer
struct MainFeature {
    @ObservableState
    struct State: Equatable {
        var home: HomeFeature.State
        var settings: SettingsFeature.State
        var selectedTab: Tab

        enum Tab: Hashable { case network, settings }
    }

    enum Action {
        case home(HomeFeature.Action)
        case settings(SettingsFeature.Action)
        case tabSelected(State.Tab)
    }

    var body: some Reducer<State, Action> {
        Scope(state: \.home, action: \.home) { HomeFeature() }
        Scope(state: \.settings, action: \.settings) { SettingsFeature() }
        Reduce { state, action in
            switch action {
            case let .tabSelected(tab):
                state.selectedTab = tab
                return .none
            case .home, .settings:
                return .none
            }
        }
    }
}
