import ComposableArchitecture
import Foundation

@Reducer
struct DeleteAccountFeature {
    @ObservableState
    struct State: Equatable {
        var confirmText: String = ""
        var confirmEnabled: Bool = false
    }

    enum Action {
        case confirmTextChanged(String)
        case confirmButtonTapped
        case cancelButtonTapped
        case confirmed
    }

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case let .confirmTextChanged(text):
                state.confirmText = text
                state.confirmEnabled = (text == "delete")
                return .none
            case .confirmButtonTapped:
                guard state.confirmEnabled else { return .none }
                return .send(.confirmed)
            case .cancelButtonTapped, .confirmed:
                return .none
            }
        }
    }
}
