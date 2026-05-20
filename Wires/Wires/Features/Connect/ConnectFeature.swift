import ComposableArchitecture
import Foundation

@Reducer
struct ConnectFeature {
    @ObservableState
    struct State: Equatable {
        static func initial() -> State { State() }
    }

    enum Action {}

    var body: some Reducer<State, Action> { EmptyReducer() }
}
