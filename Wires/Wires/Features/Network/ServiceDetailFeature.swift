import ComposableArchitecture
import Foundation

@Reducer
struct ServiceDetailFeature {
    @ObservableState
    struct State: Equatable, Identifiable {
        var id: String { summary.id }
        var summary: ServiceSummary
    }

    enum Action { case onAppear }

    var body: some Reducer<State, Action> {
        EmptyReducer()
    }
}
