import ComposableArchitecture
import Foundation

@Reducer
struct ServiceDetailFeature {
    @ObservableState
    struct State: Equatable, Identifiable {
        var id: String { summary.id }
        var summary: ServiceSummary
        var confirmingDisconnect = false
        var disconnecting = false
        var disconnectError: String?
        var didDisconnect = false
        /// Whether the Advanced disclosure renders expanded on first
        /// appearance. Fixtures flip this to true to capture the
        /// expanded state without simulating a tap.
        var advancedInitiallyExpanded = false
    }

    enum Action {
        case onAppear
        case disconnectTapped
        case disconnectConfirmTapped
        case disconnectCancelTapped
        case disconnectSucceeded
        case disconnectFailed(String)
        case reconnectTapped // navigates the parent to ConnectFeature
    }

    @Dependency(\.fabricClient) var fabric
    @Dependency(\.wiresClient) var wires

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear: return .none

            case .disconnectTapped:
                state.confirmingDisconnect = true
                state.disconnectError = nil
                return .none

            case .disconnectCancelTapped:
                state.confirmingDisconnect = false
                return .none

            case .disconnectConfirmTapped:
                state.disconnecting = true
                let capId = state.summary.id
                let fabric = self.fabric
                return .run { send in
                    do {
                        try await fabric.revokeCap(capId)
                        await send(.disconnectSucceeded)
                    } catch {
                        await send(.disconnectFailed(String(describing: error)))
                    }
                }

            case .disconnectSucceeded:
                state.disconnecting = false
                state.confirmingDisconnect = false
                state.didDisconnect = true
                return .none

            case let .disconnectFailed(message):
                state.disconnecting = false
                state.disconnectError = message
                return .none

            case .reconnectTapped:
                return .none
            }
        }
    }
}
