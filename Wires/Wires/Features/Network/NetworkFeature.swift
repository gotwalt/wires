import ComposableArchitecture
import Foundation

@Reducer
struct NetworkFeature {
    @ObservableState
    struct State: Equatable {
        var rootPubkeyHex: String
        var services: [ServiceSummary] = []
        var loading = false
        var loadError: String?
        @Presents var connect: ConnectFeature.State?
        var path = StackState<ServiceDetailFeature.State>()
    }

    @CasePathable
    enum Action {
        case onAppear
        case loaded([ServiceSummary])
        case loadFailed(String)
        case plusTapped
        case connect(PresentationAction<ConnectFeature.Action>)
        case path(StackActionOf<ServiceDetailFeature>)
        case rowTapped(ServiceSummary)
    }

    @Dependency(\.fabricClient) var fabric

    var body: some Reducer<State, Action> {
        Reduce { state, action in
            switch action {
            case .onAppear:
                // Don't clobber state that a fixture (or a prior load)
                // has already populated. Snapshot fixtures seed
                // `services` directly and rely on this short-circuit
                // so the .task-driven refresh doesn't overwrite the
                // seeded list with an empty CapRecord query.
                if FixtureRuntime.isActive
                    && (!state.services.isEmpty || state.loading || state.loadError != nil) {
                    return .none
                }
                state.loading = true
                state.loadError = nil
                let fabric = self.fabric
                return .run { send in
                    do {
                        let caps = try await fabric.listCaps()
                        let summaries = caps.map(CapToServiceMapper.summary(from:))
                        await send(.loaded(summaries))
                    } catch {
                        await send(.loadFailed(String(describing: error)))
                    }
                }

            case let .loaded(services):
                state.loading = false
                state.loadError = nil
                state.services = services
                return .none

            case let .loadFailed(message):
                state.loading = false
                state.loadError = message
                return .none

            case .plusTapped:
                state.connect = ConnectFeature.State.initial()
                return .none

            case .connect(.dismiss):
                state.connect = nil
                return .send(.onAppear)

            case .connect:
                return .none

            case let .rowTapped(summary):
                state.path.append(ServiceDetailFeature.State(summary: summary))
                return .none

            case .path:
                return .none
            }
        }
        .ifLet(\.$connect, action: \.connect) { ConnectFeature() }
        .forEach(\.path, action: \.path) { ServiceDetailFeature() }
    }
}
