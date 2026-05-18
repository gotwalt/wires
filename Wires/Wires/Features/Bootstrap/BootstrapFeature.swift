import ComposableArchitecture
import SwiftUI

@Reducer
struct BootstrapFeature {
    @ObservableState
    struct State: Equatable {}

    enum Action {
        case onAppear
    }

    var body: some Reducer<State, Action> {
        Reduce { _, _ in .none }
    }
}

struct BootstrapView: View {
    let store: StoreOf<BootstrapFeature>

    var body: some View {
        VStack(spacing: 12) {
            Text("Bootstrap")
                .font(.title2)
            Text("Scan a host ticket to pair this household.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)
        }
    }
}
