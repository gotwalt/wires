import ComposableArchitecture
import SwiftUI

@Reducer
struct HomeFeature {
    @ObservableState
    struct State: Equatable {
        var rootPubkeyHex: String
    }

    enum Action {
        case onAppear
    }

    var body: some Reducer<State, Action> {
        Reduce { _, _ in .none }
    }
}

struct HomeView: View {
    let store: StoreOf<HomeFeature>

    var body: some View {
        VStack(spacing: 12) {
            Text("Household")
                .font(.title2)
            Text(store.rootPubkeyHex.prefix(16) + "…")
                .font(.system(.body, design: .monospaced))
                .foregroundStyle(.secondary)
        }
    }
}
