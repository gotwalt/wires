import ComposableArchitecture
import SwiftUI

/// Stub — real implementation in Task 21. HomeFeature presents this as a
/// sheet when the user taps "Approve node."
@Reducer
struct NodeEnrollmentFeature {
    @ObservableState
    struct State: Equatable {}

    @CasePathable
    enum Action {
        case dismissTapped
    }

    var body: some Reducer<State, Action> {
        Reduce { _, _ in .none }
    }
}

struct NodeEnrollmentView: View {
    let store: StoreOf<NodeEnrollmentFeature>

    var body: some View {
        VStack(spacing: 16) {
            Text("Approve node")
                .font(.title2)
                .bold()
            Text("Scan a pair-request QR from the node device.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            Button("Close") { store.send(.dismissTapped) }
                .buttonStyle(.bordered)
        }
        .padding()
    }
}
