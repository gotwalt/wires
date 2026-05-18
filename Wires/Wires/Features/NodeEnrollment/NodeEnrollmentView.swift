import ComposableArchitecture
import SwiftUI
import WiresKit

struct NodeEnrollmentView: View {
    let store: StoreOf<NodeEnrollmentFeature>

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(title)
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Close") { store.send(.dismissTapped) }
                    }
                }
        }
    }

    private var title: String {
        switch store.state {
        case .scan: "Approve node"
        case .approve: "Review scopes"
        case .done: "Done"
        }
    }

    @ViewBuilder
    private var content: some View {
        switch store.state {
        case .scan:
            if let scanStore = store.scope(state: \.scan?.scan, action: \.scan) {
                ScanView(store: scanStore)
            }
        case .approve:
            if let approveStore = store.scope(state: \.approve, action: \.approve) {
                ApprovalView(store: approveStore)
            }
        case let .done(done):
            doneView(done)
        }
    }

    private func doneView(_ done: NodeEnrollmentFeature.DoneStepState) -> some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 64))
                .foregroundStyle(.green)
            Text("Node approved")
                .font(.title2)
                .bold()
            VStack(spacing: 4) {
                Text(done.preview.description.isEmpty ? done.preview.role : done.preview.description)
                    .font(.headline)
                Text(done.preview.agentPubkeyHex.prefix(16) + "…")
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Continue") { store.send(.continueTapped) }
                .buttonStyle(.borderedProminent)
                .padding(.bottom, 32)
        }
        .padding()
    }
}
