import ComposableArchitecture
import SwiftUI
import WiresKit

struct OAuthSignInView: View {
    @Bindable var store: StoreOf<OAuthSignInFeature>

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Sign in")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { store.send(.dismissTapped) }
                    }
                }
        }
    }

    @ViewBuilder private var content: some View {
        switch store.state {
        case .scan:
            if let scanStore = store.scope(state: \.scan?, action: \.scan) {
                ScanView(store: scanStore)
            }
        case .probing:
            ProgressView("Asking gateway…")
        case let .signinConfirm(_, challenge):
            VStack(spacing: 16) {
                Text("Sign in to \(challenge.gatewayURL)?")
                    .font(.title2)
                Text("You'll authenticate with your household root key. Face ID required.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                Button("Sign in") { store.send(.signinApproveTapped) }
                    .buttonStyle(.borderedProminent)
            }
            .padding()
        case .signingIn:
            ProgressView("Signing…")
        case .pairApprove:
            // v1: ApprovalFeature composition deferred (see Task 14). Show a
            // placeholder so the build is clean and the flow is testable.
            VStack(spacing: 12) {
                ProgressView()
                Text("Setting up new agent…")
                    .font(.headline)
                Text("Open the Wires app to approve the pair request from this gateway.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding()
        case let .done(message):
            VStack(spacing: 12) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 56))
                    .foregroundStyle(.green)
                Text(message).font(.title2)
                Button("Done") { store.send(.dismissTapped) }
                    .buttonStyle(.borderedProminent)
            }
            .padding()
        case let .error(message):
            VStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.orange)
                Text(message).multilineTextAlignment(.center)
                Button("Close") { store.send(.dismissTapped) }
            }
            .padding()
        }
    }
}
