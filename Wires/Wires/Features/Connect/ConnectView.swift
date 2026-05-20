import ComposableArchitecture
import SwiftUI
import WiresKit

struct ConnectView: View {
    @Bindable var store: StoreOf<ConnectFeature>

    var body: some View {
        NavigationStack {
            content
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { store.send(.dismissTapped) }
                    }
                }
        }
        .presentationBackground(.regularMaterial)
    }

    @ViewBuilder
    private var content: some View {
        switch store.state {
        case .scan:
            if let scanStore = store.scope(state: \.scan, action: \.scan) {
                connectScan(scanStore: scanStore)
            }
        case .probing, .signingIn:
            probing
        case let .signinConfirm(_, challenge):
            signinConfirm(challenge: challenge)
        case .pairApprove:
            if let approveStore = store.scope(state: \.pairApprove, action: \.approve) {
                ApprovalView(store: approveStore)
            }
        case let .done(message):
            doneView(message: message)
        case let .error(message):
            errorView(message: message)
        }
    }

    @ViewBuilder
    private func connectScan(scanStore: StoreOf<ScanFeature<SessionTicket>>) -> some View {
        VStack(spacing: 0) {
            VStack(spacing: 8) {
                Text("Add a service")
                    .font(.largeTitle.bold())
                Text("Scan the code shown by the service you want to connect.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
            }
            .padding(.vertical, 16)

            ScanView(store: scanStore)
                .frame(maxHeight: .infinity)
        }
    }

    private var probing: some View {
        VStack(spacing: 16) {
            WiresBrandGlyph(variant: .static, size: 96)
                .opacity(0.4)
            ProgressView()
            Text("Checking with your server…")
                .font(.headline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func signinConfirm(challenge: SignInChallenge) -> some View {
        OnboardingScaffold(
            title: "Sign in to your account?",
            subtitle: "Approving will use your account key on this iPhone. Face ID required.",
            hero: {
                Image(systemName: "faceid")
                    .font(.system(size: 96, weight: .light))
                    .foregroundStyle(AppColors.indigoPrimary)
            },
            content: {
                Text(challenge.gatewayURL)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .padding(.top, 8)
            },
            primaryTitle: "Sign in with Face ID",
            primaryAction: { store.send(.signinApproveTapped) }
        )
    }

    private func doneView(message: String) -> some View {
        OnboardingScaffold(
            title: "Connected",
            subtitle: message,
            hero: {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 96))
                    .foregroundStyle(.green)
            },
            content: { EmptyView() },
            primaryTitle: "Done",
            primaryAction: { store.send(.dismissTapped) }
        )
    }

    private func errorView(message: String) -> some View {
        InlineErrorBanner(
            message: friendlyMessage(message),
            primaryTitle: "Try again",
            primaryAction: { store.send(.dismissTapped) },  // for v1, retry == dismiss; future: route back to scan
            secondaryTitle: "Cancel",
            secondaryAction: { store.send(.dismissTapped) }
        )
    }

    private func friendlyMessage(_ raw: String) -> String {
        // Hide gateway-X-returned-N-style errors behind human copy.
        if raw.contains("returned") || raw.contains("status") {
            return "Couldn't reach your server. Check your connection and try again."
        }
        return raw
    }
}
