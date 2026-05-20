import ComposableArchitecture
import SwiftUI
import WiresKit

struct ConfirmServerStepView: View {
    let store: StoreOf<OnboardingFeature>

    var body: some View {
        OnboardingScaffold(
            title: "Use \(serverName) for your account?",
            subtitle: nil,
            hero: {
                ZStack {
                    RoundedRectangle(cornerRadius: 20)
                        .fill(AppColors.indigoPrimary.opacity(0.14))
                    WiresBrandGlyph(variant: .static, size: 60)
                }
                .frame(width: 120, height: 120)
            },
            content: { serverCard },
            primaryTitle: store.registerError == nil ? "Set up account here" : "Retry",
            primaryAction: { store.send(.confirmRegisterTapped) },
            primaryDisabled: store.registering,
            secondaryTitle: "Choose a different server",
            secondaryAction: { store.send(.confirmBackTapped) }
        )
    }

    private var serverName: String {
        if let host = store.confirmedHost {
            return host.serverName ?? host.endpointIdHex.prefix(16).description
        }
        return "—"
    }

    @ViewBuilder
    private var serverCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let host = store.confirmedHost {
                if let name = host.serverName {
                    LabeledContent("Server", value: name)
                }
                if let relay = host.relay {
                    LabeledContent("URL", value: relay)
                }
            }
            Text("Your Wires account will live here. You can't move it to a different server later, so make sure you trust this one.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .padding(.top, 8)
            if store.registering {
                ProgressView().padding(.top, 6)
            }
            if let err = store.registerError {
                Text(err)
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
    }
}
