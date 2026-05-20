import ComposableArchitecture
import SwiftUI

struct FaceIDStepView: View {
    let store: StoreOf<OnboardingFeature>

    var body: some View {
        OnboardingScaffold(
            title: "Protect your account with Face ID",
            subtitle: "Your account key lives on this iPhone. Face ID makes sure only you can use it — and protects it if you lose your phone.",
            hero: {
                Image(systemName: "faceid")
                    .font(.system(size: 100, weight: .light))
                    .foregroundStyle(AppColors.indigoPrimary)
            },
            content: {
                if let err = store.faceIDError {
                    Text(err)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .padding(.top, 8)
                }
            },
            primaryTitle: store.faceIDEnabling ? "Setting up…" : "Set up Face ID",
            primaryAction: { store.send(.faceIDSetupTapped) },
            primaryDisabled: store.faceIDEnabling,
            secondaryTitle: "Set up later",
            secondaryAction: { store.send(.faceIDSkipTapped) }
        )
    }
}
