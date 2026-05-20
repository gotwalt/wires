import ComposableArchitecture
import SwiftUI

struct DoneStepView: View {
    let store: StoreOf<OnboardingFeature>

    var body: some View {
        OnboardingScaffold(
            title: "You're set up",
            subtitle: "Add a service to start using your network.",
            hero: {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 96))
                    .foregroundStyle(.green)
            },
            content: { EmptyView() },
            primaryTitle: "Continue",
            primaryAction: { store.send(.continueTapped) }
        )
    }
}
