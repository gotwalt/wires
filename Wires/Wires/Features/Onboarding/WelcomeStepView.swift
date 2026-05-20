import ComposableArchitecture
import SwiftUI

struct WelcomeStepView: View {
    let store: StoreOf<OnboardingFeature>

    var body: some View {
        OnboardingScaffold(
            title: "Wires",
            subtitle: "A private network for the apps and services in your life.",
            hero: { WiresBrandGlyph(variant: .drawIn(duration: 1.6), size: 140) },
            content: { EmptyView() },
            primaryTitle: "Get started",
            primaryAction: { store.send(.getStartedTapped) }
        )
    }
}
