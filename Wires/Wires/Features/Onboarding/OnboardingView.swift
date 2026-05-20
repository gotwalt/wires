import ComposableArchitecture
import SwiftUI

struct OnboardingView: View {
    @Bindable var store: StoreOf<OnboardingFeature>

    var body: some View {
        switch store.step {
        case .welcome:
            WelcomeStepView(store: store)
        case .scan:
            ScanStepView(store: store)
        case .confirm:
            ConfirmServerStepView(store: store)
        case .faceID:
            FaceIDStepView(store: store)
        case .done:
            DoneStepView(store: store)
        }
    }
}
