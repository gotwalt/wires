import SwiftUI

/// Shared layout for every onboarding step: optional cancel/back chrome,
/// hero area, title + subtitle, body content, sticky-bottom primary and
/// secondary buttons. Ensures visual consistency across the 5 steps.
struct OnboardingScaffold<Hero: View, Content: View>: View {
    let title: String
    let subtitle: String?
    @ViewBuilder let hero: () -> Hero
    @ViewBuilder let content: () -> Content
    var primaryTitle: String
    var primaryAction: () -> Void
    var primaryDisabled: Bool = false
    var secondaryTitle: String? = nil
    var secondaryAction: (() -> Void)? = nil
    var onBack: (() -> Void)? = nil

    var body: some View {
        VStack(spacing: 0) {
            if let onBack {
                HStack {
                    Button(action: onBack) {
                        Image(systemName: "chevron.backward")
                            .font(.title3)
                            .padding(8)
                    }
                    .buttonStyle(.glass)
                    .tint(.primary)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.top, 8)
            }

            Spacer(minLength: 16)
            hero()
            Spacer(minLength: 16)

            VStack(alignment: .center, spacing: 8) {
                Text(title)
                    .font(.largeTitle.bold())
                    .multilineTextAlignment(.center)
                if let subtitle {
                    Text(subtitle)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
            .padding(.horizontal, 24)

            content()
                .padding(.horizontal, 16)
                .padding(.top, 16)

            Spacer()

            VStack(spacing: 8) {
                Button(primaryTitle, action: primaryAction)
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                    .tint(AppColors.indigoPrimary)
                    .frame(maxWidth: .infinity)
                    .disabled(primaryDisabled)

                if let secondaryTitle, let secondaryAction {
                    Button(secondaryTitle, action: secondaryAction)
                        .buttonStyle(.glass)
                        .controlSize(.large)
                        .frame(maxWidth: .infinity)
                }
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 24)
        }
    }
}
