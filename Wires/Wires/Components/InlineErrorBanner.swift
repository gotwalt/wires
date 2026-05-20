import SwiftUI

/// Inline error panel with a clear next action. Replaces ad-hoc alerts.
struct InlineErrorBanner: View {
    let message: String
    var primaryTitle: String
    var primaryAction: () -> Void
    var secondaryTitle: String? = nil
    var secondaryAction: (() -> Void)? = nil

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 40))
                .foregroundStyle(.orange)

            Text(message)
                .font(.body)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)

            HStack(spacing: 12) {
                if let secondaryTitle, let secondaryAction {
                    Button(secondaryTitle, action: secondaryAction)
                        .buttonStyle(.glass)
                        .controlSize(.large)
                }
                Button(primaryTitle, action: primaryAction)
                    .buttonStyle(.glassProminent)
                    .controlSize(.large)
                    .tint(AppColors.indigoPrimary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(24)
    }
}
