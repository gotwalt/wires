import SwiftUI

/// Small color-coded chip showing a `ServiceStatus`. Used in the service
/// list trailing slot, on the service-detail identity header, and anywhere
/// else status needs to read at a glance.
struct StatusPill: View {
    let status: ServiceStatus
    var showsLabel: Bool = true

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(status.tint)
                .frame(width: 8, height: 8)
            if showsLabel {
                Text(status.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 4)
        .padding(.horizontal, 8)
        .background(
            Capsule().fill(status.tint.opacity(0.12))
        )
        .accessibilityElement(children: .combine)
        .accessibilityLabel(status.label)
    }
}

#Preview {
    VStack(spacing: 12) {
        StatusPill(status: .connected)
        StatusPill(status: .pending)
        StatusPill(status: .disconnected)
        StatusPill(status: .revoked)
        StatusPill(status: .connected, showsLabel: false)
    }
    .padding()
}
