import SwiftUI

/// Grouped-list row for a service. 36pt indigo circle leading, primary name,
/// optional device subtitle, status pill trailing.
struct ServiceListRow: View {
    let summary: ServiceSummary

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle().fill(AppColors.indigoPrimary)
                Image(systemName: summary.category.sfSymbol)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: 36, height: 36)

            VStack(alignment: .leading, spacing: 2) {
                Text(summary.name)
                    .font(.body)
                if let device = summary.deviceName {
                    Text("on \(device)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            StatusPill(status: summary.status, showsLabel: false)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(summary.name), \(summary.status.label)")
    }
}

#Preview {
    List {
        ServiceListRow(summary: .init(
            id: "1", name: "Chase",
            deviceName: "Aaron's Mac mini",
            category: .banking, status: .connected,
            scopes: [], connectedAt: Date(), lastActivityAt: nil
        ))
        ServiceListRow(summary: .init(
            id: "2", name: "Home Assistant",
            deviceName: nil,
            category: .smartHome, status: .revoked,
            scopes: [], connectedAt: Date(), lastActivityAt: nil
        ))
    }
}
