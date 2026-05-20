import SwiftUI

/// The "this is a service" presentation block used on service detail and
/// on the connect-approve sheet. Same component, same visual identity, so
/// the approve sheet and detail page agree. See spec §6.3 / §6.4.
struct ServiceIdentityHeader: View {
    let summary: ServiceSummary
    var size: HeaderSize = .large

    enum HeaderSize {
        case large   // service detail page
        case medium  // connect-approve sheet

        var diameter: CGFloat {
            switch self {
            case .large:  return 80
            case .medium: return 64
            }
        }
        var glyphPointSize: CGFloat {
            switch self {
            case .large:  return 36
            case .medium: return 28
            }
        }
        var titleFont: Font {
            switch self {
            case .large:  return .title.bold()
            case .medium: return .title2.bold()
            }
        }
    }

    var body: some View {
        VStack(spacing: 8) {
            ZStack {
                Circle()
                    .fill(AppColors.indigoPrimary)
                Image(systemName: summary.category.sfSymbol)
                    .font(.system(size: size.glyphPointSize, weight: .semibold))
                    .foregroundStyle(.white)
            }
            .frame(width: size.diameter, height: size.diameter)

            Text(summary.name)
                .font(size.titleFont)
                .multilineTextAlignment(.center)

            if let device = summary.deviceName {
                Text("on \(device)")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            StatusPill(status: summary.status)
                .padding(.top, 4)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }
}

#Preview {
    ServiceIdentityHeader(
        summary: ServiceSummary(
            id: "1",
            name: "Chase",
            deviceName: "Aaron's Mac mini",
            category: .banking,
            status: .connected,
            scopes: [],
            connectedAt: Date(),
            lastActivityAt: nil
        )
    )
}
