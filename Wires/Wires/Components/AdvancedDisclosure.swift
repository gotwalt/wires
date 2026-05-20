import SwiftUI

/// Labeled DisclosureGroup styled to match grouped form cards. Used wherever
/// we hide hex/key material behind a deliberate user reveal.
struct AdvancedDisclosure<Content: View>: View {
    let title: String
    @State private var expanded = false
    @ViewBuilder let content: () -> Content

    var body: some View {
        DisclosureGroup(title, isExpanded: $expanded) {
            content()
                .padding(.top, 8)
        }
        .font(.subheadline.weight(.medium))
        .foregroundStyle(.secondary)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 12))
    }
}
