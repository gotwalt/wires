import SwiftUI

/// Labeled DisclosureGroup styled to match grouped form cards. Used wherever
/// we hide hex/key material behind a deliberate user reveal. Fixtures can
/// pass `initialExpanded: true` to render the expanded state without
/// simulating a tap.
struct AdvancedDisclosure<Content: View>: View {
    let title: String
    @State private var expanded: Bool
    @ViewBuilder let content: () -> Content

    init(
        title: String,
        initialExpanded: Bool = false,
        @ViewBuilder content: @escaping () -> Content
    ) {
        self.title = title
        self._expanded = State(initialValue: initialExpanded)
        self.content = content
    }

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
