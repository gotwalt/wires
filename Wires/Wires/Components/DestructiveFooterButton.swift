import SwiftUI

/// iOS Settings-style red-text destructive button used outside any card,
/// at the bottom of a scrolling page.
struct DestructiveFooterButton: View {
    let title: String
    let action: () -> Void

    var body: some View {
        Button(role: .destructive, action: action) {
            Text(title)
                .font(.body)
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.vertical, 14)
        }
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 12))
        .padding(.horizontal, 16)
        .padding(.vertical, 24)
    }
}
