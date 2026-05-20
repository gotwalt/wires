import SwiftUI

/// Expandable row representing one ScopeDescriptor. Collapsed: primary
/// "approve everything" toggle + summary line. Expanded: per-detail
/// toggles. When `editable` is false, every toggle is read-only.
struct ScopeRow: View {
    @Binding var descriptor: ScopeDescriptor
    var editable: Bool
    @State private var expanded = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(descriptor.label)
                        .font(.body)
                    Text(descriptor.summary)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if editable {
                    Toggle("", isOn: Binding(
                        get: { descriptor.allGranted },
                        set: { descriptor.setAllGranted($0) }
                    ))
                    .labelsHidden()
                    .tint(AppColors.indigoPrimary)
                } else {
                    Image(systemName: descriptor.allGranted ? "checkmark.circle.fill" : "minus.circle.fill")
                        .foregroundStyle(descriptor.allGranted ? .green : .secondary)
                }
                Button {
                    withAnimation { expanded.toggle() }
                } label: {
                    Image(systemName: "chevron.right")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .rotationEffect(.degrees(expanded ? 90 : 0))
                }
                .buttonStyle(.plain)
            }

            if expanded {
                Divider().padding(.vertical, 6)
                ForEach(descriptor.detail.indices, id: \.self) { i in
                    HStack {
                        Text(descriptor.detail[i].label)
                            .font(.body)
                        Spacer()
                        if editable {
                            Toggle("", isOn: $descriptor.detail[i].granted)
                                .labelsHidden()
                                .tint(AppColors.indigoPrimary)
                        } else {
                            Image(systemName: descriptor.detail[i].granted ? "checkmark" : "xmark")
                                .foregroundStyle(descriptor.detail[i].granted ? .green : .secondary)
                        }
                    }
                    .padding(.vertical, 2)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

#Preview {
    StatefulPreviewWrapper(ScopeDescriptor(
        id: "family",
        label: "family",
        summary: "Read messages · Send messages",
        detail: [
            .init(label: "Read messages", granted: true, kind: .read),
            .init(label: "Send messages", granted: true, kind: .write),
        ]
    )) { binding in
        List {
            ScopeRow(descriptor: binding, editable: true)
        }
    }
}

private struct StatefulPreviewWrapper<Value, Content: View>: View {
    @State var value: Value
    let content: (Binding<Value>) -> Content
    init(_ value: Value, @ViewBuilder content: @escaping (Binding<Value>) -> Content) {
        self._value = State(initialValue: value)
        self.content = content
    }
    var body: some View { content($value) }
}
