import ComposableArchitecture
import SwiftUI
import WiresKit

struct ApprovalView: View {
    @Bindable var store: StoreOf<ApprovalFeature>

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                ServiceIdentityHeader(summary: headerSummary, size: .medium)
                    .padding(.top, 16)

                aboutCard
                accessCard

                if let err = store.error {
                    Text(err)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .padding(.horizontal, 16)
                }
            }
        }
        .background(Color(.systemGroupedBackground))
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 8) {
                Button {
                    store.send(store.error == nil ? .approveTapped : .retryTapped)
                } label: {
                    HStack {
                        if store.submitting {
                            ProgressView().padding(.trailing, 6)
                        }
                        Text(store.error == nil ? "Approve with Face ID" : "Retry")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
                .tint(AppColors.indigoPrimary)
                .disabled(store.submitting || !hasAnyGrant)
            }
            .padding(16)
            .background(.regularMaterial)
        }
    }

    private var hasAnyGrant: Bool {
        store.decisions.contains { $0.granted && !$0.grantedRights.isEmpty }
    }

    private var headerSummary: ServiceSummary {
        ServiceSummary(
            id: store.preview.handle.id,
            name: store.preview.description.isEmpty ? "Service" : store.preview.description,
            deviceName: nil,
            category: .unknown,
            status: .pending,
            scopes: [],
            connectedAt: Date(),
            lastActivityAt: nil
        )
    }

    private var aboutCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("About this service")
                .font(.subheadline).foregroundStyle(.secondary)
            LabeledContent("Role", value: store.preview.role)
            if !store.preview.description.isEmpty {
                LabeledContent("Description", value: store.preview.description)
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    private var accessCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Access")
                .font(.subheadline).foregroundStyle(.secondary)
            ForEach(store.decisions) { decision in
                ScopeRow(
                    descriptor: descriptorBinding(for: decision),
                    editable: true
                )
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    private func descriptorBinding(for decision: ApprovalFeature.ScopeDecision) -> Binding<ScopeDescriptor> {
        Binding(
            get: {
                ScopeDescriptor(
                    id: decision.id,
                    label: decision.topicName,
                    summary: decision.requestedRights.map(humanizedRight).joined(separator: " · "),
                    detail: decision.requestedRights.map { right in
                        ScopeDetailRow(
                            label: humanizedRight(right),
                            granted: decision.grantedRights.contains(right) && decision.granted,
                            kind: scopeKind(right)
                        )
                    }
                )
            },
            set: { newValue in
                let anyGranted = newValue.detail.contains(where: \.granted)
                store.send(.toggleScope(id: decision.id, granted: anyGranted))
                for row in newValue.detail {
                    let right = wiresRightFromKind(row.kind)
                    store.send(.toggleRight(id: decision.id, right: right, on: row.granted))
                }
            }
        )
    }

    private func humanizedRight(_ right: Right) -> String {
        switch right {
        case .read:  return "Read messages"
        case .write: return "Send messages"
        }
    }
    private func scopeKind(_ right: Right) -> ScopeRightKind {
        switch right {
        case .read:  return .read
        case .write: return .write
        }
    }
    private func wiresRightFromKind(_ kind: ScopeRightKind) -> Right {
        switch kind {
        case .read:  return .read
        case .write: return .write
        case .grant, .custom: return .read  // fallback
        }
    }
}
