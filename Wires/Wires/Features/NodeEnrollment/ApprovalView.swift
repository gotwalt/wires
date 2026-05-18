import ComposableArchitecture
import SwiftUI
import WiresKit

struct ApprovalView: View {
    let store: StoreOf<ApprovalFeature>

    var body: some View {
        Form {
            Section {
                infoRow("Role", value: store.preview.role)
                if !store.preview.description.isEmpty {
                    infoRow("Description", value: store.preview.description)
                }
                infoRow("Node",
                        value: String(store.preview.agentPubkeyHex.prefix(16)) + "…")
            } header: {
                Text("Requesting node")
            }

            ForEach(store.decisions) { decision in
                scopeSection(for: decision)
            }

            if let err = store.error {
                Section {
                    Text(err)
                        .font(.footnote)
                        .foregroundStyle(.red)
                    Button("Dismiss") { store.send(.dismissErrorTapped) }
                        .font(.footnote)
                }
            }

            Section {
                Button {
                    store.send(store.error == nil ? .approveTapped : .retryTapped)
                } label: {
                    HStack {
                        if store.submitting {
                            ProgressView().padding(.trailing, 6)
                        }
                        Text(store.error == nil ? "Approve" : "Retry")
                            .frame(maxWidth: .infinity)
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(store.submitting || !hasAnyGrant)
            }
        }
    }

    private var hasAnyGrant: Bool {
        store.decisions.contains { $0.granted && !$0.grantedRights.isEmpty }
    }

    private func infoRow(_ label: String, value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.system(.callout, design: value.contains("…") ? .monospaced : .default))
        }
    }

    private func scopeSection(for decision: ApprovalFeature.ScopeDecision) -> some View {
        Section {
            Toggle("Grant", isOn: scopeBinding(for: decision))
            if decision.granted {
                ForEach(decision.requestedRights, id: \.self) { right in
                    Toggle(rightLabel(right), isOn: rightBinding(for: decision, right: right))
                }
            }
        } header: {
            Text(decision.topicName).textCase(nil)
        }
    }

    private func scopeBinding(for decision: ApprovalFeature.ScopeDecision) -> Binding<Bool> {
        Binding(
            get: { decision.granted },
            set: { store.send(.toggleScope(id: decision.id, granted: $0)) }
        )
    }

    private func rightBinding(for decision: ApprovalFeature.ScopeDecision, right: Right) -> Binding<Bool> {
        Binding(
            get: { decision.grantedRights.contains(right) },
            set: { store.send(.toggleRight(id: decision.id, right: right, on: $0)) }
        )
    }

    private func rightLabel(_ right: Right) -> String {
        switch right {
        case .read: return "Read"
        case .write: return "Write"
        }
    }
}
