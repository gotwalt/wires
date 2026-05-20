import ComposableArchitecture
import SwiftUI

struct ServiceDetailView: View {
    @Bindable var store: StoreOf<ServiceDetailFeature>

    var body: some View {
        ScrollView {
            LazyVStack(spacing: 16) {
                ServiceIdentityHeader(summary: store.summary)
                    .padding(.top, 16)

                aboutCard
                scopesCard
                advancedCard

                if store.summary.status == .revoked {
                    DestructiveFooterButton(title: "Reconnect…") {
                        store.send(.reconnectTapped)
                    }
                } else {
                    DestructiveFooterButton(title: "Disconnect \(store.summary.name)") {
                        store.send(.disconnectTapped)
                    }
                }
            }
        }
        .background(Color(.systemGroupedBackground))
        .navigationBarTitleDisplayMode(.inline)
        .task { store.send(.onAppear) }
        .confirmationDialog(
            "Disconnect \(store.summary.name) from your network?",
            isPresented: Binding(
                get: { store.confirmingDisconnect },
                set: { if !$0 { store.send(.disconnectCancelTapped) } }
            ),
            titleVisibility: .visible
        ) {
            Button("Disconnect", role: .destructive) {
                store.send(.disconnectConfirmTapped)
            }
            Button("Cancel", role: .cancel) {
                store.send(.disconnectCancelTapped)
            }
        }
    }

    private var aboutCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("About")
                .font(.subheadline).foregroundStyle(.secondary)
            LabeledContent("Connected on", value: store.summary.connectedAt.formatted(date: .abbreviated, time: .omitted))
            if let last = store.summary.lastActivityAt {
                LabeledContent("Last activity", value: last.formatted(.relative(presentation: .named)))
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    private var scopesCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("What it can do")
                .font(.subheadline).foregroundStyle(.secondary)
            ForEach(store.summary.scopes) { scope in
                ScopeRow(descriptor: .constant(scope), editable: false)
            }
        }
        .padding(16)
        .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        .padding(.horizontal, 16)
    }

    private var advancedCard: some View {
        AdvancedDisclosure(title: "Advanced", initialExpanded: store.advancedInitiallyExpanded) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Cap ID")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                Text(store.summary.id)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 16)
    }
}
