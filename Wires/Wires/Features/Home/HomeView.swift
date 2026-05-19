import ComposableArchitecture
import SwiftUI

struct HomeView: View {
    @Bindable var store: StoreOf<HomeFeature>

    var body: some View {
        NavigationStack {
            content
                .navigationTitle("Household")
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            store.send(.connectTapped)
                        } label: {
                            Label("Connect", systemImage: "qrcode.viewfinder")
                        }
                    }
                    #if DEBUG
                    ToolbarItem(placement: .secondaryAction) {
                        Button(role: .destructive) {
                            store.send(.resetHouseholdTapped)
                        } label: {
                            Label("Reset household (debug)", systemImage: "trash")
                        }
                    }
                    #endif
                }
                .task { store.send(.onAppear) }
                .sheet(item: $store.scope(state: \.oauthSignIn, action: \.oauthSignIn)) { childStore in
                    OAuthSignInView(store: childStore)
                }
                .alert($store.scope(state: \.alert, action: \.alert))
        }
    }

    @ViewBuilder
    private var content: some View {
        if store.loading {
            ProgressView()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let err = store.loadError {
            VStack(spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
                    .font(.system(size: 32))
                Text("Failed to load caps")
                    .font(.headline)
                Text(err)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal)
                Button("Retry") { store.send(.onAppear) }
                    .buttonStyle(.bordered)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if store.caps.isEmpty {
            emptyState
        } else {
            capsList
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "person.crop.circle.badge.questionmark")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("No nodes yet")
                .font(.headline)
            Text("Tap \"Connect\" and scan a service QR code.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var capsList: some View {
        List {
            ForEach(groupedByNode(), id: \.nodePubkeyHex) { group in
                Section {
                    ForEach(group.caps) { cap in
                        capRow(cap)
                    }
                } header: {
                    Text(headerLabel(for: group))
                        .font(.subheadline)
                        .textCase(nil)
                }
            }
        }
    }

    private func capRow(_ cap: HomeFeature.CapSummary) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(cap.topicNames.isEmpty ? "—" : cap.topicNames.joined(separator: ", "))
                .font(.callout)
            Text(cap.rights.joined(separator: " · "))
                .font(.caption)
                .foregroundStyle(.secondary)
            if let revokedAt = cap.revokedAt {
                Text("Revoked \(revokedAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption2)
                    .foregroundStyle(.red)
            }
        }
        .padding(.vertical, 2)
    }

    private struct NodeGroup {
        let nodePubkeyHex: String
        let nodeAlias: String?
        let caps: [HomeFeature.CapSummary]
    }

    private func groupedByNode() -> [NodeGroup] {
        let grouped = Dictionary(grouping: store.caps, by: \.nodePubkeyHex)
        return grouped
            .map { key, caps in
                NodeGroup(
                    nodePubkeyHex: key,
                    nodeAlias: caps.first?.nodeAlias,
                    caps: caps.sorted { $0.issuedAt < $1.issuedAt }
                )
            }
            .sorted { $0.nodePubkeyHex < $1.nodePubkeyHex }
    }

    private func headerLabel(for group: NodeGroup) -> String {
        if let alias = group.nodeAlias, !alias.isEmpty {
            return alias
        }
        return String(group.nodePubkeyHex.prefix(16)) + "…"
    }
}
