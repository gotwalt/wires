import ComposableArchitecture
import SwiftUI

struct NetworkView: View {
    @Bindable var store: StoreOf<NetworkFeature>

    var body: some View {
        NavigationStack(path: $store.scope(state: \.path, action: \.path)) {
            content
                .navigationTitle("Network")
                .toolbar {
                    ToolbarItem(placement: .primaryAction) {
                        Button {
                            store.send(.plusTapped)
                        } label: {
                            Image(systemName: "plus")
                        }
                        .tint(AppColors.indigoPrimary)
                    }
                }
                .task { store.send(.onAppear) }
                .sheet(item: $store.scope(state: \.connect, action: \.connect)) { childStore in
                    ConnectView(store: childStore)
                }
        } destination: { childStore in
            ServiceDetailView(store: childStore)
        }
    }

    @ViewBuilder
    private var content: some View {
        if store.loading && store.services.isEmpty {
            ProgressView()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let err = store.loadError {
            InlineErrorBanner(
                message: err,
                primaryTitle: "Try again",
                primaryAction: { store.send(.onAppear) }
            )
        } else if store.services.isEmpty {
            emptyState
        } else {
            servicesList
        }
    }

    private var emptyState: some View {
        VStack(spacing: 16) {
            WiresBrandGlyph(variant: .static, size: 96)
                .opacity(0.5)
            Text("No services yet")
                .font(.title3.bold())
            Text("Tap + to add a service to your network.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(.horizontal, 24)
    }

    private var servicesList: some View {
        List {
            let connected = store.services.filter { $0.status == .connected }
            let revoked = store.services.filter { $0.status == .revoked }
            let pending = store.services.filter { $0.status == .pending }

            if !connected.isEmpty {
                Section("Connected") {
                    ForEach(connected) { s in
                        Button { store.send(.rowTapped(s)) } label: {
                            ServiceListRow(summary: s)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            if !pending.isEmpty {
                Section("Pending approval") {
                    ForEach(pending) { s in
                        Button { store.send(.rowTapped(s)) } label: {
                            ServiceListRow(summary: s)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            if !revoked.isEmpty {
                Section("Recently disconnected") {
                    ForEach(revoked) { s in
                        Button { store.send(.rowTapped(s)) } label: {
                            ServiceListRow(summary: s)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }
}

