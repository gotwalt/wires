import ComposableArchitecture
import SwiftUI

struct SettingsView: View {
    @Bindable var store: StoreOf<SettingsFeature>

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    accountHeader

                    Form {
                        Section("Security") {
                            Toggle("Face ID protection", isOn: Binding(
                                get: { store.faceIDEnabled },
                                set: { store.send(.faceIDToggled($0)) }
                            ))
                            .tint(AppColors.indigoPrimary)
                        }

                        Section {
                            LabeledContent("Server name", value: store.serverName.isEmpty ? "—" : store.serverName)
                            LabeledContent("Server URL", value: store.serverURL.isEmpty ? "—" : store.serverURL)
                        } header: {
                            Text("Server")
                        } footer: {
                            Text("Your account lives on this server. You can't move it to a different server.")
                        }

                        Section("About") {
                            LabeledContent("Version", value: store.appVersion)
                        }
                    }
                    .frame(minHeight: 400)
                    .scrollDisabled(true)

                    DestructiveFooterButton(title: "Delete account") {
                        store.send(.deleteAccountTapped)
                    }
                }
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Settings")
            .task { store.send(.onAppear) }
            .sheet(item: $store.scope(state: \.deleteSheet, action: \.deleteSheet)) { childStore in
                DeleteAccountSheet(store: childStore)
                    .presentationBackground(.regularMaterial)
                    .presentationDetents([.large])
            }
            .sheet(isPresented: Binding(
                get: { store.showingAccountDetail },
                set: { if !$0 { store.send(.accountDetailDismissed) } }
            )) {
                AccountDetailSheet(store: store)
            }
        }
    }

    private var accountHeader: some View {
        Button {
            store.send(.accountRowTapped)
        } label: {
            HStack(spacing: 12) {
                ZStack {
                    Circle().fill(AppColors.indigoPrimary)
                    WiresBrandGlyph(variant: .static, size: 36, color: .white)
                }
                .frame(width: 56, height: 56)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Your Wires")
                        .font(.title3.bold())
                        .foregroundStyle(.primary)
                    Text(store.serverName.isEmpty ? store.serverURL : store.serverName)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .foregroundStyle(.secondary)
            }
            .padding(16)
            .background(Color(.secondarySystemGroupedBackground), in: .rect(cornerRadius: 16))
        }
        .buttonStyle(.plain)
        .padding(.horizontal, 16)
        .padding(.top, 16)
    }
}
