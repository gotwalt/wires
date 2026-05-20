import ComposableArchitecture
import SwiftUI

struct AccountDetailSheet: View {
    @Bindable var store: StoreOf<SettingsFeature>

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    ZStack {
                        Circle().fill(AppColors.indigoPrimary)
                        WiresBrandGlyph(variant: .static, size: 56, color: .white)
                    }
                    .frame(width: 96, height: 96)

                    Text("Your Wires")
                        .font(.title.bold())
                    Text(store.serverName.isEmpty ? store.serverURL : store.serverName)
                        .font(.body)
                        .foregroundStyle(.secondary)

                    AdvancedDisclosure(title: "Advanced") {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Account key fingerprint")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                            Text(store.rootPubkeyHex)
                                .font(.system(.footnote, design: .monospaced))
                                .textSelection(.enabled)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.horizontal, 16)

                    Spacer()
                }
                .padding(.top, 32)
            }
            .background(Color(.systemGroupedBackground))
            .navigationTitle("Account")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { store.send(.accountDetailDismissed) }
                }
            }
        }
    }
}
