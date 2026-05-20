import ComposableArchitecture
import SwiftUI

struct DeleteAccountSheet: View {
    @Bindable var store: StoreOf<DeleteAccountFeature>

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 56))
                .foregroundStyle(.red)
                .padding(.top, 32)

            Text("Delete your account?")
                .font(.title2.bold())

            Text("Your account key will be erased from this iPhone. Every service in your network will lose access. This can't be undone.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 16)

            TextField("Type 'delete' to confirm", text: Binding(
                get: { store.confirmText },
                set: { store.send(.confirmTextChanged($0)) }
            ))
            .textFieldStyle(.roundedBorder)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.never)
            .padding(.horizontal, 16)

            Spacer()

            VStack(spacing: 8) {
                Button(role: .destructive) {
                    store.send(.confirmButtonTapped)
                } label: {
                    Text("Delete account")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.glassProminent)
                .controlSize(.large)
                .tint(.red)
                .disabled(!store.confirmEnabled)

                Button("Cancel") { store.send(.cancelButtonTapped) }
                    .buttonStyle(.glass)
                    .controlSize(.large)
                    .frame(maxWidth: .infinity)
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 24)
        }
    }
}
