import ComposableArchitecture
import SwiftUI
import WiresKit

struct BootstrapView: View {
    let store: StoreOf<BootstrapFeature>

    var body: some View {
        Group {
            switch store.step {
            case .scan:
                scanStepView
            case .confirm:
                if let host = store.confirmedHost {
                    ConfirmHostView(
                        host: host,
                        registering: store.registering,
                        errorMessage: store.registerError,
                        onRegister: { store.send(.registerButtonTapped) },
                        onRetry: { store.send(.retryRegisterTapped) },
                        onDismissError: { store.send(.dismissRegisterErrorTapped) },
                        onBack: { store.send(.backFromConfirmTapped) }
                    )
                }
            case .done:
                if let completed = store.completed {
                    DoneView(
                        completed: completed,
                        onContinue: { store.send(.continueTapped) }
                    )
                }
            }
        }
    }

    private var scanStepView: some View {
        VStack(spacing: 16) {
            ScanView(store: store.scope(state: \.scan, action: \.scan))
                .frame(maxHeight: .infinity)

            Button {
                store.send(.pasteButtonTapped)
            } label: {
                Label("Paste ticket", systemImage: "doc.on.clipboard")
            }
            .buttonStyle(.bordered)
            .padding(.bottom, 24)
        }
        .sheet(isPresented: pasteSheetBinding) {
            pasteSheetView
        }
    }

    private var pasteSheetBinding: Binding<Bool> {
        Binding(
            get: { store.pasteSheetPresented },
            set: { newValue in
                if !newValue { store.send(.pasteSheetDismissed) }
            }
        )
    }

    private var pasteInputBinding: Binding<String> {
        Binding(
            get: { store.pasteInput },
            set: { store.send(.pasteInputChanged($0)) }
        )
    }

    private var pasteSheetView: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Text("Paste a host ticket")
                    .font(.headline)
                TextEditor(text: pasteInputBinding)
                    .font(.system(.body, design: .monospaced))
                    .frame(minHeight: 160)
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(.quaternary, lineWidth: 1)
                    )
                if let err = store.pasteError {
                    Text(err)
                        .font(.footnote)
                        .foregroundStyle(.red)
                }
                Spacer()
            }
            .padding()
            .navigationTitle("Paste ticket")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { store.send(.pasteSheetDismissed) }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Use ticket") { store.send(.pasteSubmitTapped) }
                        .disabled(store.pasteInput.isEmpty)
                }
            }
        }
    }
}
