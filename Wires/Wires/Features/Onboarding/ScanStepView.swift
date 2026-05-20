import ComposableArchitecture
import SwiftUI

struct ScanStepView: View {
    @Bindable var store: StoreOf<OnboardingFeature>

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                // No back/cancel — scan is step 2 and the only path forward
                // is to scan or paste. Tapping the app icon to return is the
                // existing iOS behavior.
                Spacer()
            }
            .frame(height: 44)

            VStack(spacing: 8) {
                Text("Set up your Wires")
                    .font(.largeTitle.bold())
                Text("Scan the setup code for the Wires server you want to use.")
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 24)
            }
            .padding(.bottom, 12)

            ScanView(store: store.scope(state: \.scan, action: \.scan))
                .frame(maxHeight: .infinity)

            HStack {
                Button {
                    store.send(.pasteButtonTapped)
                } label: {
                    Label("Paste code", systemImage: "doc.on.clipboard")
                }
                .buttonStyle(.glass)
                .controlSize(.large)
            }
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
                Text("Paste a setup code")
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
            .navigationTitle("Paste setup code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { store.send(.pasteSheetDismissed) }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Use code") { store.send(.pasteSubmitTapped) }
                        .disabled(store.pasteInput.isEmpty)
                }
            }
        }
    }
}
