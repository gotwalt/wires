import SwiftUI
import WiresKit

struct DoneView: View {
    let completed: BootstrapFeature.State.Completed
    let onContinue: () -> Void

    var body: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "checkmark.seal.fill")
                .font(.system(size: 64))
                .foregroundStyle(.green)
            Text("Household registered")
                .font(.title2)
                .bold()
            VStack(spacing: 6) {
                Text("Root")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(completed.rootPubkeyHex.prefix(16) + "…")
                    .font(.system(.callout, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Continue", action: onContinue)
                .buttonStyle(.borderedProminent)
                .padding(.bottom, 32)
        }
        .padding()
    }
}
