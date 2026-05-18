import SwiftUI
import WiresKit

struct ConfirmHostView: View {
    let host: HostInfo
    let registering: Bool
    let errorMessage: String?
    let onRegister: () -> Void
    let onRetry: () -> Void
    let onDismissError: () -> Void
    let onBack: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Confirm host")
                .font(.title2)
                .bold()

            VStack(alignment: .leading, spacing: 8) {
                row("Endpoint", value: host.endpointIdHex.prefix(16) + "…")
                row("Addrs", value: host.addrs.joined(separator: ", "))
                if let relay = host.relay {
                    row("Relay", value: relay)
                }
            }
            .padding()
            .background(.quinary, in: RoundedRectangle(cornerRadius: 12))

            if let err = errorMessage {
                errorBanner(err)
            }

            HStack {
                Button("Back", action: onBack)
                    .buttonStyle(.bordered)
                Spacer()
                if registering {
                    ProgressView()
                        .padding(.horizontal, 8)
                }
                Button(errorMessage == nil ? "Register" : "Retry") {
                    errorMessage == nil ? onRegister() : onRetry()
                }
                .buttonStyle(.borderedProminent)
                .disabled(registering)
            }

            Spacer()
        }
        .padding()
    }

    private func row(_ label: String, value: some StringProtocol) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(width: 70, alignment: .leading)
            Text(value)
                .font(.system(.callout, design: .monospaced))
        }
    }

    private func errorBanner(_ message: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            Text(message)
                .font(.callout)
            Spacer()
            Button("Dismiss", action: onDismissError)
                .font(.footnote)
        }
        .padding()
        .background(.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
    }
}
