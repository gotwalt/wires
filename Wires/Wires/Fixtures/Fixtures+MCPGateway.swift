import Foundation

extension MCPGatewayClient {
    /// No-op fixture. probe / postAssertion return inert defaults. The
    /// OAuth fixtures land the user past the probe step, so these are
    /// rarely exercised; they exist as safety nets.
    static func fixture() -> MCPGatewayClient {
        MCPGatewayClient(
            probe: { _, _, _ in
                .signin(challengeB64: "fixture-challenge")
            },
            postAssertion: { _, _, _, _ in }
        )
    }
}
