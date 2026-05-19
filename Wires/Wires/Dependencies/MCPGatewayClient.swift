import ComposableArchitecture
import Dependencies
import Foundation

enum MCPGatewayError: Error, Equatable {
    case malformedURL
    case transport(String)
    case server(Int, String)
    case malformedResponse(String)
}

enum ProbeResult: Equatable, Sendable {
    case pair(pairTokenB64: String)
    case signin(challengeB64: String)
}

@DependencyClient
struct MCPGatewayClient {
    /// POST `<gateway_url>/oauth/session/probe`. Returns the gateway's
    /// dispatch: either a fresh pair token or a sign-in challenge.
    var probe: @Sendable (
        _ gatewayURL: String,
        _ sessionID: String,
        _ rootPubkeyHex: String
    ) async throws -> ProbeResult

    /// POST `<gateway_url>/oauth/signin/assertion`. Returns true on 2xx.
    var postAssertion: @Sendable (
        _ gatewayURL: String,
        _ sessionID: String,
        _ rootPubkeyHex: String,
        _ signatureHex: String
    ) async throws -> Void
}

extension MCPGatewayClient: DependencyKey {
    static let liveValue: MCPGatewayClient = MCPGatewayClient(
        probe: { gatewayURL, sessionID, rootHex in
            guard let url = URL(string: gatewayURL.trimmingCharacters(in: .init(charactersIn: "/")) + "/oauth/session/probe") else {
                throw MCPGatewayError.malformedURL
            }
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: [
                "session_id": sessionID,
                "root_pubkey_hex": rootHex,
            ])
            let (data, resp): (Data, URLResponse)
            do { (data, resp) = try await URLSession.shared.data(for: req) }
            catch { throw MCPGatewayError.transport(String(describing: error)) }
            guard let http = resp as? HTTPURLResponse else {
                throw MCPGatewayError.malformedResponse("not HTTP")
            }
            if !(200..<300).contains(http.statusCode) {
                let body = String(data: data, encoding: .utf8) ?? "<binary>"
                throw MCPGatewayError.server(http.statusCode, body)
            }
            guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let kind = obj["kind"] as? String else {
                throw MCPGatewayError.malformedResponse("missing kind")
            }
            switch kind {
            case "pair":
                guard let token = obj["pair_token_b64"] as? String else {
                    throw MCPGatewayError.malformedResponse("missing pair_token_b64")
                }
                return .pair(pairTokenB64: token)
            case "signin":
                guard let challenge = obj["challenge_b64"] as? String else {
                    throw MCPGatewayError.malformedResponse("missing challenge_b64")
                }
                return .signin(challengeB64: challenge)
            default:
                throw MCPGatewayError.malformedResponse("unknown kind: \(kind)")
            }
        },
        postAssertion: { gatewayURL, sessionID, rootHex, sigHex in
            guard let url = URL(string: gatewayURL.trimmingCharacters(in: .init(charactersIn: "/")) + "/oauth/signin/assertion") else {
                throw MCPGatewayError.malformedURL
            }
            var req = URLRequest(url: url)
            req.httpMethod = "POST"
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONSerialization.data(withJSONObject: [
                "session_id": sessionID,
                "root_pubkey": rootHex,
                "signature": sigHex,
            ])
            let (data, resp): (Data, URLResponse)
            do { (data, resp) = try await URLSession.shared.data(for: req) }
            catch { throw MCPGatewayError.transport(String(describing: error)) }
            guard let http = resp as? HTTPURLResponse else {
                throw MCPGatewayError.malformedResponse("not HTTP")
            }
            if !(200..<300).contains(http.statusCode) {
                let body = String(data: data, encoding: .utf8) ?? "<binary>"
                throw MCPGatewayError.server(http.statusCode, body)
            }
        }
    )
}

extension DependencyValues {
    var mcpGatewayClient: MCPGatewayClient {
        get { self[MCPGatewayClient.self] }
        set { self[MCPGatewayClient.self] = newValue }
    }
}
