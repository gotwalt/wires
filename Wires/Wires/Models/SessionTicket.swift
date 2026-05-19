import Foundation

/// Compact QR payload the wires-mcp consent page renders.
/// Format: URL-safe base64 (no padding) of a small JSON object.
struct SessionTicket: Equatable, Sendable {
    static let kindV1 = "wires.oauth.v1"

    let version: Int
    let kind: String
    let gatewayURL: String
    let sessionID: String

    enum DecodeError: Error, Equatable {
        case malformedBase64
        case malformedJSON
        case unknownKind(String)
    }

    private struct Wire: Codable {
        let v: Int
        let k: String
        let gateway_url: String
        let session_id: String
    }

    static func decode(urlSafeBase64: String) throws -> SessionTicket {
        guard let data = Data(urlSafeBase64NoPad: urlSafeBase64) else {
            throw DecodeError.malformedBase64
        }
        let wire: Wire
        do {
            wire = try JSONDecoder().decode(Wire.self, from: data)
        } catch {
            throw DecodeError.malformedJSON
        }
        guard wire.k == kindV1 else { throw DecodeError.unknownKind(wire.k) }
        return SessionTicket(
            version: wire.v,
            kind: wire.k,
            gatewayURL: wire.gateway_url,
            sessionID: wire.session_id
        )
    }
}

extension Data {
    /// Decode a URL-safe base64 string with no padding.
    init?(urlSafeBase64NoPad s: String) {
        var t = s.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let mod = t.count % 4
        if mod != 0 { t.append(String(repeating: "=", count: 4 - mod)) }
        guard let d = Data(base64Encoded: t) else { return nil }
        self = d
    }

    /// Encode as URL-safe base64 without padding.
    func base64URLEncodedNoPad() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
