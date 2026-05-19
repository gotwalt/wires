import Foundation

/// Returning-user challenge the wires-mcp gateway embeds in the sign-in QR.
/// iOS decodes this, biometric-signs `signingBytes()` with the household root
/// key, and POSTs the signature to `/oauth/signin/assertion`.
///
/// The canonical byte encoding MUST match `SignInChallenge::signing_bytes()` in
/// `crates/wires-mcp/src/sign_in.rs` exactly.  `signingBytes()` uses
/// `JSONSerialization` with `.sortedKeys` and `.withoutEscapingSlashes`, which
/// reproduces the Rust `canonicalize()` + `serde_json::to_vec` output.
struct SignInChallenge: Equatable, Sendable {
    static let kindV1 = "wires.signin.v1"

    let version: Int
    let kind: String
    let gatewayURL: String
    let sessionID: String
    let nonce: String    // hex of 32 bytes
    let issuedAt: Int64
    let expires: Int64

    enum DecodeError: Error, Equatable {
        case malformedBase64
        case malformedJSON
        case unknownKind(String)
    }

    private struct Wire: Codable {
        let version: Int
        let kind: String
        let gateway_url: String
        let session_id: String
        let nonce: String
        let issued_at: Int64
        let expires: Int64
    }

    /// Decode from URL-safe base64 (no padding) — the encoding the server
    /// uses when embedding the challenge in the QR payload.
    static func decode(urlSafeBase64 s: String) throws -> SignInChallenge {
        guard let data = Data(urlSafeBase64NoPad: s) else {
            throw DecodeError.malformedBase64
        }
        let wire: Wire
        do {
            wire = try JSONDecoder().decode(Wire.self, from: data)
        } catch {
            throw DecodeError.malformedJSON
        }
        guard wire.kind == kindV1 else { throw DecodeError.unknownKind(wire.kind) }
        return SignInChallenge(
            version: wire.version,
            kind: wire.kind,
            gatewayURL: wire.gateway_url,
            sessionID: wire.session_id,
            nonce: wire.nonce,
            issuedAt: wire.issued_at,
            expires: wire.expires
        )
    }

    /// Canonical JSON bytes that the iOS root key signs.
    ///
    /// Reproduces the Rust server's `canonicalize()` + `serde_json::to_vec`:
    /// keys sorted lexicographically, no whitespace, slashes unescaped.
    func signingBytes() -> Data {
        let dict: [String: Any] = [
            "version": Int64(version),
            "kind": kind,
            "gateway_url": gatewayURL,
            "session_id": sessionID,
            "nonce": nonce,
            "issued_at": issuedAt,
            "expires": expires,
        ]
        // .sortedKeys ensures lexicographic key order (matches Rust canonicalize).
        // .withoutEscapingSlashes prevents "https:\/\/" in the output.
        return try! JSONSerialization.data(
            withJSONObject: dict,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
    }
}
