import Foundation
import Testing
@testable import Wires

@Suite
struct SignInChallengeTests {

    // The server's `signing_bytes()` for
    // SignInChallenge::new("https://mcp.example.com", "sess-1", [7u8;32], 1000, 60_000)
    // (confirmed by running `cargo test -p wires-mcp dump_signing_bytes -- --nocapture`)
    private static let serverFixture = #"{"expires":61000,"gateway_url":"https://mcp.example.com","issued_at":1000,"kind":"wires.signin.v1","nonce":"0707070707070707070707070707070707070707070707070707070707070707","session_id":"sess-1","version":1}"#

    // URL-safe base64 (no padding) of the server fixture bytes.
    // This is what `encode_url_safe_b64()` in sign_in.rs emits.
    private static let fixtureB64 = "eyJleHBpcmVzIjo2MTAwMCwiZ2F0ZXdheV91cmwiOiJodHRwczovL21jcC5leGFtcGxlLmNvbSIsImlzc3VlZF9hdCI6MTAwMCwia2luZCI6IndpcmVzLnNpZ25pbi52MSIsIm5vbmNlIjoiMDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNzA3MDcwNyIsInNlc3Npb25faWQiOiJzZXNzLTEiLCJ2ZXJzaW9uIjoxfQ"

    @Test
    func decodes_valid_b64() throws {
        let challenge = try SignInChallenge.decode(urlSafeBase64: Self.fixtureB64)
        #expect(challenge.version == 1)
        #expect(challenge.kind == SignInChallenge.kindV1)
        #expect(challenge.gatewayURL == "https://mcp.example.com")
        #expect(challenge.sessionID == "sess-1")
        #expect(challenge.nonce == "0707070707070707070707070707070707070707070707070707070707070707")
        #expect(challenge.issuedAt == 1000)
        #expect(challenge.expires == 61000)
    }

    @Test
    func signing_bytes_are_canonical_sorted_keys_no_whitespace() throws {
        let challenge = try SignInChallenge.decode(urlSafeBase64: Self.fixtureB64)
        let bytes = challenge.signingBytes()
        let s = String(data: bytes, encoding: .utf8)!
        // Keys must be sorted lexicographically, no whitespace, no escaped slashes.
        #expect(s.contains("\"expires\":61000"), "expires must be an integer")
        #expect(!s.contains(" "), "no whitespace")
        #expect(!s.contains("\\/"), "slashes must not be escaped")
        // Keys must appear in sorted order
        let keysInOrder = ["expires", "gateway_url", "issued_at", "kind", "nonce", "session_id", "version"]
        var searchFrom = s.startIndex
        for key in keysInOrder {
            guard let r = s.range(of: "\"\(key)\"", range: searchFrom..<s.endIndex) else {
                Issue.record("Key \"\(key)\" not found in expected order")
                return
            }
            searchFrom = r.upperBound
        }
    }

    @Test
    func rejects_unknown_kind() {
        // Construct a JSON with a different kind, base64-encode it.
        let json = #"{"version":1,"kind":"wires.signin.v99","gateway_url":"https://x.example.com","session_id":"s","nonce":"aabb","issued_at":0,"expires":1000}"#
        let b64 = json.data(using: .utf8)!.base64URLEncodedNoPad()
        #expect(throws: SignInChallenge.DecodeError.self) {
            _ = try SignInChallenge.decode(urlSafeBase64: b64)
        }
    }

    /// BYTE-PARITY TEST: iOS `signingBytes()` must produce exactly the same
    /// bytes as the Rust server's `SignInChallenge::signing_bytes()`.
    ///
    /// The fixture was captured from:
    ///   cargo test -p wires-mcp dump_signing_bytes -- --nocapture
    @Test
    func signing_bytes_match_server_for_known_inputs() throws {
        let challenge = try SignInChallenge.decode(urlSafeBase64: Self.fixtureB64)
        let bytes = challenge.signingBytes()
        let got = String(data: bytes, encoding: .utf8)!
        #expect(got == Self.serverFixture, "iOS signing bytes diverge from server — gateway will reject assertions")
    }
}
