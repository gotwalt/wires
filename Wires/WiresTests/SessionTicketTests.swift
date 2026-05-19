import Foundation
import Testing
@testable import Wires

@Suite
struct SessionTicketTests {
    @Test
    func decodes_valid_base64_json() throws {
        let json = """
        {"v":1,"k":"wires.oauth.v1","gateway_url":"https://mcp.example.com","session_id":"abc-123"}
        """
        let b64 = json.data(using: .utf8)!.base64URLEncodedNoPad()
        let t = try SessionTicket.decode(urlSafeBase64: b64)
        #expect(t.gatewayURL == "https://mcp.example.com")
        #expect(t.sessionID == "abc-123")
        #expect(t.kind == "wires.oauth.v1")
        #expect(t.version == 1)
    }

    @Test
    func rejects_unknown_kind() throws {
        let json = #"{"v":1,"k":"wires.other.v1","gateway_url":"x","session_id":"y"}"#
        let b64 = json.data(using: .utf8)!.base64URLEncodedNoPad()
        #expect(throws: SessionTicket.DecodeError.self) {
            _ = try SessionTicket.decode(urlSafeBase64: b64)
        }
    }

    @Test
    func rejects_malformed_base64() {
        #expect(throws: SessionTicket.DecodeError.self) {
            _ = try SessionTicket.decode(urlSafeBase64: "not!valid!@@")
        }
    }
}
