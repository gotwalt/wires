import Testing
@testable import Wires

@Suite("HexFormatter")
struct HexFormatterTests {
    @Test("quadGrouped inserts a space every 4 chars")
    func quadGroupedBreaks() {
        #expect(HexFormatter.quadGrouped("0064d52458dca7ec") == "0064 d524 58dc a7ec")
    }

    @Test("quadGrouped tolerates odd-length and empty inputs")
    func quadGroupedEdgeCases() {
        #expect(HexFormatter.quadGrouped("") == "")
        #expect(HexFormatter.quadGrouped("ab") == "ab")
        #expect(HexFormatter.quadGrouped("abcdef") == "abcd ef")
    }

    @Test("shortFingerprint elides the middle when long enough")
    func shortFingerprintShortens() {
        let full = String(repeating: "0", count: 8)
            + String(repeating: "x", count: 48)
            + String(repeating: "1", count: 8)
        #expect(HexFormatter.shortFingerprint(full) == "00000000…11111111")
    }

    @Test("shortFingerprint passes short inputs through unchanged")
    func shortFingerprintPassthrough() {
        #expect(HexFormatter.shortFingerprint("abcd") == "abcd")
    }
}
