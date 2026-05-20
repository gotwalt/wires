import Foundation

/// Helpers for presenting long cryptographic hex identifiers in a more
/// readable way. The raw hex is kept selectable via `textSelection(.enabled)`;
/// these formatters only change how it visually breaks.
enum HexFormatter {
    /// Group an even-length hex string into space-separated quads:
    /// `0064d52458dca7ec...` → `0064 d524 58dc a7ec ...`.
    /// Each quad is 4 hex chars = 2 bytes. The thin spaces let SwiftUI wrap
    /// at quad boundaries instead of breaking inside a byte.
    static func quadGrouped(_ hex: String) -> String {
        guard !hex.isEmpty else { return "" }
        var out = ""
        out.reserveCapacity(hex.count + hex.count / 4)
        for (i, c) in hex.enumerated() {
            if i > 0 && i % 4 == 0 { out.append(" ") }
            out.append(c)
        }
        return out
    }

    /// Short head…tail form for use in collapsed list rows where the full
    /// identifier doesn't fit: `0a2068c5…8c6054d5`. Uses 8 hex chars on each
    /// side (32 bits of leading entropy + 32 bits of trailing) which is
    /// enough to recognize at a glance but doesn't dominate a row.
    static func shortFingerprint(_ hex: String, head: Int = 8, tail: Int = 8) -> String {
        guard hex.count > head + tail + 1 else { return hex }
        let prefix = hex.prefix(head)
        let suffix = hex.suffix(tail)
        return "\(prefix)…\(suffix)"
    }
}
