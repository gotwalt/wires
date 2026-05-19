import Foundation
import WiresKit

extension Data {
    /// Decode a hex string (no separators, lower-case or upper-case). Returns
    /// `nil` on an odd length or any non-hex byte.
    init?(wiresHex hex: String) {
        guard hex.count % 2 == 0 else { return nil }
        var bytes = Data(capacity: hex.count / 2)
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx ..< next], radix: 16) else { return nil }
            bytes.append(byte)
            idx = next
        }
        self = bytes
    }

    /// Encode as a lower-case hex string (no separators).
    func wiresHex() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}

/// Stable serialised name for a Right — matches the spec's wire-format
/// strings and is what `CapRecord.rights` stores.
func wiresRightString(_ right: Right) -> String {
    switch right {
    case .read: return "read"
    case .write: return "write"
    }
}
