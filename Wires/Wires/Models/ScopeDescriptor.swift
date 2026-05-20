import Foundation

/// Generic, scope-shape-agnostic descriptor for the "what access does this
/// have / is being requested" UI. The view layer renders these. The data
/// layer (CapToServiceMapper) produces them. When the cap schema changes,
/// the mapper changes; views don't. See spec §3 Principle 5.
struct ScopeDescriptor: Equatable, Hashable, Identifiable, Sendable {
    let id: String
    let label: String
    let summary: String
    var detail: [ScopeDetailRow]

    /// True iff every detail row is granted. Drives the collapsed-state
    /// primary toggle on `ScopeRow`.
    var allGranted: Bool { detail.allSatisfy(\.granted) }

    /// Lockstep-set every detail row's `granted` flag.
    mutating func setAllGranted(_ value: Bool) {
        for i in detail.indices {
            detail[i].granted = value
        }
    }
}

struct ScopeDetailRow: Equatable, Hashable, Sendable {
    let label: String
    var granted: Bool
    let kind: ScopeRightKind
}

enum ScopeRightKind: Equatable, Hashable, Sendable {
    case read
    case write
    case grant
    case custom(String)
}
