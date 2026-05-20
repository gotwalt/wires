import Foundation

/// View-layer summary of a connected service, derived from CapRecord via
/// CapToServiceMapper. Views never see CapRecord directly. See spec §7.
struct ServiceSummary: Equatable, Identifiable, Sendable {
    let id: String                  // stable id (today: capIdHex)
    let name: String                // user-visible service name
    let deviceName: String?         // "on Aaron's Mac mini"
    let category: ServiceCategory
    let status: ServiceStatus
    let scopes: [ScopeDescriptor]
    let connectedAt: Date
    let lastActivityAt: Date?
}
