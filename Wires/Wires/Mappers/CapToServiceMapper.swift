import Foundation

/// Single conversion point from persistence (CapRecord) to view-layer
/// (ServiceSummary + ScopeDescriptor). When the cap shape changes (and per
/// the spec it WILL change), this file changes; views don't.
enum CapToServiceMapper {
    static func summary(from cap: CapRecord) -> ServiceSummary {
        ServiceSummary(
            id: cap.capIdHex,
            name: cap.nodeAlias.flatMap { $0.isEmpty ? nil : $0 } ?? "Service",
            deviceName: nil,    // populated once agents declare device separately
            category: .unknown, // populated once agents declare category
            status: cap.revokedAt == nil ? .connected : .revoked,
            scopes: scopes(from: cap),
            connectedAt: cap.issuedAt,
            lastActivityAt: nil
        )
    }

    private static func scopes(from cap: CapRecord) -> [ScopeDescriptor] {
        cap.topicNames.map { topic in
            ScopeDescriptor(
                id: topic,
                label: topic,
                summary: cap.rights.map(humanizedRight).joined(separator: " · "),
                detail: cap.rights.map { right in
                    ScopeDetailRow(
                        label: humanizedRight(right),
                        granted: true,
                        kind: scopeRightKind(right)
                    )
                }
            )
        }
    }

    private static func humanizedRight(_ raw: String) -> String {
        switch raw {
        case "read":  return "Read messages"
        case "write": return "Send messages"
        case "grant": return "Invite other services"
        default:      return raw.capitalized
        }
    }

    private static func scopeRightKind(_ raw: String) -> ScopeRightKind {
        switch raw {
        case "read":  return .read
        case "write": return .write
        case "grant": return .grant
        default:      return .custom(raw)
        }
    }
}
