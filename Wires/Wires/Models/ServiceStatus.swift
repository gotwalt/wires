import SwiftUI

enum ServiceStatus: String, CaseIterable, Codable, Sendable, Hashable {
    case connected
    case pending
    case disconnected
    case revoked

    var label: String {
        switch self {
        case .connected:    return "Connected"
        case .pending:      return "Pending"
        case .disconnected: return "Disconnected"
        case .revoked:      return "Revoked"
        }
    }

    var tint: Color {
        switch self {
        case .connected:    return .green
        case .pending:      return .orange
        case .disconnected: return .gray
        case .revoked:      return .red
        }
    }
}
