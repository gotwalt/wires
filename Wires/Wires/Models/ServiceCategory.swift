import Foundation

enum ServiceCategory: String, CaseIterable, Codable, Sendable, Hashable {
    case banking
    case utilities
    case smartHome
    case devTool
    case unknown

    var sfSymbol: String {
        switch self {
        case .banking:    return "creditcard.fill"
        case .utilities:  return "bolt.fill"
        case .smartHome:  return "house.fill"
        case .devTool:    return "terminal.fill"
        case .unknown:    return "questionmark.app.dashed"
        }
    }
}
