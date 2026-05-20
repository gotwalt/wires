import Foundation
import UIKit

/// The two appearance settings the snapshot sweep cares about. Shared
/// between the app (reads `WIRES_APPEARANCE` at launch) and the UITest
/// (writes it into `launchEnvironment`).
enum Appearance: String, CaseIterable {
    case light
    case dark

    var uiStyle: UIUserInterfaceStyle {
        switch self {
        case .light: .light
        case .dark: .dark
        }
    }
}
