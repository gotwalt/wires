import CasePaths
import ComposableArchitecture
import Foundation

enum ScanPermissionStatus: Equatable, Sendable {
    case notDetermined
    case granted
    case denied
}

enum ScanError: Error, Equatable, Sendable {
    case cameraUnavailable
    case parseFailed(String)
}

/// Reusable QR scanner reducer. Generic on the parsed payload type so the
/// same reducer drives bootstrap (`HostInfo`) and agent enrollment
/// (`PairRequestPreview`). The parser closure is injected at init.
///
/// Manual `Reducer` conformance — the `@Reducer` macro doesn't play
/// nicely with generics, and the manual form sidesteps the Swift 6
/// circular-reference quirk we hit on the non-generic features.
struct ScanFeature<Payload: Equatable & Sendable>: Reducer {
    @ObservableState
    struct State: Equatable {
        var cameraPermission: ScanPermissionStatus = .notDetermined
        var lastDecoded: String?
        var error: ScanError?
    }

    @CasePathable
    enum Action: Equatable {
        case appeared
        case permissionResolved(ScanPermissionStatus)
        case decoded(String)
        case decodedPayload(Payload)
        case decodeFailed(ScanError)
    }

    let parse: @Sendable (String) async throws -> Payload

    @Dependency(\.cameraPermissionClient) var camera

    init(parse: @escaping @Sendable (String) async throws -> Payload) {
        self.parse = parse
    }

    func reduce(into state: inout State, action: Action) -> Effect<Action> {
        switch action {
        case .appeared:
            return .run { send in
                let current = await camera.current()
                if current == .notDetermined {
                    let resolved = await camera.request()
                    await send(.permissionResolved(resolved))
                } else {
                    await send(.permissionResolved(current))
                }
            }

        case let .permissionResolved(status):
            state.cameraPermission = status
            return .none

        case let .decoded(payload):
            state.lastDecoded = payload
            state.error = nil
            return .run { [parse] send in
                do {
                    let parsed = try await parse(payload)
                    await send(.decodedPayload(parsed))
                } catch {
                    await send(.decodeFailed(.parseFailed(String(describing: error))))
                }
            }

        case .decodedPayload:
            return .none

        case let .decodeFailed(err):
            state.error = err
            return .none
        }
    }
}
