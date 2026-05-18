import ComposableArchitecture
import Foundation
import Testing
@testable import Wires

@MainActor
struct ScanFeatureTests {
    struct StubPayload: Equatable, Sendable {
        let value: String
    }

    @Test
    func permissionDeniedPathSurfacesStatus() async {
        let store = TestStore(
            initialState: ScanFeature<StubPayload>.State()
        ) {
            ScanFeature(parse: { StubPayload(value: $0) })
        } withDependencies: {
            $0.cameraPermissionClient = CameraPermissionClient(
                current: { .denied },
                request: { .denied }
            )
        }

        await store.send(.appeared)
        await store.receive(\.permissionResolved) {
            $0.cameraPermission = .denied
        }
    }

    @Test
    func decodedPayloadParsesSuccessfully() async {
        let store = TestStore(
            initialState: ScanFeature<StubPayload>.State()
        ) {
            ScanFeature(parse: { StubPayload(value: $0) })
        } withDependencies: {
            $0.cameraPermissionClient = CameraPermissionClient(
                current: { .granted },
                request: { .granted }
            )
        }

        await store.send(.decoded("hello")) {
            $0.lastDecoded = "hello"
        }
        await store.receive(\.decodedPayload, StubPayload(value: "hello"))
    }

    @Test
    func parserThrowsEmitsDecodeFailed() async {
        struct ParserError: Error {}
        let store = TestStore(
            initialState: ScanFeature<StubPayload>.State()
        ) {
            ScanFeature(parse: { _ in throw ParserError() })
        } withDependencies: {
            $0.cameraPermissionClient = CameraPermissionClient(
                current: { .granted },
                request: { .granted }
            )
        }

        await store.send(.decoded("garbage")) {
            $0.lastDecoded = "garbage"
        }
        await store.receive(\.decodeFailed) {
            $0.error = .parseFailed("ParserError()")
        }
    }
}
