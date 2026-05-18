import AVFoundation
import ComposableArchitecture
import Dependencies

/// TCA dependency over `AVCaptureDevice` camera authorization. The reducer
/// only needs two operations: read the current status and (idempotently)
/// request access if it's `.notDetermined`.
@DependencyClient
struct CameraPermissionClient {
    var current: @Sendable () async -> ScanPermissionStatus = { .notDetermined }
    var request: @Sendable () async -> ScanPermissionStatus = { .notDetermined }
}

extension CameraPermissionClient: DependencyKey {
    static let liveValue: CameraPermissionClient = CameraPermissionClient(
        current: {
            switch AVCaptureDevice.authorizationStatus(for: .video) {
            case .authorized: return .granted
            case .denied, .restricted: return .denied
            case .notDetermined: return .notDetermined
            @unknown default: return .denied
            }
        },
        request: {
            let granted = await AVCaptureDevice.requestAccess(for: .video)
            return granted ? .granted : .denied
        }
    )
}

extension DependencyValues {
    var cameraPermissionClient: CameraPermissionClient {
        get { self[CameraPermissionClient.self] }
        set { self[CameraPermissionClient.self] = newValue }
    }
}
