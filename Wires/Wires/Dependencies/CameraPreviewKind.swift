import ComposableArchitecture
import Dependencies

/// Which renderer ScanView should put inside the `.granted` branch.
///
/// `.live` instantiates an `AVCaptureSession`-backed view; `.placeholder`
/// renders a static viewfinder graphic. The latter is used for snapshot
/// fixtures (where the simulator has no camera) and could be used for
/// Xcode previews in the future.
enum CameraPreviewKind: Equatable, Sendable {
    case live
    case placeholder
}

extension DependencyValues {
    var cameraPreviewKind: CameraPreviewKind {
        get { self[CameraPreviewKindKey.self] }
        set { self[CameraPreviewKindKey.self] = newValue }
    }
}

private enum CameraPreviewKindKey: DependencyKey {
    static let liveValue: CameraPreviewKind = .live
}
