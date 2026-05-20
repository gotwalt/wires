import Foundation

extension CameraPermissionClient {
    /// Returns `status` from `current` and `request`. No system prompt
    /// ever pops in the simulator.
    static func fixture(_ status: ScanPermissionStatus) -> CameraPermissionClient {
        CameraPermissionClient(
            current: { status },
            request: { status }
        )
    }
}
