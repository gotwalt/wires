import AVFoundation
import ComposableArchitecture
import SwiftUI
import UIKit

/// SwiftUI scanner view. Wraps an `AVCaptureSession` + QR
/// `AVCaptureMetadataOutput` and forwards every decoded payload to the
/// store via `decoded(_:)`. The reducer handles parsing and error display.
struct ScanView<Payload: Equatable & Sendable>: View {
    @Bindable var store: StoreOf<ScanFeature<Payload>>
    @Dependency(\.cameraPreviewKind) private var previewKind

    var body: some View {
        ZStack {
            switch store.cameraPermission {
            case .notDetermined:
                ProgressView("Requesting camera access…")
                    .task { store.send(.appeared) }
            case .denied:
                permissionDeniedView
            case .granted:
                Group {
                    switch previewKind {
                    case .live:
                        CameraCaptureView { payload in
                            store.send(.decoded(payload))
                        }
                        .ignoresSafeArea()
                    case .placeholder:
                        FixtureCameraPlaceholder()
                    }
                }

                if let err = store.error {
                    errorBanner(err)
                }
            }
        }
    }

    private var permissionDeniedView: some View {
        VStack(spacing: 16) {
            Image(systemName: "camera.fill")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("Camera access denied")
                .font(.headline)
            Text("Enable camera access in Settings to scan QR codes.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Open Settings") {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            }
            .buttonStyle(.borderedProminent)
        }
        .padding()
    }

    private func errorBanner(_ err: ScanError) -> some View {
        VStack {
            Spacer()
            Text(message(for: err))
                .font(.callout)
                .foregroundStyle(.white)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(.red.opacity(0.85), in: Capsule())
                .padding(.bottom, 32)
        }
    }

    private func message(for err: ScanError) -> String {
        switch err {
        case .cameraUnavailable: return "Camera unavailable on this device."
        case let .parseFailed(detail): return "Couldn't decode QR: \(detail)"
        }
    }
}

// MARK: - AVCaptureSession bridge

private struct CameraCaptureView: UIViewControllerRepresentable {
    let onDecoded: (String) -> Void

    func makeUIViewController(context: Context) -> CameraScannerController {
        let c = CameraScannerController()
        c.onDecoded = onDecoded
        return c
    }

    func updateUIViewController(_ uiViewController: CameraScannerController, context: Context) {
        uiViewController.onDecoded = onDecoded
    }
}

private final class CameraScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onDecoded: ((String) -> Void)?

    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        configureSession()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        if !session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [session] in
                session.startRunning()
            }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning {
            session.stopRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    private func configureSession() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else {
            return
        }
        if session.canAddInput(input) {
            session.addInput(input)
        }
        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
        }
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        previewLayer = layer
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let payload = obj.stringValue else {
            return
        }
        onDecoded?(payload)
    }
}
