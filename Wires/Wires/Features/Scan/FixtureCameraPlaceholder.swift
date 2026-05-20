import SwiftUI

/// Static stand-in for the live camera preview. Used in snapshot fixture
/// runs. Visually mimics a viewfinder: dim background, centered reticle
/// SF Symbol. Does not instantiate an AVCaptureSession.
struct FixtureCameraPlaceholder: View {
    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color.black, Color(white: 0.12)],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            Image(systemName: "qrcode.viewfinder")
                .resizable()
                .scaledToFit()
                .frame(width: 220, height: 220)
                .foregroundStyle(.white.opacity(0.85))
                .shadow(color: .black.opacity(0.4), radius: 6, y: 2)
        }
    }
}
