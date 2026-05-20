import SwiftUI

/// Brand glyph — two crossing wires forming a stylized key. The static
/// variant renders instantly; `.drawIn(duration:)` animates each segment.
/// See spec §4 Glyph library.
struct WiresBrandGlyph: View {
    enum Variant {
        case `static`
        case drawIn(duration: Double)
    }

    let variant: Variant
    var size: CGFloat = 96
    var color: Color = AppColors.indigoPrimary

    @State private var progress: CGFloat = 1.0

    var body: some View {
        ZStack {
            // Key head — open circle, top-right
            Circle()
                .trim(from: 0, to: progress)
                .stroke(color, style: StrokeStyle(lineWidth: size * 0.08, lineCap: .round))
                .frame(width: size * 0.42, height: size * 0.42)
                .offset(x: size * 0.22, y: -size * 0.22)

            // Wire 1 — diagonal stroke from bottom-left up
            Capsule()
                .trim(from: 0, to: progress)
                .stroke(color, style: StrokeStyle(lineWidth: size * 0.08, lineCap: .round))
                .frame(width: size * 0.08, height: size * 0.78)
                .rotationEffect(.degrees(35))

            // Wire 2 — counter diagonal
            Capsule()
                .trim(from: 0, to: progress)
                .stroke(color, style: StrokeStyle(lineWidth: size * 0.08, lineCap: .round))
                .frame(width: size * 0.08, height: size * 0.78)
                .rotationEffect(.degrees(-35))
        }
        .frame(width: size, height: size)
        .onAppear {
            switch variant {
            case .static:
                progress = 1.0
            case .drawIn(let duration):
                progress = 0
                withAnimation(.easeOut(duration: duration)) {
                    progress = 1.0
                }
            }
        }
        .accessibilityHidden(true)
    }
}

#Preview("Static") {
    WiresBrandGlyph(variant: .static)
        .padding()
}

#Preview("Draw-in") {
    WiresBrandGlyph(variant: .drawIn(duration: 2.0))
        .padding()
}
