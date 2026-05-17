// swift-tools-version: 5.10
import PackageDescription

let package = Package(
    name: "WiresKit",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "WiresKit", targets: ["WiresKit"]),
    ],
    targets: [
        .binaryTarget(
            name: "wiresFFI",
            path: "Frameworks/wires.xcframework"
        ),
        .target(
            name: "WiresKit",
            dependencies: ["wiresFFI"],
            path: "Sources/WiresKit"
        ),
    ]
)
