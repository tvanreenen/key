// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "key",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "KeyCore", targets: ["KeyCore"]),
        .executable(name: "key", targets: ["key"])
    ],
    targets: [
        .target(
            name: "KeyCore",
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security")
            ]
        ),
        .executableTarget(
            name: "key",
            dependencies: ["KeyCore"]
        ),
        .testTarget(
            name: "KeyCoreTests",
            dependencies: ["KeyCore"]
        )
    ]
)
