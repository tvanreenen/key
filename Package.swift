// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "key",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "KeyCore", targets: ["KeyCore"]),
        .executable(name: "key", targets: ["key"]),
        .executable(name: "KeyLaunchAgentHelper", targets: ["KeyLaunchAgentHelper"])
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
        .executableTarget(
            name: "KeyLaunchAgentHelper",
            dependencies: ["KeyCore"]
        ),
        .testTarget(
            name: "KeyCoreTests",
            dependencies: ["KeyCore"]
        )
    ]
)
