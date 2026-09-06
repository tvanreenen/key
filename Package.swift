// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "key",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .library(name: "KeyCore", targets: ["KeyCore"]),
        .executable(name: "key", targets: ["key"]),
        .executable(name: "KeyLaunchAgentHelper", targets: ["KeyLaunchAgentHelper"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", exact: "1.8.2")
    ],
    targets: [
        .target(
            name: "JSONCanonicalization"
        ),
        .target(
            name: "KeyCore",
            dependencies: [
                "JSONCanonicalization",
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ],
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
            dependencies: ["KeyCore", "JSONCanonicalization"]
        ),
        .testTarget(
            name: "JSONCanonicalizationTests",
            dependencies: ["JSONCanonicalization"]
        )
    ]
)
