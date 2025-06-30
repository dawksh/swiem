// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swiem",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "swiem",
            targets: ["swiem"]),
    ],
    dependencies: [
        .package(url: "https://github.com/argentlabs/web3.swift", from: "0.9.2"), // SwiftKeccak
        .package(url: "https://github.com/tesseract-one/Bip39.swift.git", from: "0.2.0"),
        .package(url: "https://github.com/GigaBitcoin/secp256k1.swift", from: "0.1.7"),
        .package(url: "https://github.com/alephao/swift-rlp.git", branch: "main")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "swiem",
            dependencies: [
                .product(name: "Keccak", package: "web3.swift"),
                .product(name: "Bip39", package: "Bip39.swift"),
                .product(name: "secp256k1", package: "secp256k1.swift"),
                .product(name: "RLP", package: "swift-rlp")
            ]
        ),
        .testTarget(
            name: "swiemTests",
            dependencies: ["swiem"]
        ),
    ]
)
