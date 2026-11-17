// swift-tools-version: 5.9.0

// Patched copy of github.com/inji/inji-openid4vp-ios-swift v0.7.1 (commit 7a1574b). Being local,
// it replaces the remote package for the app and for inji-vci-client-ios-swift alike.
// Changes, both matching the Android library, without which readers reject iOS mdoc responses:
// - the direct_post.jwt JWE (jwt/JWE) follows RFC 7516/7518: Concat KDF instead of HKDF, and
//   the protected header as AES-GCM AAD;
// - the mdoc DeviceSigned map (MdocVPTokenBuilder) uses the ISO 18013-5 keys "deviceAuth" and
//   "nameSpaces" instead of "deviceAuthentication" and "namespaces";
// - request query values are decoded once, form-style ("+" is a space), as Android's URLDecoder
//   does (AuthorizationRequestUtils), so verifier names don't show as "CredIssuer+Verifier+App".
// Drop this copy once an upstream release does the same.

import PackageDescription

let package = Package(
    name: "OpenID4VP",
    platforms: [
        .iOS(.v14),
        .macOS(.v12),
    ],
    products: [
        .library(
            name: "OpenID4VP",
            targets: ["OpenID4VP"]),
    ],
    dependencies: [
        .package(url: "https://github.com/beatt83/jose-swift.git", "4.0.2"..<"4.0.3"),
        .package(url: "https://github.com/Alamofire/Alamofire.git", "5.10.2"..<"5.10.3"),
        .package(url: "https://github.com/valpackett/SwiftCBOR.git",  "0.5.0"..<"0.5.1"),
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", "2.1.7"..<"2.1.8")
    ],
    targets: [
        .target(
            name: "OpenID4VP",
            dependencies: [
                "jose-swift", "Alamofire", "SwiftCBOR", "Base58Swift"
            ]
        ),
        .testTarget(
            name: "OpenID4VPTests",
            dependencies: [
                "OpenID4VP", "jose-swift", "Alamofire", "SwiftCBOR", "Base58Swift"
            ]
        )
    ]
)
