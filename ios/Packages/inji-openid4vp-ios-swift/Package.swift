// swift-tools-version: 5.9.0

// Patched copy of github.com/inji/inji-openid4vp-ios-swift, branch release-1.0.x (commit d8c1926).
// Being local, it replaces the remote package for the app and for inji-vci-client-ios-swift alike.
// Changes (each marked "CredIssuer patch" in the source), the first two matching the patched
// Android library (io.inji:inji-openid4vp-aar:1.0.0-rc.1-credissuer.2):
// - DCQL type_values also match a credential's written type by the IRI's local name
//   (DCQLEvaluator.localTypeMatches), the rule Inji Verify 1.0 applies;
// - constructUnsignedVPToken takes a fallback holder DID, used as the ldp_vc VP holder when
//   credentialSubject.id is not a DID, as with CredIssuer's urn:uuid subjects
//   (UnsignedLdpVPTokenBuilder.resolveHolder);
// - request query values are decoded once, form-style ("+" is a space), as Android's URLDecoder
//   does (AuthorizationRequestUtils), so verifier names don't show as "CredIssuer+Verifier+App".
// The 0.7.1 copy's JWE and mdoc DeviceSigned fixes are no longer needed: release-1.0.x does both.

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
        .package(url: "https://github.com/keefertaylor/Base58Swift.git", "2.1.7"..<"2.1.8"),
        .package(url: "https://github.com/ATProtoKit/MultiformatsKit.git", from: "0.3.0")
    ],
    targets: [
        .target(
            name: "OpenID4VP",
            dependencies: [
                "jose-swift", "Alamofire", "SwiftCBOR", "Base58Swift",
                .product(name: "MultiformatsKit", package: "multiformatskit")
            ]
        ),
        .testTarget(
            name: "OpenID4VPTests",
            dependencies: [
                "OpenID4VP", "jose-swift", "Alamofire", "SwiftCBOR", "Base58Swift",
                .product(name: "MultiformatsKit", package: "multiformatskit")
            ]
        )
    ]
)
