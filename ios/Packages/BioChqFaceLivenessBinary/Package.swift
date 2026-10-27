// swift-tools-version: 5.9
// The published BioChqFaceLiveness XCFramework (face liveness and face match) from the BioChq
// Nexus, as a Swift package. URL and checksum are from the SDK's release notes
// (tag faceliveness-ios/v<version> in ooru-digital/biochq-verifier-web).
//
// Swift Package Manager logs in to Nexus through ~/.netrc:
//   machine nexus-biochq.credissuer.com login <user> password <password>
import PackageDescription

let package = Package(
    name: "BioChqFaceLivenessBinary",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "BioChqFaceLiveness", targets: ["BioChqFaceLiveness"]),
    ],
    targets: [
        // io.ooru.biometrics:faceliveness-ios:1.0.0-rc.1
        .binaryTarget(
            name: "BioChqFaceLiveness",
            url: "https://nexus-biochq.credissuer.com/repository/buildpiper-release/io/ooru/biometrics/faceliveness-ios/1.0.0-rc.1/faceliveness-ios-1.0.0-rc.1.zip",
            checksum: "d2ae2cec439dd04d578bff71c0432b7487ed70a37daa2ac7b26a9c1d6beade98"
        ),
    ]
)
