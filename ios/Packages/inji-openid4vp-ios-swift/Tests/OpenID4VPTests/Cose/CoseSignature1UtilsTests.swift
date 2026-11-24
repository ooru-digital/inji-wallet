import XCTest
import SwiftCBOR
@testable import OpenID4VP

final class CoseSignature1UtilsTests: XCTestCase {

    private let supportedAlgorithms: [(name: String, coseAlg: CBOR)] = [
        ("ES256", .negativeInt(6)),
        ("ES384", .negativeInt(34)),
        ("ES512", .negativeInt(35)),
        ("EdDSA", .negativeInt(7)),
        ("PS256", .negativeInt(36)),
        ("PS384", .negativeInt(37)),
        ("PS512", .negativeInt(38))
    ]

    private func decodeSingleItem(_ bytes: [UInt8]) throws -> CBOR {
        guard let item = try CBORDecoder(input: bytes).decodeItem() else {
            throw InvalidData(message: "Failed to decode CBOR test bytes", className: "CoseSignature1UtilsTests")
        }
        return item
    }

    private func extractProtectedAlg(from protectedHeaderBytes: [UInt8]) throws -> CBOR {
        let decodedProtected = try decodeSingleItem(protectedHeaderBytes)
        guard case let .map(protectedMap) = decodedProtected,
              let alg = protectedMap[.unsignedInt(1)] else {
            throw InvalidData(message: "Invalid protected header structure", className: "CoseSignature1UtilsTests")
        }
        return alg
    }

    func testCreateSignature1StructureBuildsExpectedStructureForAllSupportedAlgorithms() throws {
        let payload: [UInt8] = [0x01, 0x02, 0x03]

        for entry in supportedAlgorithms {
            let encoded = try CoseSignature1Utils.createSignature1Structure(payload: payload, alg: entry.name)
            let decoded = try decodeSingleItem(encoded)

            guard case let .array(items) = decoded, items.count == 4 else {
                XCTFail("Sig_Structure must be a 4-item array")
                return
            }

            XCTAssertEqual(items[0], .utf8String("Signature1"))
            XCTAssertEqual(items[2], .byteString([]))
            XCTAssertEqual(items[3], .byteString(payload))

            guard case let .byteString(protectedBytes) = items[1] else {
                XCTFail("body_protected must be a bstr")
                return
            }
            let alg = try extractProtectedAlg(from: protectedBytes)
            XCTAssertEqual(alg, entry.coseAlg)
        }
    }

    func testCreateSignature1StructureThrowsForUnsupportedAlgorithm() {
        XCTAssertThrowsError(
            try CoseSignature1Utils.createSignature1Structure(payload: [0x01], alg: "RS256")
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unsupported signing algorithm: RS256",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }

    func testCreateCoseSign1BuildsExpectedStructureForAllSupportedAlgorithms() throws {
        let signature: [UInt8] = [0xAA, 0xBB, 0xCC]

        for entry in supportedAlgorithms {
            let coseSign1 = try CoseSignature1Utils.createCoseSign1(signingAlgorithm: entry.name, signature: signature)

            guard case let .array(items) = coseSign1, items.count == 4 else {
                XCTFail("COSE_Sign1 must be a 4-item array")
                return
            }

            guard case let .byteString(protectedBytes) = items[0] else {
                XCTFail("protected header must be a bstr")
                return
            }
            let alg = try extractProtectedAlg(from: protectedBytes)
            XCTAssertEqual(alg, entry.coseAlg)

            XCTAssertEqual(items[1], .map([:]))
            XCTAssertEqual(items[2], .null)
            XCTAssertEqual(items[3], .byteString(signature))
        }
    }

    func testCreateCoseSign1SupportsEmptySignature() throws {
        let coseSign1 = try CoseSignature1Utils.createCoseSign1(signingAlgorithm: "ES256", signature: [])
        guard case let .array(items) = coseSign1, items.count == 4 else {
            XCTFail("COSE_Sign1 must be a 4-item array")
            return
        }
        XCTAssertEqual(items[3], .byteString([]))
    }

    func testCreateCoseSign1ThrowsForUnsupportedAlgorithm() {
        XCTAssertThrowsError(
            try CoseSignature1Utils.createCoseSign1(signingAlgorithm: "RS256", signature: [0x01])
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Unsupported signing algorithm: RS256",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
