import Foundation
import SwiftCBOR

internal enum CoseSignature1Utils {

    /// Creates a COSE Sig_Structure for COSE_Sign1 signing (RFC 8152).
    ///
    /// Sig_Structure = [
    ///   context       : "Signature1",
    ///   body_protected : bstr .cbor Headers,
    ///   external_aad   : bstr,
    ///   payload        : bstr
    /// ]
    ///
    /// - Parameters:
    ///   - payload: The raw bytes to be signed (e.g. CBOR-encoded DeviceAuthenticationBytes).
    ///   - alg: The signing algorithm string (e.g. "ES256").
    /// - Returns: The CBOR-encoded Sig_Structure as bytes.
    static func createSignature1Structure(payload: [UInt8], alg: String) throws -> [UInt8] {
        let coseAlg = try mapSigningAlgorithmToProtectedAlg(algorithm: alg)
        let protectedHeaderBytes = cborEncode(.map([.unsignedInt(1): coseAlg]))

        let sigStructure = CBOR.array([
            .utf8String("Signature1"),
            .byteString(protectedHeaderBytes), // body_protected
            .byteString([]),                   // empty external_aad
            .byteString(payload)               // payload
        ])

        return cborEncode(sigStructure)
    }

    /// Creates a COSE_Sign1 structure (the final signed message, RFC 8152).
    ///
    /// COSE_Sign1 = [
    ///   protected   : bstr .cbor Headers,
    ///   unprotected : {},
    ///   payload     : nil,
    ///   signature   : bstr
    /// ]
    ///
    /// - Parameters:
    ///   - signingAlgorithm: The signing algorithm (e.g. "ES256").
    ///   - signature: The raw signature bytes.
    /// - Returns: The COSE_Sign1 as a CBOR value.
    static func createCoseSign1(signingAlgorithm: String, signature: [UInt8]) throws -> CBOR {
        let coseAlg = try mapSigningAlgorithmToProtectedAlg(algorithm: signingAlgorithm)
        let protectedHeaderBytes = cborEncode(.map([.unsignedInt(1): coseAlg]))

        return CBOR.array([
            .byteString(protectedHeaderBytes),
            .map([:]),  // empty unprotected header
            .null,      // detached payload
            .byteString(signature)
        ])
    }
}
