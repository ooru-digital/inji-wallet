import Foundation
import SwiftCBOR

fileprivate let className = "CBORUtils"

func decodeCBOR(base64EncodedInput : String) throws -> CBOR? {
    do{
        let decodedBase64Data = try Base64Decoder.decodeBase64ToData(base64EncodedInput)
        let inputToCBORDecode = Array(decodedBase64Data)
        let cborDecodedData = try CBOR.decode(inputToCBORDecode)
        return cborDecodedData
    }
    catch let error {
        throw InvalidData( message: "Error while decoding input - \(error)", className: String(describing: CBOR.self))
    }
}

func cborEncode(_ input: CBOR) -> [UInt8] {
    return CBOR.encode(input)
}

func toCBOR(_ input: Data) -> CBOR {
    return CBOR.byteString([UInt8](input))
}

// creates #6.24 (bstr .cbor input)
func wrapCBORInputWithTag24(input: CBOR) -> CBOR? {
    guard let encodedInput: [UInt8]? = SwiftCBOR.CBOR.encode(input) else {
        print("Failed to encode input CBOR")
        return nil
    }
    let cborTaggedValue: CBOR = .tagged(CBOR.Tag(rawValue: 24), .byteString(encodedInput!))
    
    return cborTaggedValue
}

internal func toCBORArray(_ input: [CBOR]) -> CBOR {
    return CBOR.array(input.map { ($0) })
}

func getValueFromCBORMap(cborMap: CBOR, key: String) -> CBOR? {
    guard case let .map(items) = cborMap else { return nil }
    
    let cborKey = CBOR.utf8String(key)
    return items[cborKey]
}

func extractStringFromCBOR(_ cbor: CBOR) -> String? {
    if case let .utf8String(str) = cbor {
        return str
    }
    return nil
}

func cborToByteString(cbor: CBOR) -> String {
    let encodedData : [UInt8] = CBOR.encode(cbor)
    
    return encodedData.map { String(format: "%02x", $0) }.joined()
}

//RFC 8610, 8230 ECDSA / EdDSA Algorithm Values
func mapSigningAlgorithmToProtectedAlg(algorithm: String) throws -> CBOR {
    switch algorithm {
    case "ES256":
        return .negativeInt(6)   // ECDSA w/ SHA-256 (-7 in COSE)
    case "ES384":
        return .negativeInt(34)  // ECDSA w/ SHA-384 (-35 in COSE)
    case "ES512":
        return .negativeInt(35)  // ECDSA w/ SHA-512 (-36 in COSE)
    case "EdDSA":
        return .negativeInt(7)   // EdDSA (-8 in COSE)
    case "PS256":
        return .negativeInt(36)  // RSASSA-PSS w/ SHA-256 (-37 in COSE)
    case "PS384":
        return .negativeInt(37)  // RSASSA-PSS w/ SHA-384 (-38 in COSE)
    case "PS512":
        return .negativeInt(38)  // RSASSA-PSS w/ SHA-512 (-39 in COSE)
    default:
        throw InvalidData(
            message: "Unsupported signing algorithm: \(algorithm)",
            className: className
        )
    }
}
