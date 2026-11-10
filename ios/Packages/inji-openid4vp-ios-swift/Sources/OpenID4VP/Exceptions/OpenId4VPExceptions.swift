import Foundation

public class OpenID4VPException: Error, CustomStringConvertible, LocalizedError {
    public let errorCode: String
    public let message: String
    public let className: String
    // holds the response received from the Verifier if the error is sent to the Verifier
    public var verifierResponse: VerifierResponse?
    
    internal func setVerifierResponse(_ response: VerifierResponse) {
        self.verifierResponse = response
    }
    
    private static var logTag = ""
    private static var traceabilityId: String?

    public init(errorCode: String, message: String, className: String) {
        self.errorCode = errorCode
        self.message = message
        self.className = className
        print("ERROR [\(errorCode)] - \(message) | Class: \(className)")
    }

    public var description: String {
        return "\(errorCode) : \(message)"
    }

    public var errorDescription: String? {
        return message
    }

    func toErrorResponse() -> [String: String] {
        return [
            "error": errorCode,
            "error_description": message
        ]
    }
    
    func toAuthorizationErrorResponse(state: String?) -> AuthorizationErrorResponse {
            return AuthorizationErrorResponse(
                error: self.errorCode,
                errorDescription: self.message,
                state: state
            )
        }
    
    static func setTraceabilityId(className: String, traceabilityId: String? = nil) {
        if let traceId = traceabilityId {
            self.traceabilityId = traceId
        }
    }
    static func getLogTag(_ className: String) -> String {
        return "INJI-OpenID4VP : \(className) | traceID \(String(describing: self.traceabilityId))"
    }
    
    static func error(_ logTag: String, _ exception: Error) {
        print("\(logTag) | ERROR: \(exception.localizedDescription)")
    }
    
    static func error( _ exception: Error, className: String) {
        print("\(logTag) | ERROR: \(exception.localizedDescription)")
    }
}


class InvalidQueryParams: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class InvalidVerifier: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidClient, message: message, className: className)
    }
}

class InvalidInputPattern: OpenID4VPException {
    init(fieldPath: Any, className: String) {
        let pattern = (fieldPath as? [String])?.joined(separator: "->") ?? "\(fieldPath)"
        let message = "Invalid Input Pattern: \(pattern) pattern is not matching with OpenId4VP specification"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class JsonEncodingFailed: OpenID4VPException {
    init(fieldPath: Any? = nil, errorMessage: String, className: String) {
        super.init(
            errorCode: OpenID4VPErrorCodes.invalidRequest,
            message: "Json encoding failed for \(fieldPath ?? "") due to this error: \(errorMessage)",
            className: className
        )
    }
}

class DeserializationFailure: OpenID4VPException {
    init(fieldPath: Any, errorMessage: String, className: String) {
        super.init(
            errorCode: OpenID4VPErrorCodes.invalidRequest,
            message: "Deserializing for \(fieldPath) failed due to this error: \(errorMessage)",
            className: className
        )
    }
}

class InvalidLimitDisclosure: OpenID4VPException {
    init(className: String) {
        super.init(
            errorCode: OpenID4VPErrorCodes.invalidRequest,
            message: "Invalid Input: constraints->limit_disclosure value should be preferred",
            className: className
        )
    }
}



class InvalidData: OpenID4VPException {
    init(message: String, className: String, code: String? = nil) {
        super.init(errorCode: code ?? OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class MissingInput: OpenID4VPException {
    init(fieldPath: Any, message: String? = "", className: String) {
        let resolvedMessage: String
        if let field = fieldPath as? String, !field.isEmpty {
            resolvedMessage = "Missing Input: \(field) param is required"
        } else if let list = fieldPath as? [String], !list.isEmpty {
            resolvedMessage = "Missing Input: \(list.joined(separator: "->")) param is required"
        } else {
            resolvedMessage = message ?? ""
        }
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: resolvedMessage, className: className)
    }
}

class InvalidInput: OpenID4VPException {
    init(fieldPath: Any, value: Any? = nil, className: String) {
        let path = (fieldPath as? [String])?.joined(separator: "->") ?? "\(fieldPath)"
        let message: String

        if let str = value as? String, str.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            message = "Invalid Input: \(path) value cannot be empty or null"
        } else if value == nil {
            message = "Invalid Input: \(path) value cannot be empty or null"
        } else if value is Bool {
            message = "Invalid Input: \(path) value must be either true or false"
        } else {
            message = "Invalid Input: \(path) value is invalid"
        }

        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}


// MARK: - JWS

class UnsupportedPublicKeyType: OpenID4VPException {
    init(className: String) {
        let message = "Unsupported Public Key type. Supported: publicKeyMultibase, publicKeyJwk, publicKeyHex, publicKeyPem"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class KidExtractionFailed: OpenID4VPException {
    init(className: String) {
        let message = "Kid extraction from did document failed"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class PublicKeyResolutionFailed: OpenID4VPException {
    init(message: String, className: String, code: String = OpenID4VPErrorCodes.invalidRequest) {
        super.init(errorCode: code, message: message, className: className)
    }
}

class InvalidSignature: OpenID4VPException {
    init(className: String) {
        let message = "JWS proof verification failed"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class VerificationFailure: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class JsonDecodingFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(
            errorCode: OpenID4VPErrorCodes.invalidRequest,
            message: message,
            className: className
        )
    }
}


// MARK: - JWE


class UnsupportedEncryptionAlgorithm: OpenID4VPException {
    init(className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: "Required Encryption algorithm is not supported", className: className)
    }
}


class UnsupportedDidUrl: OpenID4VPException {
    init(className: String) {
        let message = "Given did url is not supported"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class DidResolutionFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class PayloadConversionFailed: OpenID4VPException {
    init(className: String) {
        let message =  "Failed to convert payload to Data"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class InvalidResponseMode: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

public class GenericFailure: OpenID4VPException {
    public init(message: String = "", className: String) {
        let message = "Unknown error occurred \(message)"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}




class InvalidType: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class MismatchingClientIDInRequest: OpenID4VPException {
    init(className: String) {
        let message = "Client Id mismatch in Authorization Request parameter and the Request Object"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class MismatchingClientIdSchemeInRequest: OpenID4VPException {
    init(className: String) {
        let message = "Client Id Scheme mismatch in Authorization Request parameter and the Request Object"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class UnsupportedKeyAgreementAlgorithm: OpenID4VPException {
    init(className: String) {
        let message = "Required Key Agreement algorithm is not supported."
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class KeyAgreementFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: "Key agreement failed. - \(message)", className: className)
    }
}

class PublicKeyConversionFailed: OpenID4VPException {
    init(message : String = "Public key Data conversion from base64 failed.", className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class InvalidEncryptionKeySize: OpenID4VPException {
    init(className: String) {
        let message = "Invalid Key size provided for encryption."
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class UnsupportedHttpMethod: OpenID4VPException {
    init(message: String, className: String) {
        let message = "Unsupported HTTP method: \(message)"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequestUriMethod, message: message, className: className)
    }
}

class UnsupportedSignatureAlgorithm: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class Base64DecodingFailed: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

class UnsupportedTypeDecoding: OpenID4VPException {
    init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}



class UTF8EncodingFailed: OpenID4VPException {
    init(fieldPath: Any, className: String) {
        let message = "Failed to convert \(fieldPath) string to UTF-8 data"
        super.init(errorCode: OpenID4VPErrorCodes.invalidRequest, message: message, className: className)
    }
}

public class AccessDenied: OpenID4VPException {
    public init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.accessDenied, message: message, className: className)
    }
}

public class InvalidTransactionData: OpenID4VPException {
    public init(message: String, className: String) {
        super.init(errorCode: OpenID4VPErrorCodes.invalidTransactionData, message: message, className: className)
    }
}

public class UnsupportedOperationException : OpenID4VPException {
    public init(message: String, className: String, code: String = "unsupported_operation") {
        super.init(errorCode: code, message: message, className: className)
    }
}

public class ErrorDispatchFailure : OpenID4VPException {
    public init(message: String, className: String) {
        super.init(
            errorCode: OpenID4VPErrorCodes.errorDispatchFailure,
            message: "Failed to send error to verifier: \(message)",
            className: className
        )
    }
}
