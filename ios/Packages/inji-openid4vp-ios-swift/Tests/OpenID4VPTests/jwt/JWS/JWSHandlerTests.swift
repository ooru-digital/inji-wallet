import XCTest
@testable import OpenID4VP
import CryptoKit
import JSONWebSignature

final class JWSHandlerTests: XCTestCase {
    let mockNetworkManager = MockNetworkManager()
        
    func testJWSVerificationWithPublicKeyInDidJwk() async throws {
        let jws = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6andrOmV5SnJkSGtpT2lBaVQwdFFJaXdnSW1OeWRpSTZJQ0pGWkRJMU5URTVJaXdnSW5naU9pQWlhVTV4T0ZsTlZscFlZVFJSVHpOd2R6RmtYekJUVEVONVNFaHpSREppTTFGWFgyMXBNVFZKVFRWV1RTSXNJQ0poYkdjaU9pQWlSV1JFVTBFaUxDQWlhMlY1WDI5d2N5STZJRnNpZG1WeWFXWjVJbDBzSUNKMWMyVWlPaUFpYzJsbkluMCJ9.eyJjbGllbnRfaWQiOiJkaWQ6andrOmV5SnJkSGtpT2lBaVQwdFFJaXdnSW1OeWRpSTZJQ0pGWkRJMU5URTVJaXdnSW5naU9pQWlhVTV4T0ZsTlZscFlZVFJSVHpOd2R6RmtYekJUVEVONVNFaHpSREppTTFGWFgyMXBNVFZKVFRWV1RTSXNJQ0poYkdjaU9pQWlSV1JFVTBFaUxDQWlhMlY1WDI5d2N5STZJRnNpZG1WeWFXWjVJbDBzSUNKMWMyVWlPaUFpYzJsbkluMCIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSI6Imh0dHBzOi8vM2E3YTc1NDZiYTI0Lm5ncm9rLWZyZWUuYXBwL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoidTc0aFM1cVZINjh0Ums0Z3ZxMGJGdz09Iiwic3RhdGUiOiJXNUIvWmxBOE5ySjNTQVE2REI5SUd3PT0iLCJyZXNwb25zZV91cmkiOiJodHRwczovLzNhN2E3NTQ2YmEyNC5uZ3Jvay1mcmVlLmFwcC92ZXJpZmllci92cC1yZXNwb25zZSIsImNsaWVudF9tZXRhZGF0YSI6IntcImNsaWVudF9uYW1lXCI6XCJSZXF1ZXN0ZXIgbmFtZVwiLFwibG9nb191cmlcIjpcIjxsb2dvX3VyaT5cIixcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJqd2tzXCI6e1wia2V5c1wiOlt7XCJrdHlcIjpcIk9LUFwiLFwiY3J2XCI6XCJYMjU1MTlcIixcInVzZVwiOlwiZW5jXCIsXCJ4XCI6XCJCVk5WZHFvcnB4Q0NuVE9ra3c4UzJOQVlYdmZFdmtDLThSRE9iaHJBVUE0XCIsXCJhbGdcIjpcIkVDREgtRVNcIixcImtpZFwiOlwidmVyaWZpZXIta2V5LWlkXCJ9XX0sXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiXX0sXCJsZHBfdnBcIjp7XCJwcm9vZl90eXBlXCI6W1wiRWQyNTUxOVNpZ25hdHVyZTIwMThcIixcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCIsXCJSc2FTaWduYXR1cmUyMDE4XCJdfX19In0.7XIo2x9Bk-DfVyliFo-J5RK3eHC1FKMHzVIvl9vE397qadBAVVTIhWNaoe4evYmcUkjC1HlpEIO1rPP1Xvt4Aw"
        let publicKey = PublicKeyType.ed25519(try Curve25519.Signing.PublicKey(rawRepresentation: [136, 218, 188, 96, 197, 89, 93, 174, 16, 59, 122, 112, 213, 223, 244, 72, 176, 178, 28, 123, 3, 217, 189, 208, 91, 249, 162, 215, 146, 12, 229, 83]))
        
        await XCTAssertAsyncNoThrowsError(try await JWSHandler.verify(jws: jws, publicKey: (publicKey)))
    }
    
    func testJWSVerificationWithPublicKeyInDidKey() async throws {
        let jws = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6a2V5Ono2TWtvZlV3ZzZCQjNmUTNqaEJteURuM1BhOU02ZkN5aG03NVMxdGM0aHpXZzFyciJ9.eyJjbGllbnRfaWQiOiJkaWQ6a2V5Ono2TWtvZlV3ZzZCQjNmUTNqaEJteURuM1BhOU02ZkN5aG03NVMxdGM0aHpXZzFyciIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSI6Imh0dHBzOi8vM2E3YTc1NDZiYTI0Lm5ncm9rLWZyZWUuYXBwL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiZzZEZGdscXJxT2tNbU9NT0hmeHBMdz09Iiwic3RhdGUiOiJuWHVkTDFBMXlEMjRyMjNkQngxdFRnPT0iLCJyZXNwb25zZV91cmkiOiJodHRwczovLzNhN2E3NTQ2YmEyNC5uZ3Jvay1mcmVlLmFwcC92ZXJpZmllci92cC1yZXNwb25zZSIsImNsaWVudF9tZXRhZGF0YSI6IntcImNsaWVudF9uYW1lXCI6XCJSZXF1ZXN0ZXIgbmFtZVwiLFwibG9nb191cmlcIjpcIjxsb2dvX3VyaT5cIixcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJqd2tzXCI6e1wia2V5c1wiOlt7XCJrdHlcIjpcIk9LUFwiLFwiY3J2XCI6XCJYMjU1MTlcIixcInVzZVwiOlwiZW5jXCIsXCJ4XCI6XCJCVk5WZHFvcnB4Q0NuVE9ra3c4UzJOQVlYdmZFdmtDLThSRE9iaHJBVUE0XCIsXCJhbGdcIjpcIkVDREgtRVNcIixcImtpZFwiOlwidmVyaWZpZXIta2V5LWlkXCJ9XX0sXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiXX0sXCJsZHBfdnBcIjp7XCJwcm9vZl90eXBlXCI6W1wiRWQyNTUxOVNpZ25hdHVyZTIwMThcIixcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCIsXCJSc2FTaWduYXR1cmUyMDE4XCJdfX19In0.eHtFcTR3qy97yAMXqTe6MRVe53WsyKByjHgKVqDsqONgXBMWyH_6uXpD1xIWWu7kgT-p73LB_P2yPRDWnXfzDQ"
        let publicKey = PublicKeyType.ed25519(try Curve25519.Signing.PublicKey(rawRepresentation: [136, 218, 188, 96, 197, 89, 93, 174, 16, 59, 122, 112, 213, 223, 244, 72, 176, 178, 28, 123, 3, 217, 189, 208, 91, 249, 162, 215, 146, 12, 229, 83]))
        
        await XCTAssertAsyncNoThrowsError(try await JWSHandler.verify(jws: jws, publicKey: (publicKey)))
    }
    
    func testJWSVerificationWithPublicKeyInDidWeb() async throws {
        let didResponse = """
        {
          "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1"
          ],
          "id": "did:web:KiruthikaJeyashankar.github.io:did",
          "verificationMethod": [
            {
              "id": "did:web:KiruthikaJeyashankar.github.io:did#key-1",
              "type": "Ed25519VerificationKey2020",
              "controller": "did:web:KiruthikaJeyashankar.github.io:did",
              "publicKeyHex": "88dabc60c5595dae103b7a70d5dff448b0b21c7b03d9bdd05bf9a2d7920ce553"
            }
          ],
          "assertionMethod": [
            "did:web:KiruthikaJeyashankar.github.io:did#key-1"
          ]
        }
"""
        mockNetworkManager.setMockResponse(
            for: "https://KiruthikaJeyashankar.github.io/did/did.json",
            responseBody: didResponse
        )
        let jws = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6d2ViOktpcnV0aGlrYUpleWFzaGFua2FyLmdpdGh1Yi5pbzpkaWQja2V5LTEifQ.eyJjbGllbnRfaWQiOiJkaWQ6d2ViOktpcnV0aGlrYUpleWFzaGFua2FyLmdpdGh1Yi5pbzpkaWQiLCJwcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiOiJodHRwczovLzNhN2E3NTQ2YmEyNC5uZ3Jvay1mcmVlLmFwcC92ZXJpZmllci9wcmVzZW50YXRpb25fZGVmaW5pdGlvbl91cmkiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJub25jZSI6IkIrTklPcEZxLzcwTU5NM3FoYk1hbGc9PSIsInN0YXRlIjoid0lZbmxDSFpXZCtYZUJaS2NmQ3FTQT09IiwicmVzcG9uc2VfdXJpIjoiaHR0cHM6Ly8zYTdhNzU0NmJhMjQubmdyb2stZnJlZS5hcHAvdmVyaWZpZXIvdnAtcmVzcG9uc2UiLCJjbGllbnRfbWV0YWRhdGEiOiJ7XCJjbGllbnRfbmFtZVwiOlwiUmVxdWVzdGVyIG5hbWVcIixcImxvZ29fdXJpXCI6XCI8bG9nb191cmk-XCIsXCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9hbGdcIjpcIkVDREgtRVNcIixcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2VuY1wiOlwiQTI1NkdDTVwiLFwiandrc1wiOntcImtleXNcIjpbe1wia3R5XCI6XCJPS1BcIixcImNydlwiOlwiWDI1NTE5XCIsXCJ1c2VcIjpcImVuY1wiLFwieFwiOlwiQlZOVmRxb3JweENDblRPa2t3OFMyTkFZWHZmRXZrQy04UkRPYmhyQVVBNFwiLFwiYWxnXCI6XCJFQ0RILUVTXCIsXCJraWRcIjpcInZlcmlmaWVyLWtleS1pZFwifV19LFwidnBfZm9ybWF0c1wiOntcIm1zb19tZG9jXCI6e1wiYWxnXCI6W1wiRVMyNTZcIl19LFwibGRwX3ZwXCI6e1wicHJvb2ZfdHlwZVwiOltcIkVkMjU1MTlTaWduYXR1cmUyMDE4XCIsXCJFZDI1NTE5U2lnbmF0dXJlMjAyMFwiLFwiUnNhU2lnbmF0dXJlMjAxOFwiXX19fSJ9.Q4YGLycMfJAw_p8uttAnUGBMCXMiV4z5WMy2isWIVXSvNeB83vgFhPaaiWyTiBYRAPT4Tn8JFhiHKEcSNbkVCg"
        let publicKey = PublicKeyType.ed25519(try Curve25519.Signing.PublicKey(rawRepresentation: [136, 218, 188, 96, 197, 89, 93, 174, 16, 59, 122, 112, 213, 223, 244, 72, 176, 178, 28, 123, 3, 217, 189, 208, 91, 249, 162, 215, 146, 12, 229, 83]))
        
//        await XCTAssertAsyncNoThrowsError(try await JWSHandler.verify(jws: jws, publicKeyResolver: keyResolver, verificationMethodUri: didWeb))
        await XCTAssertAsyncNoThrowsError(try await JWSHandler.verify(jws: jws, publicKey: (publicKey)))
    }
    
    func testInvalidSignature() async throws {
        let jws = "eyJ0eXAiOiJvYXV0aC1hdXRoei1yZXErand0IiwiYWxnIjoiRWREU0EiLCJraWQiOiJkaWQ6andrOmV5SnJkSGtpT2lBaVQwdFFJaXdnSW1OeWRpSTZJQ0pGWkRJMU5URTVJaXdnSW5naU9pQWlhVTV4T0ZsTlZscFlZVFJSVHpOd2R6RmtYekJUVEVONVNFaHpSREppTTFGWFgyMXBNVFZKVFRWV1RTSXNJQ0poYkdjaU9pQWlSV1JFVTBFaUxDQWlhMlY1WDI5d2N5STZJRnNpZG1WeWFXWjVJbDBzSUNKMWMyVWlPaUFpYzJsbkluMCJ9.eyJjbGllbnRfaWQiOiJkaWQ6andrOmV5SnJkSGtpT2lBaVQwdFFJaXdnSW1OeWRpSTZJQ0pGWkRJMU5URTVJaXdnSW5naU9pQWlhVTV4T0ZsTlZscFlZVFJSVHpOd2R6RmtYekJUVEVONVNFaHpSREppTTFGWFgyMXBNVFZKVFRWV1RTSXNJQ0poYkdjaU9pQWlSV1JFVTBFaUxDQWlhMlY1WDI5d2N5STZJRnNpZG1WeWFXWjVJbDBzSUNKMWMyVWlPaUFpYzJsbkluMCIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSI6Imh0dHBzOi8vM2E3YTc1NDZiYTI0Lm5ncm9rLWZyZWUuYXBwL3ZlcmlmaWVyL3ByZXNlbnRhdGlvbl9kZWZpbml0aW9uX3VyaSIsInJlc3BvbnNlX3R5cGUiOiJ2cF90b2tlbiIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiYnZrVE5uQmZ3MGZ1QlorSkJMZmdMdz09Iiwic3RhdGUiOiI2K2x6bmZQREdtSzN0K0d5QXNUYkxnPT0iLCJyZXNwb25zZV91cmkiOiJodHRwczovLzNhN2E3NTQ2YmEyNC5uZ3Jvay1mcmVlLmFwcC92ZXJpZmllci92cC1yZXNwb25zZSIsImNsaWVudF9tZXRhZGF0YSI6IntcImNsaWVudF9uYW1lXCI6XCJSZXF1ZXN0ZXIgbmFtZVwiLFwibG9nb191cmlcIjpcIjxsb2dvX3VyaT5cIixcImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZ1wiOlwiRUNESC1FU1wiLFwiYXV0aG9yaXphdGlvbl9lbmNyeXB0ZWRfcmVzcG9uc2VfZW5jXCI6XCJBMjU2R0NNXCIsXCJqd2tzXCI6e1wia2V5c1wiOlt7XCJrdHlcIjpcIk9LUFwiLFwiY3J2XCI6XCJYMjU1MTlcIixcInVzZVwiOlwiZW5jXCIsXCJ4XCI6XCJCVk5WZHFvcnB4Q0NuVE9ra3c4UzJOQVlYdmZFdmtDLThSRE9iaHJBVUE0XCIsXCJhbGdcIjpcIkVDREgtRVNcIixcImtpZFwiOlwidmVyaWZpZXIta2V5LWlkXCJ9XX0sXCJ2cF9mb3JtYXRzXCI6e1wibXNvX21kb2NcIjp7XCJhbGdcIjpbXCJFUzI1NlwiXX0sXCJsZHBfdnBcIjp7XCJwcm9vZl90eXBlXCI6W1wiRWQyNTUxOVNpZ25hdHVyZTIwMThcIixcIkVkMjU1MTlTaWduYXR1cmUyMDIwXCIsXCJSc2FTaWduYXR1cmUyMDE4XCJdfX19In0.uRVQYsPL7qcJ2NIPUbvcD2ZLHwEJj9nJlPDI7yV6vc_Pcq3x4olmwmhJW4jI5gAr9o6NouIBit2QgjTwIUcYDw"
        let publicKey = PublicKeyType.ed25519(try Curve25519.Signing.PublicKey(rawRepresentation: [136, 218, 188, 96, 197, 89, 93, 174, 16, 59, 122, 112, 213, 223, 244, 72, 176, 178, 28, 123, 3, 217, 189, 208, 91, 249, 162, 215, 146, 12, 229, 83]))
        
        await XCTAssertAsyncThrowsError(try await JWSHandler.verify(jws: jws, publicKey: (publicKey))) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "JWS proof verification failed",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
