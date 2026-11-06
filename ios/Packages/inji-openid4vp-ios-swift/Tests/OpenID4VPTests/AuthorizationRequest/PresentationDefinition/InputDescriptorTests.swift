import XCTest
@testable import OpenID4VP

final class InputDescriptorTests: XCTestCase {
    func testNoThrowErrorForValidInputDescriptot() {
        let jsonData = """
        {
          "id": "id card credential",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertNoThrow(try JSONDecoder().decode(InputDescriptor.self, from: jsonData))
    }
    
    func testThrowErrorWhenInputDescriptorIdIsEmpty() {
        let inputDescriptorWithInvalidId = """
        {
          "id": "",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertThrowsError(try JSONDecoder().decode(InputDescriptor.self, from: inputDescriptorWithInvalidId)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: input_descriptor->id value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenInputDescriptorNameIsEmpty() {
        let inputDescriptorWithInvalidName = """
        {
          "id": "id card credenital",
          "name": "",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertThrowsError(try JSONDecoder().decode(InputDescriptor.self, from: inputDescriptorWithInvalidName)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: input_descriptor->name value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenInputDescriptorPurposeIsEmpty() {
        let inputDescriptorWithInvalidPurpose = """
        {
          "id": "id card credenital",
          "name": "ID card details",
          "purpose": "",
          "format": {
            "ldp_vc": {
              "proof_type": [
                "Ed25519Signature2018"
              ]
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertThrowsError(try JSONDecoder().decode(InputDescriptor.self, from: inputDescriptorWithInvalidPurpose)) { error in
            
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: input_descriptor->purpose value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testThrowErrorWhenInputDescriptorFormatHasEntryWithEmptyProofType() {
        let inputDescriptorWithInvalidFormatField = """
        {
          "id": "id card credenital",
          "name": "ID card details",
          "purpose": "We can only allow people with valid ID for registration of event",
          "format": {
            "ldp_vc": {
              "proof_type": []
            }
          },
          "constraints": {
            "fields": [
              {
                "path": [
                  "$.type"
                ],
                "filter": {
                  "type": "string",
                  "pattern": "IDCardCredential"
                }
              }
            ]
          }
        }
        """.data(using: .utf8)!
        
        XCTAssertThrowsError(try JSONDecoder().decode(InputDescriptor.self, from: inputDescriptorWithInvalidFormatField)) { error in
            assertOpenID4VPException(error,
                expectedMessage: "Invalid Input: input_descriptor->format->ldp_vc->proof_type value cannot be empty or null",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
}
