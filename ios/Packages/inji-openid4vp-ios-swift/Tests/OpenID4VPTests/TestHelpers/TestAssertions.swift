@testable import OpenID4VP
import Foundation

import XCTest

func assertJsonString(expected jsonString1: String, actual jsonString2: String, strict: Bool = true, file: StaticString = #file, line: UInt = #line) {
    guard let data1 = jsonString1.data(using: .utf8),
          let data2 = jsonString2.data(using: .utf8) else {
        XCTFail("Invalid JSON string encoding", file: file, line: line)
        return
    }
    
    do {
        let json1 = try JSONSerialization.jsonObject(with: data1, options: [])
        let json2 = try JSONSerialization.jsonObject(with: data2, options: [])
        
        switch json1 {
        case let dict1 as [String: Any]:
            guard let dict2 = json2 as? [String: Any] else {
                XCTFail("First JSON is a dictionary but second JSON is not", file: file, line: line)
                return
            }
            assertDictionariesEqual(expected: dict1, actual: dict2, file: file, line: line, strict: strict)
            
        case let array1 as [Any]:
            guard let array2 = json2 as? [Any] else {
                XCTFail("First JSON is an array but second JSON is not", file: file, line: line)
                return
            }
            assertArraysEqual(expected: array1, actual: array2, file: file, line: line, strict: strict)
            
        default:
            XCTFail("JSON must be either a dictionary or an array", file: file, line: line)
        }
    } catch {
        XCTFail("JSON deserialization failed with error: \(error)", file: file, line: line)
    }
}

func assertArraysEqual(expected: [Any], actual: [Any], file: StaticString = #file, line: UInt = #line, strict: Bool = true) {
    if strict {
        XCTAssertEqual(expected.count, actual.count, "Array sizes are different", file: file, line: line)
    }
    
    let minCount = min(expected.count, actual.count)
    for i in 0..<minCount {
        let expectedItem = expected[i]
        let actualItem = actual[i]
        
        switch (expectedItem, actualItem) {
        case let (expectedDict as [String: Any], actualDict as [String: Any]):
            assertDictionariesEqual(expected: expectedDict, actual: actualDict, file: file, line: line, strict: strict)
            
        case let (expectedArray as [Any], actualArray as [Any]):
            assertArraysEqual(expected: expectedArray, actual: actualArray, file: file, line: line, strict: strict)
            
        default:
            // Use string representation comparison for other types
            let expectedStr = "\(expectedItem)"
            let actualStr = "\(actualItem)"
            XCTAssertEqual(expectedStr, actualStr, "Array elements at index \(i) don't match", file: file, line: line)
        }
    }
}

//Assert two dictionaries
func assertDictionariesEqual(expected: [String: Any], actual: [String: Any]?, file: StaticString = #file, line: UInt = #line, strict: Bool = true) {
    guard let actualDict = actual else {
        XCTFail("Actual is nil", file: file, line: line)
        return
    }
    
    func isEqual(_ lhs: Any?, _ rhs: Any?) -> Bool {
        switch (lhs, rhs) {
        case let (lhs as String, rhs as String): return lhs == rhs
        case let (lhs as Int, rhs as Int): return lhs == rhs
        case let (lhs as Double, rhs as Double): return lhs == rhs
        case let (lhs as Bool, rhs as Bool): return lhs == rhs
        case let (lhs as NSNull, rhs as NSNull):
            return lhs == rhs
        case let (lhs as [String: Any], rhs as [String: Any]): return dictionariesEqual(lhs, rhs, strict: strict)
        case let (lhs as [Any], rhs as [Any]): return arraysEqual(lhs, rhs)
        case let (lhs as any RawRepresentable, rhs as any RawRepresentable):
            return isEqual(lhs.rawValue, rhs.rawValue)
        case let (lhs as Encodable, rhs as Encodable):
            do {
                let encoder = JSONEncoder()
                let jsonData1 = try encoder.encode(lhs)
                let jsonData2 = try encoder.encode(rhs)
                
                let dict1 = try JSONSerialization.jsonObject(with: jsonData1, options: []) as? [String: Any]
                let dict2 = try JSONSerialization.jsonObject(with: jsonData2, options: []) as? [String: Any]
                
                XCTAssertNotNil(dict1, "Failed to convert instance1 to dictionary", file: file, line: line)
                XCTAssertNotNil(dict2, "Failed to convert instance2 to dictionary", file: file, line: line)
                
                assertDictionariesEqual(expected: dict1 ?? [:], actual: dict2, file: file, line: line)
                return true
            } catch {
                print("error - \(error) occurred during conversion")
                return false
            }
        default: return "\(String(describing: lhs))"  == "\(String(describing: rhs))"
        }
    }
    
    func dictionariesEqual(_ lhs: [String: Any], _ rhs: [String: Any], strict: Bool = true) -> Bool {
        if strict == true && lhs.count != rhs.count  { return false }
        
        return lhs.allSatisfy { key, value in
            guard let rhsValue = rhs[key] else { return false }
            return isEqual(value, rhsValue)
        }
    }
    
    func arraysEqual(_ lhs: [Any], _ rhs: [Any]) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return zip(lhs, rhs).allSatisfy { isEqual($0, $1) }
    }
    
    if strict {
        XCTAssertEqual(expected.count, actualDict.count, "Dictionary sizes are different", file: file, line: line)
    }
    
    for (key, expectedValue) in expected {
        
        guard let actualValue = actualDict[key] else {
            XCTFail("Missing key '\(key)' in actual dictionary", file: file, line: line)
            continue
        }
        
        XCTAssertTrue(isEqual(expectedValue, actualValue), "Mismatch for key '\(key)'. Expected: \(expectedValue), but got: \(actualValue)", file: file, line: line)
    }
}

func XCTAssertAsyncThrowsError<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ errorHandler: (_ error: any Error) -> Void = { _ in }
) async {
    do {
        _ = try await expression()
        XCTFail("Expected error to be thrown, but no error was thrown. \(message())", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}

func XCTAssertAsyncNoThrowsError<T>(
    _ expression: @autoclosure () async throws -> T,
    _ message: @autoclosure () -> String = "",
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
    } catch {
        XCTFail("Expected no error to be thrown, but an error was thrown: \(error). \(message())", file: file, line: line)
    }
}

func XCTAssertNoThrowAndVerify<T>(_ expression: @autoclosure () throws -> T,
                                  file: StaticString = #filePath,
                                  line: UInt = #line,
                                  _ assertions: (T) -> Void) {
    do {
        let result = try expression()
        assertions(result)
    } catch {
        XCTFail("Expression threw an error: \(error)", file: file, line: line)
    }
}


func XCTAssertNoThrowAndVerifyAsync<T>(_ expression: @autoclosure () async throws -> T,
                      file: StaticString = #filePath,
                      line: UInt = #line,
                           _ assertions: (T) -> Void) async {
    do {
        let result = try await expression()
        assertions(result)
    } catch {
        print("Expression threw an error: \(error)")
        XCTFail("Expression threw an error: \(error)", file: file, line: line)
    }
}

// Write a custom assertion for comparing two arrays
func assertArraysEqual<T: Equatable>(expected: [T], actual: [T], file: StaticString = #file, line: UInt = #line) {
    XCTAssertEqual(expected.count, actual.count, "Array sizes are different", file: file, line: line)
    
    expected.forEach { expectedElement in
        XCTAssertTrue(actual.contains(expectedElement), "Expected element \(expectedElement) not found in actual array", file: file, line: line)
    }
}

func assertOpenID4VPException(
    _ error: Error,
    expectedMessage: String,
    expectedCode: String,
    expectedVerifierResponse: VerifierResponse? = nil,
    expectedUnderlyingErrorMessage: String? = nil,
    file: StaticString = #file,
    line: UInt = #line
) {
    guard let ovpException = error as? OpenID4VPException else {
        XCTFail("Expected OpenID4VPException but got \(error)", file: file, line: line)
        return
    }
    XCTAssertEqual(expectedMessage, ovpException.message, file: file, line: line)
    XCTAssertEqual(expectedCode, ovpException.errorCode, file: file, line: line)
    if(expectedVerifierResponse != nil) {
        let actualVerifierReponse = ovpException.verifierResponse
        XCTAssertEqual(expectedVerifierResponse?.body(), actualVerifierReponse?.body(), file: file, line: line)
        XCTAssertEqual(expectedVerifierResponse?.headers, actualVerifierReponse?.headers, file: file, line: line)
        XCTAssertEqual(expectedVerifierResponse?.statusCode, actualVerifierReponse?.statusCode, file: file, line: line)
        XCTAssertEqual(expectedVerifierResponse?.redirectUri, actualVerifierReponse?.redirectUri, file: file, line: line)
        XCTAssertEqual(expectedVerifierResponse?.additionalParams, actualVerifierReponse?.additionalParams, file: file, line: line)
    }
    if(expectedUnderlyingErrorMessage != nil) {
        XCTAssertEqual(expectedUnderlyingErrorMessage, ovpException.cause?.localizedDescription, file: file, line: line)
    }
}


func assertPublicKey(expectedBase64Encoded: String, actualKey: PublicKeyType) {
    switch actualKey {
    case .ed25519(let publicKey):
        XCTAssertEqual(expectedBase64Encoded, publicKey.rawRepresentation.base64EncodedString())
        
    case .secKey(let secKey):
        // Extract the raw representation from SecKey
        guard let keyData = extractPublicKeyData(from: secKey) else {
            XCTFail("Failed to extract public key data from SecKey")
            return
        }
        
        let actualBase64 = keyData.base64EncodedString()
        XCTAssertEqual(expectedBase64Encoded, actualBase64)
    }
}

private func extractPublicKeyData(from secKey: SecKey) -> Data? {
    var error: Unmanaged<CFError>?
    
    guard let keyData = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else {
        return nil
    }

    return keyData
}
