import XCTest
@testable import OpenID4VP

final class VPTokenSigningResultTests: XCTestCase {


    func testInitStoresSignedData() {
        let result = VPTokenSigningResult(id: "uuid1", signedData: Data("signed-payload".utf8))
        XCTAssertEqual(result.id, "uuid1")
        XCTAssertEqual(result.signedData, Data("signed-payload".utf8))
    }

    func testDecodesFromJSON() throws {
        let json = #"{"signedData":Data("signed-payload".utf8)}"#.data(using: .utf8)!
       
        
        XCTAssertThrowsError(try JSONDecoder().decode(VPTokenSigningResult.self, from: json)) { error in
            XCTAssertEqual("The data couldn’t be read because it isn’t in the correct format.", error.localizedDescription)
        }
    }

    func testEncodeDecode() throws {
        let original = VPTokenSigningResult(id: "uuid1", signedData: Data("round-trip-data".utf8))
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(VPTokenSigningResult.self, from: data)
        XCTAssertEqual(decoded.id, original.id)
        XCTAssertEqual(decoded.signedData, original.signedData)
    }

    func testAcceptsEmptySignedData() {
        let result = VPTokenSigningResult(id: "uuid1", signedData: Data("".utf8))
        XCTAssertEqual(result.signedData, Data("".utf8))
    }
}
