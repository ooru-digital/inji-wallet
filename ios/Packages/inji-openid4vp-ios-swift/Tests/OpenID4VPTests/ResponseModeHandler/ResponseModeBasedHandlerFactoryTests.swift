import XCTest
@testable import OpenID4VP

final class ResponseModeBasedHandlerFactoryTests: XCTestCase {
    func testThrowErrorWhenResponseModeIsNotSupportedOnGettingResponseModeHandler() throws {
        XCTAssertThrowsError(try ResponseModeBasedHandlerFactory.get(responseMode: "fragment")) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Given response_mode - fragment is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testReturnOfResponseResponseHandlerWhenFactoryGetIsInvoked() throws {
        let responseModeHandler1: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "direct_post")
        let responseModeHandler2: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "direct_post.jwt")
        let responseModeHandler3: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "iar-post")
        let responseModeHandler4: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "iar-post.jwt")
        let responseModeHandler5: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "iae_post")
        let responseModeHandler6: any ResponseModeBasedHandler = try ResponseModeBasedHandlerFactory.get(responseMode: "iae_post.jwt")
        
        XCTAssertTrue(responseModeHandler1 is DirectPostResponseModeHandler)
        XCTAssertTrue(responseModeHandler2 is DirectPostJwtResponseModeHandler)
        XCTAssertTrue(responseModeHandler3 is DirectPostResponseModeHandler)
        XCTAssertTrue(responseModeHandler4 is DirectPostJwtResponseModeHandler)
        XCTAssertTrue(responseModeHandler5 is DirectPostResponseModeHandler)
        XCTAssertTrue(responseModeHandler6 is DirectPostJwtResponseModeHandler)
    }
    
    func testShouldThrowErrorForEmptyResponseMode() {
        XCTAssertThrowsError(
            try ResponseModeBasedHandlerFactory.get(responseMode: "")
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Given response_mode -  is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testShouldThrowErrorForNilResponseMode() {
        XCTAssertThrowsError(
            try ResponseModeBasedHandlerFactory.get(responseMode: nil)
        ) { error in
            assertOpenID4VPException(
                error,
                expectedMessage: "Given response_mode - nil is not supported",
                expectedCode: OpenID4VPErrorCodes.invalidRequest
            )
        }
    }
    
    func testGet_ShouldThrowErrorForSimilarIncorrectModes() {
        let invalidModes = [
            "direct-post",
            "directpost",
            "direct_post_jwt",
            "direct_post_json",
            "post_direct",
            "direct_get",
            "indirect_post"
        ]

        for mode in invalidModes {
            XCTAssertThrowsError(
                try ResponseModeBasedHandlerFactory.get(responseMode: mode)
            ) { error in
                assertOpenID4VPException(
                    error,
                    expectedMessage: "Given response_mode - \(mode) is not supported",
                    expectedCode: OpenID4VPErrorCodes.invalidRequest
                )
            }
        }
    }
}
