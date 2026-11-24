
@testable import OpenID4VP
import XCTest

final class VPTokenFactoryTests: XCTestCase {
    let mockAuthorizationRequest = getMockAuthorizationRequest()
    
    func testGetVPTokenBuilder_WithLdpVcFormat() throws {
        let builder = try VPTokenFactory.getVPTokenBuilder(authorizationRequest: mockAuthorizationRequest, credentialFormat: .ldp_vc)
        XCTAssertTrue(builder is LdpVPTokenBuilder)
    }

    func testGetVPTokenBuilder_WithMdocFormat() throws {
        let builder = try VPTokenFactory.getVPTokenBuilder(authorizationRequest: mockAuthorizationRequest, credentialFormat: FormatType.mso_mdoc)
        XCTAssertTrue(builder is MdocVPTokenBuilder)
    }

    func testGetVPTokenBuilder_WithSdJwtFormat() throws {
        let vcSdJwtBuilder = try VPTokenFactory.getVPTokenBuilder(authorizationRequest: mockAuthorizationRequest, credentialFormat: FormatType.vc_sd_jwt)
        XCTAssertTrue(vcSdJwtBuilder is SdJwtVPTokenBuilder)

        let dcSdJwtBuilder = try VPTokenFactory.getVPTokenBuilder(authorizationRequest: mockAuthorizationRequest, credentialFormat: FormatType.dc_sd_jwt)
        XCTAssertTrue(dcSdJwtBuilder is SdJwtVPTokenBuilder)
    }
}
