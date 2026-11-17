
@testable import OpenID4VP
import XCTest

final class VPTokenFactoryTests: XCTestCase {
    /// Test credential format - ldp_vc

    func testGetVPTokenBuilder_WithLdpVcFormat() throws {
        let builder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: .ldp_vc)

        XCTAssertTrue(builder is LdpVPTokenBuilder)
    }

    /// Test credential format - mso_mdoc
    func testGetVPTokenBuilder_WithMdocFormat() throws {
        let builder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: FormatType.mso_mdoc)

        XCTAssertTrue(builder is MdocVPTokenBuilder)
    }
    
    /// Test credential format - SD-JWT
    func testGetVPTokenBuilder_WithSdJwtFormat() throws {
        let vcSdJwtBuilder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: FormatType.vc_sd_jwt)
        
        XCTAssertTrue(vcSdJwtBuilder is SdJwtVPTokenBuilder)
        
        let dcSdJwtBuilder = try VPTokenFactory.getVPTokenBuilder(credentialFormat: FormatType.dc_sd_jwt)
        
        XCTAssertTrue(dcSdJwtBuilder is SdJwtVPTokenBuilder)
    }
}
