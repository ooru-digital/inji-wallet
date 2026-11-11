import XCTest
@testable import OpenID4VP

final class UnsignedSdJwtVPTokenBuilderTests: XCTestCase {
    func testBuildReturnsExpectedStructure() async throws {
        let builder = UnsignedSdJwtVPTokenBuilder(
            clientId: "client",
            authorizationRequestNonce: "nonce",
            networkManager: MockNetworkManager()
        )
        var credentialInputDescriptorMappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(sampeVcSdJwtWithHolderBinding), inputDescriptorId: "input1")
        ]
        
        let (payload, unsignedSdJwtVPToken) = try await builder.build(
            credentialInputDescriptorMappings: &credentialInputDescriptorMappings
        )
        
        let unsignedVPToken = unsignedSdJwtVPToken as? UnsignedSdJwtVPToken
        XCTAssertNotNil(unsignedVPToken)
        XCTAssertTrue(((unsignedVPToken?.uuidToUnsignedKBT.values.first?.starts(with: "eyJ")) != nil)) // Check if it looks like a JWT
        XCTAssertNotNil(credentialInputDescriptorMappings.first?.identifier) // identifier should be set to UUID
        XCTAssertEqual(credentialInputDescriptorMappings.first?.identifier, unsignedVPToken?.uuidToUnsignedKBT.keys.first) // identifier should match the key in unsigned vp token
        
        XCTAssertNil(payload)
    }
    
    func testPerformHashWithoutSdAlgAvailableInSdJwtClaimWithInputDescriptor() async throws {
        let credentialWithNoSdAlg = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk4VWw4ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBTQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il19.ewogICJpc3N1YW5jZV9kYXRlIjogIjIwMjUtMDgtMTgiLAogICJleHBpcnlfZGF0ZSI6ICIyMDI2LTA4LTI4IiwKICAiaXNzdWluZ19jb3VudHJ5IjogIkRFIiwKICAibmJmIjogMTc1NTQ3NTIwMCwKICAiZXhwIjogMTc4Nzg3NTIwMCwKICAidmN0IjogImh0dHBzOi8vZXhhbXBsZS5ldWRpLmVjLmV1cm9wYS5ldS9jb3IvMSIsCiAgImNuZiI6IHsKICAgICJraWQiOiJkaWQ6andrOmV5SnJkSGtpT2lKRlF5SXNJbU55ZGlJNklsQXRNalUySWl3aWVDSTZJaTFwYTJsT2VtUnhWMUJETVdsWVNXOUtOREp2VjBNNGNVMTZWSGR2V2pBNGVqWTVSalZaWldOYU9Xc2lMQ0o1SWpvaVVVbFFjR1JQUkV4NFgxaHhkVmhMYVVaaFYzb3lXVzg0TW1SV2VsVXpOV3BGU2pSTmMyTlZSMFo1T0NJc0luVnpaU0k2SW5OcFp5SjkjMCJ9LCJpc3MiOiJodHRwczovL2Z1bmtlLmFuaW1vLmlkIiwiaWF0IjoxNzU2ODk2NjUzLCJfc2QiOlsiQzJQX3FvcTBQdlRvMVlZcnYzXzVGV2k0aUVhWlVHS1lhQ2t6YWtnTUlIYyIsIkY0WmRCUEl4MHJRYmhuaWRuU3AxSEw3LVRSX09DRnFoV0lWSlo3bUIzRlUiLCJVdHYtdEdoSWdvS0lLTlRiOWd0YnI3Ylk5RW1RQU1LTnd0WGpjTXNRcExNIiwiZ3dfRmotNExRRkpDZ3JkVUpwRUJtbTRuemEzMVhSdGFnNVNoX0VQOER6VSIsImthdDRVQW1LOXhuTkd6NS14RXZDVHVmZW5BRzlSdUVveHlrckstbE5LZWciLCJvRUJMS1c0UUQ5Z2NKbkhCRi1YR2VrbEEzeDhMMTV1bEN3NVVxcGV5aElzIiwicXRpVUp6bFNMOU0ybjd5eGdoa0lOSnhVSnQ2S2ZaZFBjRGtxaHRWcTR6USIsInk0THlyMno2QUlkSGhwOGV0NVZxOXJoU2I2NXNHaU1YMDZFVloxLV9pNlEiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.F0gYaWKFzPXoI4pO4mixg6WgN1gM3hfqiJLIgxEAjfQb5yrQEU3G2CCYwJtg7d9bcs9-4lu4ZVS6aWpUJ70UNw~WyI1Njg2Njc5MzY5MTc4MDgxMDA5Nzc0MTQiLCJmYW1pbHlfbmFtZSIsIk11c3Rlcm1hbm4iXQ~WyIxMTc2MjI4NDI0Mzk4MTY4Mzc4NTQ1NTg0IiwiZ2l2ZW5fbmFtZSIsIkVyaWthIl0~WyI1MTI2Mzc4NDkyMDcxOTExMjczMTQwNjAiLCJiaXJ0aF9kYXRlIiwiMTk2NC0wOC0xMiJd~WyIxMTI0MjE5NzQ2NzM0MDA1ODYzMjU3NTAiLCJyZXNpZGVudF9hZGRyZXNzIiwiSGVpZGVzdHJhc3NlIDE3LCA1MTE0NyBLb2xuIl0~WyI1MzcxMzg4MzMyNjMxMDc3MjY5MjQ4NDkiLCJnZW5kZXIiLDJd~WyI5MjcxODEyMjgxOTIyMDY1MDcxOTQyMTMiLCJiaXJ0aF9wbGFjZSIsIkvDtmxuIl0~WyI1MTE2NDk3MzQxMDM5NTU1MTIwMzc0MDQiLCJhcnJpdmFsX2RhdGUiLCIyMDI0LTAzLTAxIl0~WyI5MTQ0NDg4OTMwNzAwNzQ5Mjc3NjMwODkiLCJuYXRpb25hbGl0eSIsIkRFIl0~"
        
        let builder = UnsignedSdJwtVPTokenBuilder(
            clientId: "client",
            authorizationRequestNonce: "nonce",
            networkManager: MockNetworkManager()
        )
        var credentialInputDescriptorMappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(credentialWithNoSdAlg), inputDescriptorId: "input1")
        ]
        let (payload, unsignedSdJwtVPToken) = try await builder.build(
            credentialInputDescriptorMappings: &credentialInputDescriptorMappings
        )
        let unsignedVPToken = unsignedSdJwtVPToken as? UnsignedSdJwtVPToken
        XCTAssertNotNil(unsignedVPToken)
        XCTAssertTrue(((unsignedVPToken?.uuidToUnsignedKBT.values.first?.starts(with: "eyJ")) != nil)) // Check if it looks like a JWT
        XCTAssertNil(payload)
    }
    
    func testBuilderReturnNoEntryInUnsignedVPTokenForHolderNotBindedCredential() async throws {
        let builder = UnsignedSdJwtVPTokenBuilder(
            clientId: "client",
            authorizationRequestNonce: "nonce",
            networkManager: MockNetworkManager()
        )
        
        var credentialInputDescriptorMappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(sampleVcSdJwtWithNoHolderBinding), inputDescriptorId: "input1")
        ]
        
        let (payload, unsignedSdJwtVPToken) = try await builder.build(
            credentialInputDescriptorMappings: &credentialInputDescriptorMappings
        )
        
        XCTAssertNil(payload)
        let unsignedVPToken = unsignedSdJwtVPToken as? UnsignedSdJwtVPToken
        XCTAssertNotNil(unsignedVPToken)
        XCTAssertTrue(((unsignedVPToken?.uuidToUnsignedKBT.isEmpty)) != nil) // Check if no entry available in unsigned vp token for not holder binded credential
    }
    
    func testBuildThrowsWhenKidMissingOrInvalid() async {
        let sdJwtWithInvalidKid = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCNVRDQ0FZdWdBd0lCQWdJUUdVZEYwa0JpUUdEYXdwKzBkQlNTNWpBS0JnZ3Foa2pPUFFRREFqQWRNUTR3REFZRFZRUURFd1ZCYm1sdGJ6RUxNQWtHQTFVRUJoTUNUa3d3SGhjTk1qVXdOREV5TVRReU16TXdXaGNOTWpZd05UQXlNVFF5TXpNd1dqQWhNUkl3RUFZRFZRUURFd2xqY21Wa2J5QmtZM014Q3pBSkJnTlZCQVlUQWs1TU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZYVk5BMGxhYSs1UDJuazVQSkZvdjh4aEJGTno1VU9KQklWc3lrMFNLU2ZxVGZLTUI2UitjRkROaWpkbUJZeXVFYVVnTWd1VWM4aE9Wbm5yZVc5dGhLT0JxRENCcFRBZEJnTlZIUTRFRmdRVVlSOHZGUVRsa2pmMS9ObktlWnh2WTBaejNhQXdEZ1lEVlIwUEFRSC9CQVFEQWdlQU1CVUdBMVVkSlFFQi93UUxNQWtHQnlpQmpGMEZBUUl3SHdZRFZSMGpCQmd3Rm9BVUw5OHdhTll2OVFueElIYjVDRmd4anZaVXRVc3dJUVlEVlIwU0JCb3dHSVlXYUhSMGNITTZMeTltZFc1clpTNWhibWx0Ynk1cFpEQVpCZ05WSFJFRUVqQVFnZzVtZFc1clpTNWhibWx0Ynk1cFpEQUtCZ2dxaGtqT1BRUURBZ05JQURCRkFpQkJ3ZFMvY0ZCczNhd3RmUDlHRlZrZ1NPSVRRZFBCTUxoc0pCeWpnN2wyTFFJaEFQUUpXeTdxUXNmcTJHcmRwY0dYSHJEVkswdy9YblBGMlhBVDZyVFg4dUNQIiwiTUlJQnp6Q0NBWFdnQXdJQkFnSVFWd0FGb2xXUWltOTRnbXlDaWMzYkNUQUtCZ2dxaGtqT1BRUURBakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d0hoY05NalF3TlRBeU1UUXlNek13V2hjTk1qZ3dOVEF5TVRReU16TXdXakFkTVE0d0RBWURWUVFERXdWQmJtbHRiekVMTUFrR0ExVUVCaE1DVGt3d1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRQy9ZeUJwY1JRWDhaWHBIZnJhMVROZFNiUzdxemdIWUhKM21zYklyOFRKTFBOWkk4VWw4ekpsRmRRVklWbHM1KzVDbENiTitKOUZVdmhQR3M0QXpBK280R1dNSUdUTUIwR0ExVWREZ1FXQkJRdjN6Qm8xaS8xQ2ZFZ2R2a0lXREdPOWxTMVN6QU9CZ05WSFE4QkFmOEVCQU1DQVFZd0lRWURWUjBTQkJvd0dJWVdhSFIwY0hNNkx5OW1kVzVyWlM1aGJtbHRieTVwWkRBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQU1Dc0dBMVVkSHdRa01DSXdJS0Flb0J5R0dtaDBkSEJ6T2k4dlpuVnVhMlV1WVc1cGJXOHVhV1F2WTNKc01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ1RnODBBbXFWSEpMYVp0MnV1aEF0UHFLSVhhZlAyZ2h0ZDlPQ21kRDUxWndJZ0t2VmtyZ1RZbHhTUkFibUtZNk1sa0g4bU0zU05jbkVKazlmR1Z3SkcrKzA9Il19.ewogICJpc3N1YW5jZV9kYXRlIjogIjIwMjUtMDgtMTgiLAogICJleHBpcnlfZGF0ZSI6ICIyMDI2LTA4LTI4IiwKICAiaXNzdWluZ19jb3VudHJ5IjogIkRFIiwKICAibmJmIjogMTc1NTQ3NTIwMCwKICAiZXhwIjogMTc4Nzg3NTIwMCwKICAidmN0IjogImh0dHBzOi8vZXhhbXBsZS5ldWRpLmVjLmV1cm9wYS5ldS9jb3IvMSIsCiAgImNuZiI6IHsKICAgICJqd2siOiB7CiAgICAgICAgICJrdHkiOiAiRUMiLAogICAgICAgICAiY3J2IjogIlAtMjU2IiwKICAgICAgICAgIngiOiAiVENBRVIxOVp2dTNPSEY0ajRXNHZmU1ZvSElQMUlMaWxEbHM3dkNlR2VtYyIsCiAgICAgICAgICJ5IjogIlp4amlXV2JaTVFHSFZXS1ZRNGhiU0lpcnNWZnVlY0NFNnQ0alQ5RjJIWlEiCiAgICAgICB9CiAgfSwKICAiaXNzIjogImh0dHBzOi8vZnVua2UuYW5pbW8uaWQiLAogICJpYXQiOiAxNzU2ODk2NjUzLAogICJfc2QiOiBbCiAgICAiQzJQX3FvcTBQdlRvMVlZcnYzXzVGV2k0aUVhWlVHS1lhQ2t6YWtnTUlIYyIsCiAgICAiRjRaZEJQSXgwclFiaG5pZG5TcDFITDctVFJfT0NGcWhXSVZKWjdtQjNGVSIsCiAgICAiVXR2LXRHaElnb0tJS05UYjlndGJyN2JZOUVtUUFNS053dFhqY01zUXBMTSIsCiAgICAiZ3dfRmotNExRRkpDZ3JkVUpwRUJtbTRuemEzMVhSdGFnNVNoX0VQOER6VSIsCiAgICAia2F0NFVBbUs5eG5OR3o1LXhFdkNUdWZlbkFHOVJ1RW94eWtySy1sTktlZyIsCiAgICAib0VCTEtXNFFEOWdjSm5IQkYtWEdla2xBM3g4TDE1dWxDdzVVcXBleWhJcyIsCiAgICAicXRpVUp6bFNMOU0ybjd5eGdoa0lOSnhVSnQ2S2ZaZFBjRGtxaHRWcTR6USIsCiAgICAieTRMeXIyejZBSWRIaHA4ZXQ1VnE5cmhTYjY1c0dpTVgwNkVWWjEtX2k2USIKICBdLAogICJfc2RfYWxnIjogInNoYS0yNTYiCn0.F0gYaWKFzPXoI4pO4mixg6WgN1gM3hfqiJLIgxEAjfQb5yrQEU3G2CCYwJtg7d9bcs9-4lu4ZVS6aWpUJ70UNw~WyI1Njg2Njc5MzY5MTc4MDgxMDA5Nzc0MTQiLCJmYW1pbHlfbmFtZSIsIk11c3Rlcm1hbm4iXQ~WyIxMTc2MjI4NDI0Mzk4MTY4Mzc4NTQ1NTg0IiwiZ2l2ZW5fbmFtZSIsIkVyaWthIl0~WyI1MTI2Mzc4NDkyMDcxOTExMjczMTQwNjAiLCJiaXJ0aF9kYXRlIiwiMTk2NC0wOC0xMiJd~WyIxMTI0MjE5NzQ2NzM0MDA1ODYzMjU3NTAiLCJyZXNpZGVudF9hZGRyZXNzIiwiSGVpZGVzdHJhc3NlIDE3LCA1MTE0NyBLb2xuIl0~WyI1MzcxMzg4MzMyNjMxMDc3MjY5MjQ4NDkiLCJnZW5kZXIiLDJd~WyI5MjcxODEyMjgxOTIyMDY1MDcxOTQyMTMiLCJiaXJ0aF9wbGFjZSIsIkvDtmxuIl0~WyI1MTE2NDk3MzQxMDM5NTU1MTIwMzc0MDQiLCJhcnJpdmFsX2RhdGUiLCIyMDI0LTAzLTAxIl0~WyI5MTQ0NDg4OTMwNzAwNzQ5Mjc3NjMwODkiLCJuYXRpb25hbGl0eSIsIkRFIl0~"
        var credentialInputDescriptorMappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(sdJwtWithInvalidKid), inputDescriptorId: "input1")
        ]
        let builder = UnsignedSdJwtVPTokenBuilder(
            clientId: "client",
            authorizationRequestNonce: "nonce",
            networkManager: MockNetworkManager()
        )
        
        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &credentialInputDescriptorMappings)) { error in
            assertOpenID4VPException(error, expectedMessage: "Unsupported cnf format, only 'kid' is supported", expectedCode: "unsupported_operation")
        }
    }
    
    func testBuildThrowsWhenSdJwtIsInvalid() async {
        let invalidSdJwt = 12345  // Not a String
        var credentialInputDescriptorMappings = [
            CredentialInputDescriptorMapping(format: .vc_sd_jwt, credential: AnyCodable(invalidSdJwt), inputDescriptorId: "input1")
        ]
        let builder = UnsignedSdJwtVPTokenBuilder(
            clientId: "client",
            authorizationRequestNonce: "nonce",
            networkManager: MockNetworkManager()
        )
        
        await XCTAssertAsyncThrowsError(try await builder.build(credentialInputDescriptorMappings: &credentialInputDescriptorMappings)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }
}
