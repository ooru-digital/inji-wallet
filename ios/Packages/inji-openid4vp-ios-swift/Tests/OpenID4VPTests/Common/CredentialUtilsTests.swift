import XCTest
import SwiftCBOR
@testable import OpenID4VP

final class CredentialUtilsTests: XCTestCase {

    private let classNameValue = "CredentialUtilsTests"

    private let sdHashes = [
        "C2P_qoq0PvTo1YYrv3_5FWi4iEaZUGKYaCkzakgMIHc",
        "F4ZdBPIx0rQbhnidnSp1HL7-TR_OCFqhWIVJZ7mB3FU",
        "Utv-tGhIgoKIKNTb9gtbr7bY9EmQAMKNwtXjcMsQpLM",
        "gw_Fj-4LQFJCgrdUJpEBmm4nza31XRtag5Sh_EP8DzU",
        "kat4UAmK9xnNGz5-xEvCTufenAG9RuEoxykrK-lNKeg",
        "oEBLKW4QD9gcJnHBF-XGeklA3x8L15ulCw5UqpeyhIs",
        "qtiUJzlSL9M2n7yxghkINJxUJt6KfZdPcDkqhtVq4zQ",
        "y4Lyr2z6AIdHhp8et5Vq9rhSb65sGiMX06EVZ1-_i6Q"
    ]
    private let cnfKid = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Ii1pa2lOemRxV1BDMWlYSW9KNDJvV0M4cU16VHdvWjA4ejY5RjVZZWNaOWsiLCJ5IjoiUUlQcGRPREx4X1hxdVhLaUZhV3oyWW84MmRWelUzNWpFSjRNc2NVR0Z5OCIsInVzZSI6InNpZyJ9#0"

    private var jwtBodyClaims: [String: Any] {
        [
            "issuance_date": "2025-08-18",
            "expiry_date": "2026-08-28",
            "issuing_country": "DE",
            "nbf": 1755475200,
            "exp": 1787875200,
            "vct": "https://example.eudi.ec.europa.eu/cor/1",
            "iss": "https://funke.animo.id",
            "iat": 1756896653,
            "_sd_alg": "sha-256",
            "_sd": sdHashes,
//            "family_name": "Doe",
//            "given_name": "John"
        ]
    }

    // MARK: - extractSdJwtPayload

    func testExtractSdJwtPayloadReturnsCredentialAndPayload() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let (rawCredential, payload, _) = try extractSdJwtPayload(credential, className: classNameValue)

        let expectedJwtBodyClaims: [String: Any] = [
            "issuance_date": "2025-08-18",
            "expiry_date": "2026-08-28",
            "issuing_country": "DE",
            "nbf": 1755475200,
            "exp": 1787875200,
            "vct": "https://example.eudi.ec.europa.eu/cor/1",
            "iss": "https://funke.animo.id",
            "iat": 1756896653,
            "_sd_alg": "sha-256"
        ]
        XCTAssertEqual(rawCredential, sampeVcSdJwtWithHolderBinding)
        for (key, expected) in expectedJwtBodyClaims {
            XCTAssertEqual("\(payload[key] ?? "nil")", "\(expected)", "Mismatch for key '\(key)'")
        }
        XCTAssertNil(payload["family_name"])
        XCTAssertNil(payload["given_name"])
    }

    func testExtractSdJwtPayloadThrowsWhenCredentialIsNotString() throws {
        let credential = AnyCodable(["key": "value"])

        XCTAssertThrowsError(try extractSdJwtPayload(credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSdJwtPayloadThrowsWhenStringIsEmpty() throws {
        let credential = AnyCodable("")

        XCTAssertThrowsError(try extractSdJwtPayload(credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is malformed or empty", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSdJwtPayloadThrowsWhenJwtIsInvalid() throws {
        let credential = AnyCodable("not.a.valid~jwt")

        XCTAssertThrowsError(try extractSdJwtPayload(credential, className: classNameValue))
    }

    func testExtractSdJwtPayloadWithoutDecodeDisclosuresOmitsSelectiveClaims() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let (_, payload, _) = try extractSdJwtPayload(credential, className: classNameValue)

        var expectedPayload = jwtBodyClaims
        expectedPayload["cnf"] = ["kid": cnfKid]
        assertDictionariesEqual(expected: expectedPayload, actual: payload)
    }

    func testExtractSdJwtPayloadWithDecodeDisclosuresMergesSelectiveClaims() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let (_, payload, _) = try extractSdJwtPayload(credential, className: classNameValue, decodeDisclosures: true)

        var expectedPayload = jwtBodyClaims
        expectedPayload["cnf"] = ["kid": cnfKid]

        assertDictionariesEqual(expected: expectedPayload, actual: payload)
    }

    func testExtractSdJwtPayloadDecodeDisclosuresSkipsMalformedSegments() throws {
        let parts = sampeVcSdJwtWithHolderBinding.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        guard parts.count > 2 else {
            XCTFail("fixture must include disclosures")
            return
        }
        var mutated = parts
        mutated[1] = "!!!not-valid!!!"
        let credential = AnyCodable(mutated.joined(separator: "~"))

        let (_, payload, _) = try extractSdJwtPayload(credential, className: classNameValue, decodeDisclosures: true)

        // First disclosure is malformed and skipped; remaining valid ones are still decoded.
        // JWT body claims must still be intact.
        XCTAssertEqual(payload["vct"] as? String, "https://example.eudi.ec.europa.eu/cor/1")
        XCTAssertEqual(payload["iss"] as? String, "https://funke.animo.id")
        XCTAssertNil(payload["family_name"], "Malformed first disclosure must be skipped — family_name must be absent")
    }
    
    func testExtractSdJwtPayloadWithNestedDisclosableClaims() throws {
        let testSdJwt = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rdHF0WE5HOENEVVk5UHJydG9TdEZ6ZUNuaHBNbWd4WUwxZ2lrY1czQnp2TlcifQ.eyJ2Y3QiOiJJZGVudGl0eUNyZWRlbnRpYWwiLCJmYW1pbHlfbmFtZSI6IkRvZSIsInBob25lX251bWJlciI6IisxLTIwMi01NTUtMDEwMSIsImFkZHJlc3MiOnsic3RyZWV0X2FkZHJlc3MiOiIxMjMgTWFpbiBTdCIsImxvY2FsaXR5IjoiQW55dG93biIsIl9zZCI6WyJOSm5tY3QwQnFCTUUxSmZCbEM2alJRVlJ1ZXZwRU9OaVl3N0E3TUh1SnlRIiwib201Wnp0WkhCLUdkMDBMRzIxQ1ZfeE00RmFFTlNvaWFPWG5UQUpOY3pCNCJdfSwiY25mIjp7Imp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im9FTlZzeE9VaUg1NFg4d0pMYVZraWNDUmswMHdCSVE0c1JnYms1NE44TW8ifX0sImlzcyI6ImRpZDprZXk6ejZNa3RxdFhORzhDRFVZOVBycnRvU3RGemVDbmhwTW1neFlMMWdpa2NXM0J6dk5XIiwiaWF0IjoxNjk4MTUxNTMyLCJfc2QiOlsiMUN1cjJrMkEyb0lCNUNzaFNJZl9BX0tnLWwyNnVfcUt1V1E3OVAwVmRhcyIsIlIxelRVdk9ZSGdjZXBqMGpIeXBHSHo5RUh0dFZLZnQweXN3YmM5RVRQYlUiLCJlRHFRcGRUWEpYYldoZi1Fc0k3enc1WDZPdlltRk4tVVpRUU1lc1h3S1B3IiwicGREazJfWEFLSG83Z09BZndGMWI3T2RDVVZUaXQya0pIYXhTRUNROXhmYyIsInBzYXVLVU5XRWkwOW51M0NsODl4S1hnbXBXRU5abDV1eTFOMW55bl9qTWsiLCJzTl9nZTBwSFhGNnFtc1luWDFBOVNkd0o4Y2g4YUVOa3hiT0RzVDc0WXdJIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.Kkhrxy2acd52JTl4g_0x25D5d1QNCTbqHrD9Qu9HzXMxPMu_5T4z-cSiutDYb5cIdi9NzMXPe4MXax-fUymEDg~WyJzYWx0IiwicmVnaW9uIiwiQW55c3RhdGUiXQ~WyJzYWx0IiwiY291bnRyeSIsIlVTIl0~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~WyJzYWx0IiwiZW1haWwiLCJqb2huZG9lQGV4YW1wbGUuY29tIl0~WyJzYWx0IiwiYmlydGhkYXRlIiwiMTk0MC0wMS0wMSJd~WyJzYWx0IiwiaXNfb3Zlcl8xOCIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl8yMSIsdHJ1ZV0~WyJzYWx0IiwiaXNfb3Zlcl82NSIsdHJ1ZV0~"
        
        let (_, _, fullyResolvedClaims) = try extractSdJwtPayload(AnyCodable(testSdJwt), className: classNameValue)
        
        let expectedResolvedClaims: [String: Any] = [
            "vct": "IdentityCredential",
            "family_name": "Doe",
            "phone_number": "+1-202-555-0101",
            "address": [
                "street_address": "123 Main St",
                "locality": "Anytown",
                "region": "Anystate",
                "country": "US"
            ],
            "cnf": [
                "jwk": [
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "oENVsxOUiH54X8wJLaVkicCRk00wBIQ4sRgbk54N8Mo"
                ]
            ],
            "iss": "did:key:z6MktqtXNG8CDUY9PrrtoStFzeCnhpMmgxYL1gikcW3BzvNW",
            "iat": 1698151532,
            "is_over_18": true,
            "is_over_21": true,
            "given_name": "John",
            "birthdate": "1940-01-01",
            "email": "johndoe@example.com",
            "is_over_65": true
        ]

        assertDictionariesEqual(expected: expectedResolvedClaims, actual: fullyResolvedClaims)
    }

    func testExtractSdJwtPayloadWorksWithNoHolderBinding() throws {
        let credential = AnyCodable(sampleVcSdJwtWithNoHolderBinding)

        let (rawCredential, payload, _) = try extractSdJwtPayload(credential, className: classNameValue)

        XCTAssertEqual(rawCredential, sampleVcSdJwtWithNoHolderBinding)
        assertDictionariesEqual(expected: jwtBodyClaims, actual: payload)
    }

    // MARK: - extractSDJwtString

    func testExtractSDJwtStringReturnsStringValue() throws {
        let credential = AnyCodable(sampeVcSdJwtWithHolderBinding)

        let result = try extractSDJwtString(from: credential, className: classNameValue)

        XCTAssertEqual(result, sampeVcSdJwtWithHolderBinding)
    }

    func testExtractSDJwtStringThrowsWhenValueIsNotString() throws {
        let credential = AnyCodable(42)

        XCTAssertThrowsError(try extractSDJwtString(from: credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSDJwtStringThrowsWhenValueIsArray() throws {
        let credential = AnyCodable(["a", "b"])

        XCTAssertThrowsError(try extractSDJwtString(from: credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    func testExtractSDJwtStringThrowsWhenValueIsDictionary() throws {
        let credential = AnyCodable(["key": "value"])

        XCTAssertThrowsError(try extractSDJwtString(from: credential, className: classNameValue)) { error in
            assertOpenID4VPException(error, expectedMessage: "SD-JWT credential is not a String", expectedCode: OpenID4VPErrorCodes.invalidRequest)
        }
    }

    // MARK: - extractMdocDocType

    func testExtractMdocDocType_withDocTypeKey_returnsDocTypeAndString() throws {
        let credential = "uQACam5hbWVTcGFjZXOib29yZy5pc28uMjMyMjAuMYXYGFhspGhkaWdlc3RJRABxZWxlbWVudElkZW50aWZpZXJqaXNzdWVfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMjAyNS0wMS0yOGZyYW5kb21YIErxfnTB6hOiIA04ICZ3yd-AuJ26dpcXlp8YuTgBM1yN2BhYbaRoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVya2V4cGlyeV9kYXRlbGVsZW1lbnRWYWx1ZdkD7GoyMDM0LTA4LTI4ZnJhbmRvbVgg_OZCKXTCt98EpyngHcPgZpZUOW7xklPYilJWdTE0BQPYGFhmpGhkaWdlc3RJRAJxZWxlbWVudElkZW50aWZpZXJvaXNzdWluZ19jb3VudHJ5bGVsZW1lbnRWYWx1ZWJOTGZyYW5kb21YIL6jfi_BR7RpL5Yr__t-oyd8WmXJ_Q9TBIZzXtjUpY7x2BhYc6RoZGlnZXN0SUQDcWVsZW1lbnRJZGVudGlmaWVyeBlpc3N1aW5nX2F1dGhvcml0eV91bmljb2RlbGVsZW1lbnRWYWx1ZWRGaW1lZnJhbmRvbVgg0nFVdYSYfhAEiniI2Wd8UBj8h4QXlOCgf-QQIQvEBezYGFhupGhkaWdlc3RJRARxZWxlbWVudElkZW50aWZpZXJvZG9jdW1lbnRfbnVtYmVybGVsZW1lbnRWYWx1ZWowMTIzNDU2Nzg5ZnJhbmRvbVgghUJWGs3zVkR5RBXjc9SRIRzjKoLKtfnN-NQgGf28nhlub3JnLmlzby43MzY3LjGQ2BhYbKRoZGlnZXN0SUQAcWVsZW1lbnRJZGVudGlmaWVyamlzc3VlX2RhdGVsZWxlbWVudFZhbHVl2QPsajIwMjUtMDEtMjhmcmFuZG9tWCAQK1JdDqGeoW_k1hSgif2_OM4jGICEFrwxHfYYyO78C9gYWG2kaGRpZ2VzdElEAXFlbGVtZW50SWRlbnRpZmllcmtleHBpcnlfZGF0ZWxlbGVtZW50VmFsdWXZA-xqMjAzNC0wOC0yOGZyYW5kb21YIC15QwiKpul2vNwQ5Z2FdMY39miUMoRj1IdcVemp7J0p2BhYZqRoZGlnZXN0SUQCcWVsZW1lbnRJZGVudGlmaWVyb2lzc3VpbmdfY291bnRyeWxlbGVtZW50VmFsdWViTkxmcmFuZG9tWCDEDePMqiuu5O9lcZUQpOYwXbsQVAis8noW4I5bpm-Ao9gYWHOkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcngZaXNzdWluZ19hdXRob3JpdHlfdW5pY29kZWxlbGVtZW50VmFsdWVkRmltZWZyYW5kb21YIP7xaybfvXtpejSlB1VqWwllBydC9GbH3Cl_vbYjThtU2BhYbqRoZGlnZXN0SUQEcWVsZW1lbnRJZGVudGlmaWVyb2RvY3VtZW50X251bWJlcmxlbGVtZW50VmFsdWVqMDEyMzQ1Njc4OWZyYW5kb21YIPJA5tKANspHhq4760sB_Cjhtp7a5d9_PkXNQf8dGbcW2BhYbqRoZGlnZXN0SUQFcWVsZW1lbnRJZGVudGlmaWVyc3JlZ2lzdHJhdGlvbl9udW1iZXJsZWxlbWVudFZhbHVlZjExTU0wNWZyYW5kb21YIAB7l5XRkRffvEYK8PNZKeb2F5eCJTMMW48tiDuaozl-2BhYfqRoZGlnZXN0SUQGcWVsZW1lbnRJZGVudGlmaWVydGRhdGVfb2ZfcmVnaXN0cmF0aW9ubGVsZW1lbnRWYWx1ZcB0MjAyMS0xMi0yMFQxNzo0NTowMFpmcmFuZG9tWCAX_0vWuwnTpUMegYqwg3boCCZYMbSrVp6uDKcdYK3fbtgYWHqkaGRpZ2VzdElEB3FlbGVtZW50SWRlbnRpZmllcngaZGF0ZV9vZl9maXJzdF9yZWdpc3RyYXRpb25sZWxlbWVudFZhbHVlajIwMjAtMDctMTRmcmFuZG9tWCAps-PWQppAuUo7uscn2EUSjAFOe5s6VwSvohD-OjExFtgYWH-kaGRpZ2VzdElECHFlbGVtZW50SWRlbnRpZmllcngddmVoaWNsZV9pZGVudGlmaWNhdGlvbl9udW1iZXJsZWxlbWVudFZhbHVlbFBEMDItNTAxNjg5MGZyYW5kb21YIBJYrNNvfFBTwcOmEqG3dk8EVze9fccuoyEGkBeS2Rw62BhY8KRoZGlnZXN0SUQJcWVsZW1lbnRJZGVudGlmaWVybnZlaGljbGVfaG9sZGVybGVsZW1lbnRWYWx1ZYG5AARzZmFtaWx5X25hbWVfdW5pY29kZXgZYmFyb24gVmFuIGRlciBDw6tybm9zbGrDqXJmYW1pbHlfbmFtZV9sYXRpbjF4GWJhcm9uIFZhbiBkZXIgQ8Orcm5vc2xqw6lyZ2l2ZW5fbmFtZV91bmljb2RlY0NCQXFnaXZlbl9uYW1lX2xhdGluMWNDQkFmcmFuZG9tWCBp34-ABspkyViM6yfsS569XVruHuU_dtmQDJXpBJBUGNgYWMqkaGRpZ2VzdElECnFlbGVtZW50SWRlbnRpZmllcnJiYXNpY192ZWhpY2xlX2luZm9sZWxlbWVudFZhbHVluQAFdXZlaGljbGVfY2F0ZWdvcnlfY29kZWJNMXR0eXBlX2FwcHJvdmFsX251bWJlcmdlMS10ZXN0ZG1ha2VkT1BFTG9jb21tZXJjaWFsX25hbWVlTUlUU1VnY29sb3Vyc4IECWZyYW5kb21YIA4IOgJdyh4UHCGj3SuJF-E0ZGq6Ztwc3wMuiovKZkVf2BhYzaRoZGlnZXN0SUQLcWVsZW1lbnRJZGVudGlmaWVyaW1hc3NfaW5mb2xlbGVtZW50VmFsdWW5AAVkdW5pdGJrZ3gZdGVjaG5fcGVybV9tYXhfbGFkZW5fbWFzcxkFCnB2ZWhpY2xlX21heF9tYXNzGQR-dndob2xlX3ZlaGljbGVfbWF4X21hc3MZCcR1bWFzc19pbl9ydW5uaW5nX29yZGVyGQOYZnJhbmRvbVggrY7ZOa4ThtGv9SzVgJ37J9KPk3XcfWXC-BaaaprHg3jYGFjApGhkaWdlc3RJRAxxZWxlbWVudElkZW50aWZpZXJxdHJhaWxlcl9tYXNzX2luZm9sZWxlbWVudFZhbHVluQADZHVuaXRia2d4I3RlY2hfcGVybV9tYXhfdG93X21hc3NfYnJha2VkX3RyYWlsGQbWeCN0ZWNoX3Blcm1fbWF4X3Rvd19tYXNzX3VuYnJfdHJhaWxlchkBy2ZyYW5kb21YIAoqwh1CT6FCq4zpC7-PkeDboMx08WauVqxGxE1wuHp72BhYlKRoZGlnZXN0SUQNcWVsZW1lbnRJZGVudGlmaWVya2VuZ2luZV9pbmZvbGVsZW1lbnRWYWx1ZbkAA29lbmdpbmVfY2FwYWNpdHkZA-dsZW5naW5lX3Bvd2VyGDRtZW5lcmd5X3NvdXJjZYEPZnJhbmRvbVggHZb1NzpvgwZOm91cmkf2DDcwaUUl9kYa90Oc9Ta4-VTYGFiYpGhkaWdlc3RJRA5xZWxlbWVudElkZW50aWZpZXJsc2VhdGluZ19pbmZvbGVsZW1lbnRWYWx1ZbkAAnducl9vZl9zZWF0aW5nX3Bvc2l0aW9ucwV4GW51bWJlcl9vZl9zdGFuZGluZ19wbGFjZXMBZnJhbmRvbVggEuhRQXivy2P0TF2_Z2Pkm99CkI5k2nL72lEaKNWBSLTYGFhupGhkaWdlc3RJRA9xZWxlbWVudElkZW50aWZpZXJ2dW5fZGlzdGluZ3Vpc2hpbmdfc2lnbmxlbGVtZW50VmFsdWVjTkxEZnJhbmRvbVggagyXDtjE36sSTawTchag-yb29HtI8cYqW-bK0UKUruFqaXNzdWVyQXV0aIRDoQEmogRYMXpEbmFlUnNqTURGTHBmcVZXZ2lqb1JQczhNb1RHOVpVRlBBRlZ1emo5cm5wd1d1OHoYIVkB6TCCAeUwggGLoAMCAQICEBlHRdJAYkBg2sKftHQUkuYwCgYIKoZIzj0EAwIwHTEOMAwGA1UEAxMFQW5pbW8xCzAJBgNVBAYTAk5MMB4XDTI1MDQxMjE0MjMzMFoXDTI2MDUwMjE0MjMzMFowITESMBAGA1UEAxMJY3JlZG8gZGNzMQswCQYDVQQGEwJOTDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBV1TQNJWmvuT9p5OTyRaL_MYQRTc-VDiQSFbMpNEikn6k3yjAekfnBQzYo3ZgWMrhGlIDILlHPITlZ563lvbYSjgagwgaUwHQYDVR0OBBYEFGEfLxUE5ZI39fzZynmcb2NGc92gMA4GA1UdDwEB_wQEAwIHgDAVBgNVHSUBAf8ECzAJBgcogYxdBQECMB8GA1UdIwQYMBaAFC_fMGjWL_UJ8SB2-QhYMY72VLVLMCEGA1UdEgQaMBiGFmh0dHBzOi8vZnVua2UuYW5pbW8uaWQwGQYDVR0RBBIwEIIOZnVua2UuYW5pbW8uaWQwCgYIKoZIzj0EAwIDSAAwRQIgQcHUv3BQbN2sLXz_RhVZIEjiE0HTwTC4bCQco4O5di0CIQD0CVsu6kLH6thq3aXBlx6w1StMP15zxdlwE-q01_Lgj1kET9gYWQRKuQAGZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2bHZhbHVlRGlnZXN0c6Jvb3JnLmlzby4yMzIyMC4xpQBYIB2G4hDSeswt4Rq6ydeZylDfRDAWiYspdkidAE7Yb4qBAVggyIgiR5fGfOdnpM4Ji2id2ZpD2QMS_Tengis6rel1DPACWCDHGEHm4o0gAzk9D4RW9MUYCswWvJjvqydtvBvE-OQ5qANYILal7XhtLFFVV_kp5UQ_Zr6-f2sebkZpAGZNZY-ImJMjBFggzVJ5MdMc1SV5OwY03_Uy4mMn2yaPbREt1rrTEUibuOdub3JnLmlzby43MzY3LjGwAFggg2_eeMPRk3JlcBZ5AJe-KNHVWjAO6zkNy72SbDEsJzIBWCDTJAD9cCltZ_dNPxcqPCFMRJ3nwYua1UlpATpTNnzhiAJYIPFJFGZLA6l6PzstIBx60algbwrcF-mjS88n2nlEqXG1A1ggZZhaoyzv7daURZRlNyJigO93ZZrMuHnL7rmIDG-ShD0EWCBzU2BjNfa-7rRCsog_zxQjDQSyFTqOUdv1s0cxSp1E8gVYIAWp0nAnJc64-MfhtLc_6SdTNrwCayefbXaabn6ZXLj4BlggsZuWXhxG0cWNp5A3RXmwyUblUDKdW4JF2VGON7pX4FkHWCBirQK45XswEzjDyW2hYmKRk8SqM_5NxDAHzpNlYP2_LwhYIFUJT76s_Zg9seiKLoew4wZdJM9svs0TMreNKAH9klh1CVggqNmT3T1jaGBRYMUulr-KnygbpsyXhVzCXT10PJ0RWwcKWCDrVUbaRj7pUG0u7z1mOVNArA7VHOOOaEbc_v4Ol0YkQwtYIEwIjGdsKQzjVbbprpeip-WxrnqbuQIC3I49CIqwBTOIDFggmFHFoD4EugsXG-oJAcMQGY08lPDOaeul1ZNzY48pn0gNWCAflI9gHteg9U_kecDKKI21Vx4_7Vrus2X_U81B6wuODg5YIHY18e1l558_qlD3NcjSyCSMOWsNTwECCzjhDXLBFyCRD1gghsadql0BM096G4_cfvlnep6v5rlFXNhqnEaJC_NUbF5tZGV2aWNlS2V5SW5mb7kAAWlkZXZpY2VLZXmkAQIgASFYINrE_dpcUCKQWZa4Gs73VOPsrbFzFo0sdA9ba58hn2qpIlgg-xN3D4F3LOWlcM99l3Kn3KnxWtsd7wxO5e-KJfhuNhZnZG9jVHlwZXNvcmcuaXNvLjczNjcuMS5tVlJDbHZhbGlkaXR5SW5mb7kABGZzaWduZWTAdDIwMjUtMDEtMjhUMDA6MDA6MDBaaXZhbGlkRnJvbcB0MjAyNS0wMS0yOFQwMDowMDowMFpqdmFsaWRVbnRpbMB0MjAzNC0wOC0yOFQwMDowMDowMFpuZXhwZWN0ZWRVcGRhdGXAdDIwMjctMDEtMTNUMjA6MTg6MzVaWEBv-3sb9npMUov5sUU-IXyJ6LnJoLhQ_eyqqqxYyyWDGxlUA4ZMUMZ5m5JvJF1cEEZ6IYec5sTDm9Dr1LBfMI6Y"
        let (mdocCredential, decodedMdocCredential) = try decodeMdoc(AnyCodable(credential), className: "test")

        let (docType, docTypeString) = try extractMdocDocType(from: decodedMdocCredential, className: classNameValue)

        XCTAssertEqual(docTypeString, "org.iso.7367.1.mVRC")
        XCTAssertEqual(docType, CBOR.utf8String("org.iso.7367.1.mVRC"))
    }
}

