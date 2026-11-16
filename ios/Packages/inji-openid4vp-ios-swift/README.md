# INJI-OpenID4VP-ios-swift

inji-openid4vp-ios-swift is an implementation of OpenID for Verifiable Presentations written in swift

**Table of Contents**

- [OpenID4VP specification draft versions supported](#openid4vp-specification-draft-versions-supported)
- [Supported features](#supported-features)
- [Specifications supported](#specifications-supported)
- [Functionalities](#functionalities)
- [Installation](#installation)
- [APIs](#apis)
  - [authenticateVerifier](#authenticateverifier)
  - [constructUnsignedVPToken](#constructUnsignedVPToken)
  - [constructUnsignedVPTokenV2](#constructunsignedvptokenv2)
  - [constructVPResponse](#constructvpresponse)
  - [constructVPResponseV2](#constructvpresponsev2)
  - [sendVPResponseToVerifier](#sendvpresponsetoverifier)
  - [constructErrorInfo](#constructerrorinfo)
  - [sendErrorInfoToVerifier](#senderrorinfotoverifier)

## OpenID4VP specification draft versions supported

- OpenID for Verifiable Presentations - draft 21
- OpenID for Verifiable Presentations - draft 23

## Supported features

| Feature                                                    | Supported values                                                                                                                                                                                                                                                                                                                                  |
|------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Device flow                                                | Cross device flow, Same device flow (only `direct_post` and `direct_post.jwt` supported)                                                                                                                                                                                                                                                          |
| Client id scheme                                           | `pre-registered`, `redirect_uri`, `did`                                                                                                                                                                                                                                                                                                           |
| Signed authorization request verification algorithms       | Ed25519                                                                                                                                                                                                                                                                                                                                           |
| Obtaining authorization request                            | - By value : both signed (via `request` param) and unsigned (via URL encoded parameters)<br/> - By reference ( via `request_uri` method)<br/>_Note: The use of signed or unsigned requests, is determined by the `client_id_scheme` associated with the client._ ([more details](#client-id-schemes-and-signed--unsigned-request-support-matrix)) |
| Obtaining presentation definition in authorization request | By value, By reference (via `presentation_definition_uri`)                                                                                                                                                                                                                                                                                        |
| Authorization Response content encryption algorithms       | `A256GCM`                                                                                                                                                                                                                                                                                                                                         |
| Authorization Response key encryption algorithms           | `ECDH-ES`                                                                                                                                                                                                                                                                                                                                         |
| Credential formats                                         | `ldp_vc`, `mso_mdoc`, `dc+sd-jwt`, `vc+sd-jwt`                                                                                                                                                                                                                                                                                                    |
| Authorization Response mode                                | `direct_post`, `direct_post.jwt` (with encrypted & unsigned responses) and `iar-post` (unencrypted response), `iar-post.jwt` (Encrypted and unsigned response)                                                                                                                                                                                    |
| Authorization Response type                                | `vp_token`                                                                                                                                                                                                                                                                                                                                        |

### Client ID Schemes and Signed / Unsigned request support matrix

| Client Id Scheme | Supports Unsigned request             | Supports Signed request | Notes                                                                                                                                                                                                                                                                    |
|------------------|---------------------------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `pre-registered` | depends ⚖️ on pre-registered Verifier | ✅                       | When `shouldValidateClient` is true, unsigned requests are allowed only if the pre-registered verifier's `allowUnsignedRequest` is true. Otherwise, unsigned requests are always allowed. For signed requests, the trusted verifier's `jwks_uri` is used for validation. |
| `redirect_uri`   | ✅                                     | ❌                       | Signed request is not supported, since this client ID scheme mandates unsigned Authorization Request as per the specification. [(reference)](https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#section-5.10.4-2.1)                                 |
| `did`            | ❌                                     | ✅                       | Only signed Authorization Requests are allowed. Requests can be sent by value or by reference, but must always be signed.                                                                                                                                                |

**Note:**
- All `By Reference` requests are fetched using HTTP GET / POST method and expected to be _**signed**_ JWT.
- All `By Value` requests are either _**signed**_ JWT or URL-encoded parameters (_**unsigned**_).


#### Notes on Supported response modes
1. `direct_post` : 
   - Authorization Response is sent as a POST request to the `response_uri` endpoint. Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type
2. `direct_post.jwt` : 
   - Authorization Response is sent as a POST request to the `response_uri` endpoint. 
   - Authorization Response is attached as request body in `application/x-www-form-urlencoded` HTTP content type. 
   - The response is encrypted using the public key provided in the client_metadata of the authorization request.
   - The created JWE's header contains the `apu` (producer info) as wallet generated nonce (with entropy 16 bytes) and `apv` (recipient info) as the verifier nonce i.e., the nonce received in the authorization request.
   > Note: If the Authorization request includes an `mso_mdoc` format VP, it can only use the `direct_post.jwt` response mode, as required by the ISO-18013-7 specification. Other supported response mode (`direct_post`) is not applicable.
3. `iar-post` :
   - Authorization Response is constructed in unencrypted format.
   - Sample Authorization response structure:
   ```shell
    {
      "vp_token": <verifiable-presentation-token>,
      "presentation_submission": { ... }
    }
    ```
4. `iar-post.jwt` :
   - Authorization Response is constructed in encrypted format (and unsigned) using the public key provided in the client_metadata of the authorization request.
   - The created JWE's header contains the apu (producer info) as wallet generated nonce (with entropy 16 bytes) and apv (recipient info) as the verifier nonce i.e., the nonce received in the authorization request.
   - Sample Authorization response structure:
   ```shell
    {
      "response": <encrypted data of vp_token & presentation_submission>
    }
    ```

## Specifications supported
- The implementation follows OpenID for Verifiable Presentations - draft 21 and draft23 .[Specification-21](https://openid.net/specs/openid-4-verifiable-presentations-1_0-21.html) [Specification-23](https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html).
- The library validates the client_id and client_id_scheme parameters in the authorization request according to the relevant specification.
- If the client_id_scheme parameter is included in the authorization request, the request is treated as conforming to Draft 21, and validation is performed accordingly.
- If the client_id_scheme parameter is not included, the request is interpreted as following Draft 23, and validation is applied based on that specification.

- Below are the fields we expect in the authorization request based on the client id scheme as part of draft 21,
  - Client_id_scheme is **_pre-registered_**
    * client_id
    * client_id_scheme
    * presentation_definition/presentation_definition_uri
    * response_type
    * response_mode
    * nonce
    * state
    * response_uri
    * client_metadata (Optional)

  - Client_id_scheme is **_redirect_uri_**
    * client_id
    * client_id_scheme
    * presentation_definition/presentation_definition_uri
    * response_type
    * nonce
    * state
    * redirect_uri
    * client_metadata (Optional)
    
  - **_Request Uri_** is also supported as part of this version.
    - When request_uri is passed as part of the authorization request, below are the fields we expect in the authorization request,
        * client_id
        * client_id_scheme
        * request_uri
        * request_uri_method
    
- Below are the fields we expect in the authorization request based on the client id scheme as part of draft 23,
  - Client_id_scheme is **_pre-registered_**
    * client_id
    * presentation_definition/presentation_definition_uri
    * response_type
    * response_mode
    * nonce
    * state
    * response_uri
    * client_metadata (Optional)

  - Client_id_scheme is **_redirect_uri_**
    * client_id
    * presentation_definition/presentation_definition_uri
    * response_type
    * nonce
    * state
    * redirect_uri
    * client_metadata (Optional)
    
  - **_Request Uri_** is also supported as part of this version.
  - When request_uri is passed as part of the authorization request, below are the fields we expect in the authorization request,
     * client_id
     * request_uri
     * request_uri_method
   
  - The request uri can return either a jwt token/encoded if it is a jwt the signature is verified as mentioned in the specification.
  - The client id and client id scheme from the authorization request and the client id and client id scheme received from the response of the request uri should be same.

**Note** : The pre-registered client id scheme validation can be toggled on/off based on the optional boolean which you can pass to the authenticateVerifier methods shouldValidateClient parameter. This is false by default.
## Functionalities
- Decode and parse the Verifier's encoded Authorization Request received from the Wallet.
- Authenticates the Verifier using the received clientId and returns the valid Presentation Definition to the Wallet.
- Receives the list of verifiable credentials(VC's) from the Wallet which are selected by the end user based on the credentials requested as part of Verifier Authorization request.
- Constructs the verifiable presentation and send it to wallet for generating Json Web Signature (JWS).
- Receives the signed Verifiable presentation and sends a POST request with generated vp_token and presentation_submission to the Verifier response_uri endpoint.


  **Note** : Fetching Verifiable Credentials by passing [Scope](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-using-scope-parameter-to-re) param in Authorization Request is not supported by this library.

## Installation
- In your swift application go to file > add package dependency > add the  https://github.com/inji/inji-openid4vp-ios-swift.git in git search bar> add package
- Import the library and use

## 🚨 Breaking Changes

From Version release-0.4.x onward:

### API contract changes
This library has undergone some changes in its API contract. 

#### 1. Instantiation of OpenID4VP
- The OpenID4VP class is now initialized with `traceabilityId` and `walletMetadata` parameters.
  - traceabilityId: Used to track the traceability of the requests and responses.
  - walletMetadata: Metadata which wallet supports, such that client-id-scheme support, vp format support, proof type support, etc. (See [walletMetadata construction](#walletmetadata-construction) below for details)

```swift
let openID4VP = OpenID4VP(traceabilityId: "trace-id", walletMetadata: WalletMetadata)
```

#### 2. Construction of WalletMetadata
- The WalletMetadata construction has now been simplified. You can create a WalletMetadata object with the required parameters exposed as constants.
- In detail,
- `WalletMetadata` is now a struct that contains the following properties:
  - `presentationDefinitionURISupported`: Bool
  - `vpFormatsSupported`: [String: VPFormatSupported]
  - `clientIdSchemesSupported`: [ClientIdScheme]
  - `requestObjectSigningAlgValuesSupported`: [RequestSigningAlgorithm]?
  - `authorizationEncryptionAlgValuesSupported`: [KeyManagementAlgorithm]?
  - `authorizationEncryptionEncValuesSupported`: [ContentEncryptionAlgorithm]?

```swift
let walletMetadata = try WalletMetadata(presentationDefinitionURISupported: true,
                                        vpFormatsSupported: [
                                            .ldp_vc: VPFormatSupported(
                                                algValuesSupported: ["Ed25519Signature2018", "Ed25519Signature2020"]
                                            ),
                                            .mso_mdoc: VPFormatSupported(
                                                algValuesSupported: ["ES256"]
                                            )
                                        ],
                                        clientIdSchemesSupported: [.preRegistered, .redirectUri, .did],
                                        requestObjectSigningAlgValuesSupported: [.edDsa],
                                        authorizationEncryptionAlgValuesSupported: [.ecdhEs],
                                        authorizationEncryptionEncValuesSupported: [.A256GCM])
```

3. The `shouldValidateClient` parameter in `authenticateVerifier` now defaults to true.
- If your integration previously relied on it being false, you must now explicitly pass false to preserve the old behavior.
- Example (updated usage)

```swift
 let authorizationRequest : AuthorizationRequest = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri,
                trustedVerifierJSON: trustedVerifiers),
                walletMetadata: walletMetadata,
                shouldValidateClient: false // explicitly set to false if you want to skip client validation
            )
```

## Construction of OpenID4VP instance

- The OpenID4VP class is initialized with `traceabilityId` and `walletMetadata` parameters.

```swift
let openID4VP = OpenID4VP(traceabilityId: "trace-id", walletMetadata: WalletMetadata)
```

###### Parameters
| Name           | Type            | Required | Default Value                                                            | Description                                                                                                                                                                                                     |
|----------------|-----------------|:---------|:-------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| traceabilityId | String          | Yes      | N/A                                                                      | Unique identifier for tracking requests and responses.                                                                                                                                                          |
| walletMetadata | WalletMetadata  | No       | nil                                                                      | Metadata which wallet supports, such that client-id-scheme support, vp format support, proof type support, etc. (See [below](#walletmetadata-construction) for more details on construction of wallet metadata) |

### WalletMetadata construction
- The WalletMetadata is a struct that contains metadata about the wallet's capabilities and supported features.
- It is used to inform the Verifier about the wallet's capabilities when processing authorization requests.
- The WalletMetadata will be sent to the verifier while making a POST request to the `request_uri` endpoint if the authorization request contains `request_uri` and `request_uri_method` as `post`.

```swift
let walletMetadata = try WalletMetadata(presentationDefinitionURISupported: true,
                                        vpFormatsSupported: [
                                            .ldp_vc: VPFormatSupported(
                                                algValuesSupported: ["Ed25519Signature2018", "Ed25519Signature2020"]
                                            ),
                                            .mso_mdoc: VPFormatSupported(
                                                algValuesSupported: ["ES256"]
                                            )
                                        ],
                                        clientIdSchemesSupported: [.preRegistered, .redirectUri, .did],
                                        requestObjectSigningAlgValuesSupported: [.edDsa],
                                        authorizationEncryptionAlgValuesSupported: [.ecdhEs],
                                        authorizationEncryptionEncValuesSupported: [.A256GCM])
```

#### Parameters

| Parameter                                 | Type                            | Required | Default Value                  | Description                                                                                 |
|-------------------------------------------|---------------------------------|----------|--------------------------------|---------------------------------------------------------------------------------------------|
| presentationDefinitionURISupported        | Bool                            | No       | true                           | Indicates whether the wallet supports `presentation_definition_uri`.                        |
| vpFormatsSupported                        | [FormatType: VPFormatSupported] | Yes      | N/A                            | A dictionary specifying the supported verifiable presentation formats and their algorithms. |
| clientIdSchemesSupported                  | [ClientIdScheme]                | No       | [ClientIdScheme.preRegistered] | A list of supported client ID schemes.                                                      |
| requestObjectSigningAlgValuesSupported    | [RequestSigningAlgorithm]?      | No       | nil                            | A list of supported algorithms for signing request objects.                                 |
| authorizationEncryptionAlgValuesSupported | [KeyManagementAlgorithm]?       | No       | nil                            | A list of supported algorithms for encrypting authorization responses.                      |
| authorizationEncryptionEncValuesSupported | [ContentEncryptionAlgorithm]?   | No       | nil                            | A list of supported encryption methods for authorization responses.                         |

**Notes**
- Wallet can send the entire metadata, library will customize it as per authorization request client_id_scheme. Eg - in case pre-registered, library modifies wallet metadata to be sent without request object signing info properties as specified in the specification.

## APIs

### authenticateVerifier

 - Validates the Verifier's Authorization request received from the Wallet and returns the valid Authorization request object. 
 - This method is overloaded to support different ways of Verifier's Authorization request data either as encoded string or as Map of parameters.
 - This method does the following:
   - Receives a list of trusted verifiers & Verifier's Authorization request from consumer (of the library, example - Wallet app).
   - Takes an optional boolean to toggle the client validation.
   - Decodes and parse the request, extracts the clientId and verifies it against trusted verifier's list clientId if clientId is identified to have `pre_registered` clientId scheme.
   - If the data contains request_uri and request_uri_method as post, then the wallet metadata is shared in the request body while making an api call to request_uri for fetching authorization request.
   - The library also validates the incoming authorization request with the wallet metadata passed during the instantiation of OpenID4VP class.

#### Overloads

##### 1. Validates the Authorization request received as URL Encoded string


```swift
    let authorizationRequest : AuthorizationRequest = try openID4VP.authenticateVerifier(urlEncodedAuthorizationRequest: String, trustedVerifiers: [Verifier], shouldValidateClient: Bool)
```

``` swift
//NOTE: New API contract
let authorizationRequest: AuthorizationRequest = try openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest: String,
    trustedVerifiers: [Verifier],
    shouldValidateClient: false
)

//NOTE: Old API contract (with walletMetadata parameter) for backward compatibility
let authorizationRequest: AuthorizationRequest = try openID4VP.authenticateVerifier(
    urlEncodedAuthorizationRequest: String,
    trustedVerifiers: [Verifier],
    shouldValidateClient: false,
    walletMetadata: WalletMetadata? = nil
)
```

##### 2. Validates the Authorization request received as Map of parameters

```swift
    let authorizationRequest : AuthorizationRequest = try openID4VP.authenticateVerifier(authorizationRequest: [String: Any], trustedVerifiers: [Verifier], shouldValidateClient: Bool)
```

#### Parameters

| Name                           | Type            | Required | Default Value | Description                                                                                                                                                                                                                                                                             |
|--------------------------------|-----------------|----------|---------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| urlEncodedAuthorizationRequest | String          | Yes      | N/A           | URL encoded query parameter string containing the Verifier's authorization request                                                                                                                                                                                                      |
| authorizationRequest           | [String : Any]  | Yes      | N/A           | authorization request                                                                                                                                                                                                                                                                   |
| trustedVerifiers               | [Verifier]      | Yes      | N/A           | A list of trusted Verifier objects each containing a clientId, responseUri, jwksUri and allowUnsignedRequest which is used to verify if the Authorization Request if from known Verifier (refer [here](#verifier-parameters) for more details)                                          |
| walletMetadata (deprecated*)   | WalletMetadata? | No       | N/A           | Nullable WalletMetadata to be shared with Verifier (Note: Available in Old deprecated API contract, walletMetadata is now passed as a constructor parameter of OpenID4VP class)<br/>Note: Applicable only for authenticateVerifier method with urlEncodedAuthorizationRequest parameter |
| shouldValidateClient           | Bool            | No       | true          | Boolean to toggle client validation for pre-registered client id scheme                                                                                                                                                                                                                 |

> Only one of `urlEncodedAuthorizationRequest` or `authorizationRequest` is accepted per call, depending on the overload.

#### Usage Notes
- Choose urlEncodedAuthorizationRequest for URL encoded authorization request strings.
- Choose authorizationRequest for request available in a Map data type. 
- trustedVerifiers, walletMetadata and shouldValidateClient behavior is consistent across both overloads.

#### Response Parameters

| Type                 | Description                                 |
|----------------------|---------------------------------------------|
| AuthorizationRequest | The validated Authorization Request object. |

#### Example usage

```swift
 let trustedVerifiers: [Verifier] = [
  Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com/response"], jwksUri: "https://mock-verifier.com/.well-known/jwks.json", allowUnsignedRequest: false)
]

// Usage with URL Encoded Authorization Request

 let urlEncodedAuthorizationRequest: String = """
        openid4vp://authorize?
          client_id=did%3Aweb%verifier.inji.net%3Av1%3Averify
          &client_metadata=...
          &request_uri=https%3A%2F%2Fclient.example.org%2Frequest%2Fvapof4ql2i7m41m68uep
          &request_uri_method=post HTTP/1.1
        """
 let authorizationRequest : AuthorizationRequest = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: urlEncodedAuthorizationRequest,
                trustedVerifier: trustedVerifiers,
                shouldValidateClient: true
            )
            
// Usage with Map of parameters Authorization Request

 let authorizationRequestMap: [String: Any] = [
    "client_id": "mock-client",
    "response_type": "vp_token",
    "response_mode": "direct_post",
    "presentation_definition": [/*...*/],
    "nonce": "random-nonce",
    "state": "random-state",
    "redirect_uri": "https://mock-verifier.com/response"
]

 let authorizationRequest : AuthorizationRequest = try await openID4VP.authenticateVerifier(
                authorizationRequest: authorizationRequestMap,
                trustedVerifiers: trustedVerifiers,
                shouldValidateClient: true
            )
```

### authenticateVerifier (deprecated)
- Receives a list of trusted verifiers & Verifier's encoded Authorization request from consumer app(mobile wallet).
- Takes an optional boolean to toggle the client validation.
- Decodes and parse the request, extracts the clientId and verifies it against trusted verifier's list clientId.
- If the data contains request_uri and request_uri_method as post, then the wallet metadata is shared in the request body while making an api call to request_uri for fetching authorization request.
- The library also validates the incoming authorization request with the wallet metadata
- Returns the validated Authorization request object

> **Note:**
> 
> Replace with <br/>```let authorizationRequest : AuthorizationRequest = try authenticateVerifier(urlEncodedAuthorizationRequest: String, trustedVerifierJSON: [Verifier], shouldValidateClient: Bool)```
> (trustedVerifierJSON parameter name is changed to trustedVerifiers)

```swift
    let authorizationRequest : AuthorizationRequest = try authenticateVerifier(urlEncodedAuthorizationRequest: String, trustedVerifierJSON: [Verifier], shouldValidateClient: Bool)
```

###### Parameters

| Name                           | Type             | Required | Default Value | Description                                                                      |
|--------------------------------|------------------|:---------|:--------------|----------------------------------------------------------------------------------|
| urlEncodedAuthorizationRequest | String           | Yes      | N/A           | URL Encoded authorization request.                                               |
| trustedVerifierJSON            | [Verifier]       | Yes      | N/A           | Array of verifiers to verify the client id of the verifier.                      |
| walletMetadata                 | WalletMetadata?  | Yes      | N/A           | Optional WalletMetadata to be shared with Verifier                               |
| shouldValidateClient           | Bool             | No       | true          | Optional Boolean to toggle client validation for pre-registered client id scheme |


###### Example usage

```swift
 let trustedVerifiers: [Verifier] = [
  Verifier(clientId: "mock-client", responseUris: ["https://mock-verifier.com/response"], jwksUri: "https://mock-verifier.com/.well-known/jwks.json", allowUnsignedRequest: false)
]

 let authorizationRequest : AuthorizationRequest = try await openID4VP.authenticateVerifier(
                urlEncodedAuthorizationRequest: testValidUrlEncodedVPRequestWithRedirectUri,
                trustedVerifierJSON: trustedVerifiers,
                walletMetadata: walletMetadata,
                shouldValidateClient: true
            )
```

#### Verifier Parameters

Each Verifier object in the trustedVerifiers list should contain the following properties:

| Parameter            | Type     | Required | Default Value | Description                                                                                                                                                                                       |
|----------------------|----------|----------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| clientId             | String   | Yes      | N/A           | The unique identifier for the Verifier.                                                                                                                                                           |
| responseUri          | [String] | Yes      | N/A           | A list of trusted Verifier objects each containing a clientId, responseUri, jwksUri and allowUnsignedRequest list (refer [here](#verifier-parameters) for more details)                           |
| jwksUri              | String   | No       | null          | URI value of the Verifier's hosted public key. This will be used to verify the signed Authorization Request. If this is not available Verifier's signed Authorization request cannot be verified. |
| allowUnsignedRequest | Bool     | No       | false         | Accepts unsigned requests from the Verifier. If `shouldValidateClient` is false, unsigned requests are still not allowed.                                                                         |


###### Exceptions

1. DecodingException is thrown when there is and issue while decoding the Authorization Request
2. InvalidQueryParams exception is thrown if
    - query params are not present in the Request
    - there is a issue while extracting the params
    - both presentation_definition and presentation_definition_uri are present in Request
    - both presentation_definition and presentation_definition_uri are not present in Request
3. MissingInput exception is thrown if any of required params are not present in Request
4. InvalidInput exception is thrown if any of required params value is empty
5. JWTVerification exception is thrown if there is any error in extracting public key, kid or signature verification failure.
6. InvalidData exception is thrown if 
   - the received request client_id & response_uri are not matching with any of the trusted verifiers
   - `response_mode` is not supported
   - For `direct_post.jwt` response mode
     - client_metadata is not available
     - unable to find the public key JWK from the `jwks` of `client_metadata` as per the provided algorithm in `client_metadata`
   - `publicKeyMultibase` is null or empty 
7. UnsupportedPublicKeyType exception is thrown when the public key type is not `publicKeyMultibase`.
8. PublicKeyResolutionFailed exception is thrown when there are any errors in extracting the public key from verification method
9. InvalidVerifier exception is thrown if the received request client_iD & response_uri are not matching with any of the trusted verifiers
     

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


### constructUnsignedVPToken
- Receives a dictionary of input_descriptor id & list of verifiable credentials for each input_descriptor that are selected by the end-user.
- Creates a vp_token without proof using received input_descriptor IDs and verifiable credentials, then returns its string representation to consumer app(mobile wallet) for signing it.

```swift
    let unsignedVPTokens = try openID4VP.constructUnsignedVPToken(credentialsMap: [String: [FormatType: Array<Any>]])
```

###### Parameters

| Name           | Type                               | Required | Default Value | Description                                                                                                                                    |
|----------------|------------------------------------|:--------:|:--------------|------------------------------------------------------------------------------------------------------------------------------------------------|
| credentialsMap | [String: [FormatType: Array<Any>]] |   Yes    | N/A           | A Map which contains input descriptor id as key and value is the map of credential format and the list of user selected verifiable credentials |

###### Example usage

```swift
let unsignedVPTokens: [FormatType: UnsignedVPToken] = try openID4VP.constructUnsignedVPToken(
    credentialsMap: [
        "input_descriptor_id": [
            FormatType.ldp_vc.rawValue: [["id": "uuid-1234-1234", //....]],
            FormatType.mso_mdoc.rawValue: ["<base64-encoded-cbor-encoded-credential>"]
        ]
    ]
)
```

###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.
2. InvalidData exception is thrown if provided verifiable credentials list is empty

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.


### constructUnsignedVPTokenV2
- This method creates a flattened list of unsigned VP tokens from a collection of Verifiable Credentials, where each token contains the holder's key reference and signature algorithm required for signing.
- It takes credentials organized by input descriptor IDs and formats, processes them, and returns a list of `UnsignedVPTokenV2` objects, each containing:
    - The credential format type
    - Holder key reference
    - Signature algorithm to be used
    - Data that needs to be signed
- This API simplifies the signing process by providing all necessary information upfront, allowing the wallet to sign each token independently without needing to understand format-specific details.

```swift
    let unsignedVPTokens : [UnsignedVPTokenV2] = try openID4VP.constructUnsignedVPTokenV2(
        verifiableCredentials: [String: [FormatType: [Any]]],
        holderId: String? = nil,
        signatureSuite: String? = nil
    )
```

#### Request Parameters

| Name                  | Type                          | Required | Default Value | Description                                                                                                                                           |
|-----------------------|-------------------------------|----------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| verifiableCredentials | [String: [FormatType: [Any]]] | Yes      | N/A           | A dictionary which contains input descriptor id as key and value is the map of credential format and the list of user selected verifiable credentials |
| holderId              | String?                       | No       | nil           | The holder's identifier (e.g., DID). Required for LDP_VC format credentials                                                                           |
| signatureSuite        | String?                       | No       | nil           | The signature suite/algorithm to be used for signing LDP credentials (e.g., "RsaSignature2018", "Ed25519Signature2018"). Required for LDP_VC format   |


#### Response Parameters

The method returns a `[UnsignedVPTokenV2]` where each `UnsignedVPTokenV2` object contains:

| Property            | Type       | Description                                                                                                                                           |
|---------------------|------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| format              | FormatType | The credential format type (LDP_VC, MSO_MDOC, VC_SD_JWT, or DC_SD_JWT)                                                                                |
| holderKeyReference  | String     | Reference to the holder's key - DID for LDP credentials, key identifier (kid) for SD-JWT, Base64 encoded key for `mso_mdoc` credentials               |
| signatureAlgorithm  | String     | The signature algorithm to use (e.g., "RsaSignature2018" for LDP, "ES256" for mDOC, "ES256" for SD-JWT)                                               |
| dataToSign          | String     | The actual data that needs to be signed - base64 encoded canonicalized data for LDP, unsigned KB-JWT for SD-JWT, device authentication bytes for mDOC |


#### Example usage

```swift
let unsignedVPTokens : [UnsignedVPTokenV2] = try openID4VP.constructUnsignedVPTokenV2(
    verifiableCredentials: [
        "input_descriptor_id_1": [
            FormatType.ldp_vc: [
                "<ldp-vc-json>",
            ]
        ],
        "input_descriptor_id_2": [
            FormatType.mso_mdoc: [
                "credential2",
            ]
        ],
        "input_descriptor_id_3": [
            FormatType.vc_sd_jwt: [
                "credential3",
            ]
        ],
    ],
    holderId: "did:example:holder123",
    signatureSuite: "Ed25519Signature2018"
)

// The wallet can now iterate through unsignedVPTokens and sign each one
let signingResults = unsignedVPTokens.map { unsignedVpToken in
    let signature = signData(unsignedVpToken.dataToSign, unsignedVpToken.holderKeyReference, unsignedVpToken.signatureAlgorithm)
    return VPTokenSigningResultV2(signedData: signature)
}

// Use the signing results with constructVPResponseV2
let response = try openID4VP.constructVPResponseV2(vpTokenSigningResults: signingResults)
```

#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the vp_token without proof.
2. InvalidData exception is thrown if:
    - Provided verifiable credentials list is empty
    - `holderId` is not provided for `LDP_VC` format (required to populate `holderKeyReference` in the response)
    - `signatureSuite` is not provided for `LDP_VC` format
    - No mapping found for a specific credential format
    - Invalid credential structure

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### constructVPResponse

- This function constructs the VP response (with `vp_token` and `presentation_submission`) as per the response mode (refer [here](#notes-on-supported-response-modes) for more details on response mode) with the provided signed data (vpTokenSigningResults).
- Returns back the constructed VPResponse.


```swift
    let vpResponse : [String : Any] = try openID4VP.constructVPResponse(vpTokenSigningResults: [FormatType:VPTokenSigningResult])
```

#### Parameters

| Name                  | Type                               | Required | Default Value | Description                                                                                                                                                   |
|-----------------------|------------------------------------|:---------|:--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | [FormatType: VPTokenSigningResult] | Yes      | N/A           | This will be a map with key as credential format and value as VPTokenSigningResult (which is specific to respective credential format's required information) |

#### Response Parameters

| Type           | Description                                                                                                              |
|----------------|--------------------------------------------------------------------------------------------------------------------------|
| [String : Any] | A map containing the constructed VP response with vp_token and presentation_submission which can be sent to the Verifier |

#### Example usage

```swift
let ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws : createJWS(unsignedLdpVPToken), // If signature algorithm is , "JsonWebSignature2020" / "Ed25519Signature2018" / "RSASignature2018" then jws should be sent
    proofValue : <proofValue>,  // If signature algorithm is "Ed25519Signature2020", then proofValue should be sent
    signatureAlgorithm : "<signatureAlgorithm>",
)

let mdocVPTokenSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication: [
        "<docType>": DeviceAuthentication(
            signature: createSignature(unsignedMdocVPToken.docTypeToDeviceAuthenticationBytes("<docType>")), 
            algorithm: "<mdocAuthenticationAlgorithm>",
        )
    ]
  )

let vpTokenSigningResults : [FormatType: VPTokenSigningResult] = [FormatType.ldp_vc : ldpVPTokenSigningResult, FormatType.mso_mdoc: mdocVPTokenSigningResult]

let vpResponse : [String:Any] = try openID4VP.constructVPResponse(vpTokenSigningResults : vpTokenSigningResults)
```

#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. InvalidData exception is thrown if the response_type in the authorization request is not supported

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.



### constructVPResponseV2
- Constructs a `vp_token` with proof using the provided list of `VPTokenSigningResultV2` (simplified signing results) and `presentation_submission` which can be sent to the Verifier (Verifying party).
- This is the V2 API that works with the flattened list of signed data from `constructUnsignedVPTokenV2`, simplifying the signing workflow by accepting a simple list of signatures in the same order as the unsigned tokens.
- Returns back a map of VP response as per the response mode.

**Note:** This method automatically reconstructs the format-specific signing results internally, so the wallet only needs to provide signatures in the same order as received from `constructUnsignedVPTokenV2`.

```swift
    let response : [String: Any] = try openID4VP.constructVPResponseV2(vpTokenSigningResults: [VPTokenSigningResultV2])
```

#### Request Parameters

| Name                   | Type                        | Description                                                                                                                               |
|------------------------|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults  | [VPTokenSigningResultV2]    | A list of signing results in the same order as the unsigned tokens from `constructUnsignedVPTokenV2`. Each contains only the signed data. |


#### Response Parameters

[String: Any] contains the following properties:

1. If the response mode is related to unencrypted - `direct_post` or `iar-post`:
    - "vp_token": The constructed VP token.
    - "presentation_submission": The presentation submission as a [String: Any].
2. If response mode is related to encrypted - `direct_post.jwt` or `iar-post.jwt`:
    - "response": The encrypted data of the VP response with payload of the JWT containing `vp_token` and `presentation_submission`.


#### Example usage

```swift
// First, get unsigned tokens
let unsignedVPTokens : [UnsignedVPTokenV2] = try openID4VP.constructUnsignedVPTokenV2(
    verifiableCredentials: [
        "input_descriptor_id_1": [
            FormatType.ldp_vc: ["<ldp-vc-json>"]
        ],
        "input_descriptor_id_2": [
            FormatType.mso_mdoc: ["credential2"]
        ],
        "input_descriptor_id_3": [
            FormatType.vc_sd_jwt: ["credential3"]
        ]
    ],
    holderId: "did:example:holder123",
    signatureSuite: "Ed25519Signature2018"
)

// Sign each token and create signing results in the same order
let signingResults = unsignedVPTokens.map { token in
    let signature = wallet.sign(
        data: token.dataToSign,
        keyReference: token.holderKeyReference,
        algorithm: token.signatureAlgorithm
    )
    return VPTokenSigningResultV2(signedData: signature)
}

// Construct the VP response
let vpResponse : [String: Any] = try openID4VP.constructVPResponseV2(
    vpTokenSigningResults: signingResults
)
```

#### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. InvalidData exception is thrown if:
    - The response_type in the authorization request is not supported
    - The number of signing results doesn't match the expected number of unsigned tokens
    - Invalid signature data provided

This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### sendVPResponseToVerifier
- This function constructs the VP response (with `vp_token` and `presentation_submission`) as per the response mode (refer [here](#notes-on-supported-response-modes) for more details on response mode) with the provided signed data (vpTokenSigningResults), then sends it to the Verifier via a HTTP POST request.
- Returns back the response received from the Verifier. Refer here for the structure of VerifierResponse - [VerifierResponse structure](#verifierresponse-structure)

```swift
    let response = try await openID4VP.sendVPResponseToVerifier(vpTokenSigningResults: [FormatType:VPTokenSigningResult])
```

###### Parameters

| Name                  | Type                               | Required | Default Value | Description                                                                                                                                                   |
|-----------------------|------------------------------------|:---------|:--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | [FormatType: VPTokenSigningResult] | Yes      | N/A           | This will be a map with key as credential format and value as VPTokenSigningResult (which is specific to respective credential format's required information) |

### Response Parameters

VerifierResponse contains the following properties:

#### VerifierResponse structure

| Name             | Type             | Description                                                                                                   |
|------------------|------------------|---------------------------------------------------------------------------------------------------------------|
| statusCode       | Int              | HTTP status code received from the Verifier                                                                   |
| redirectUri      | String           | The redirect URI to which the wallet application needs to redirect after sending the response to the Verifier |     
| additionalParams | Map<String, Any> | A map containing any additional response body parameters received from the Verifier                           |
| headers          | Map<String, Any> | A map containing any headers received from the Verifier                                                       |

###### Example usage

```swift
let ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws : createJWS(unsignedLdpVPToken), // If signature algorithm is , "JsonWebSignature2020" / "Ed25519Signature2018" / "RSASignature2018" then jws should be sent
    proofValue : <proofValue>,  // If signature algorithm is "Ed25519Signature2020", then proofValue should be sent
    signatureAlgorithm : "<signatureAlgorithm>",
)

let mdocVPTokenSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication: [
        "<docType>": DeviceAuthentication(
            signature: createSignature(unsignedMdocVPToken.docTypeToDeviceAuthenticationBytes("<docType>")), 
            algorithm: "<mdocAuthenticationAlgorithm>",
        )
    ]
  )
let vpTokenSigningResults : [FormatType: VPTokenSigningResult] = [FormatType.ldp_vc : ldpVPTokenSigningResult, FormatType.mso_mdoc: mdocVPTokenSigningResult]
let response : VerifierResponse = try await openID4VP.sendVPResponseToVerifier(vpTokenSigningResults : vpTokenSigningResults)
```

###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. UnsupportedTypeDecoding exception is thrown when there is any issue in decoding the unsupported type.
3. InterruptedIOException is thrown if the connection is timed out when network call is made.
4. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.
5. InvalidData exception is thrown if the response_type in the authorization request is not supported


This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### shareVerifiablePresentation (deprecated, use sendVPResponseToVerifier instead)
- This function constructs a vp_token with proof using received VPTokenSigningResult, then sends it and the presentation_submission to the Verifier via a HTTP POST request.
- Returns the response back to the consumer app(mobile app) saying whether it has received the shared Verifiable Credentials or not.

```swift
    let response = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults: [FormatType:VPTokenSigningResult])
```

###### Parameters

| Name                  | Type                               | Required | Default Value | Description                                                                                                                                                   |
|-----------------------|------------------------------------|:---------|:--------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|
| vpTokenSigningResults | [FormatType: VPTokenSigningResult] | Yes      | N/A           | This will be a map with key as credential format and value as VPTokenSigningResult (which is specific to respective credential format's required information) |


###### Example usage

```swift
let ldpVPTokenSigningResult = LdpVPTokenSigningResult(
    jws : createJWS(unsignedLdpVPToken), // If signature algorithm is , "JsonWebSignature2020" / "Ed25519Signature2018" / "RSASignature2018" then jws should be sent
    proofValue : <proofValue>,  // If signature algorithm is "Ed25519Signature2020", then proofValue should be sent
    signatureAlgorithm : "<signatureAlgorithm>",
)

let mdocVPTokenSigningResult = MdocVPTokenSigningResult(
    docTypeToDeviceAuthentication: [
        "<docType>": DeviceAuthentication(
            signature: createSignature(unsignedMdocVPToken.docTypeToDeviceAuthenticationBytes("<docType>")), 
            algorithm: "<mdocAuthenticationAlgorithm>",
        )
    ]
  )
let vpTokenSigningResults : [FormatType: VPTokenSigningResult] = [FormatType.ldp_vc : ldpVPTokenSigningResult, FormatType.mso_mdoc: mdocVPTokenSigningResult]
val response : String = try await openID4VP.shareVerifiablePresentation(vpTokenSigningResults : vpTokenSigningResults)
```

###### Exceptions

1. JsonEncodingFailed exception is thrown if there is any issue while serializing the generating vp_token or presentation_submission class instances.
2. UnsupportedTypeDecoding exception is thrown when there is any issue in decoding the unsupported type.
3. InterruptedIOException is thrown if the connection is timed out when network call is made.
4. NetworkRequestFailed exception is thrown when there is any other exception occurred when sending the response over http post request.
5. InvalidData exception is thrown if the response_type in the authorization request is not supported


This method will also notify the Verifier about the error by sending it to the response_uri endpoint over http post request. If response_uri is invalid and validation failed then Verifier won't be able to know about it.

### constructErrorInfo

- Receives an exception and constructs an error response map containing error code, message and optional state to be sent to the Verifier.

```swift
    let errorInfo: [String: Any] = openID4VP.constructErrorInfo(exception: Error)
```

###### Parameters

| Name      | Type  | Description                   | Required | Default Value |
|-----------|-------|-------------------------------|:---------|:--------------|
| exception | Error | Contains the exception object | Yes      | N/A           | 

###### Response Parameters

| Type           | Description                                                                                                                                                                  |
|----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [String : Any] | Map contaning the error response including the properties `error`, `error_description` and `state` (Optional - available if authorization request is validated successfully) |

###### Example usage

```swift
// Example: The user declines to share the requested credentials. In this case, Verifier needs to be informed about the scenario.
// So call the constructErrorInfo method with appropriate exception message to notify the Verifier.
let errorInfo: [String: Any] = openID4VP.constructErrorInfo(
        exception: AccessDenied(
            message: "User did not give consent to share the requested Credentials with the Verifier.",
            className: "SomeClassName"
        )
)
```

### sendErrorInfoToVerifier

- Receives an exception and sends it's message to the Verifier via an HTTP POST request to the Verifier's response_uri endpoint.
- Returns back the response received from the Verifier. Refer here for the structure of VerifierResponse - [VerifierResponse structure](#verifierresponse-structure)

```swift
// Example: The user declines to share the requested credentials. In this case, Verifier needs to be informed about the scenario.
// So call the sendErrorInfoToVerifier method with appropriate exception message to notify the Verifier.

let verifierResponse: VerifierResponse = openID4VP.sendErrorInfoToVerifier(
        AccessDenied(
            message = "User did not give consent to share the requested Credentials with the Verifier.",
            className = this.className
        )
)
```
###### Exceptions

1. ErrorDispatchFailure is thrown if any issue occurs while sending the Authorization Error response to the Verifier.

### sendErrorToVerifier (deprecated, use sendErrorInfoToVerifier instead)
- Receives an exception and sends it's message to the Verifier via a HTTP POST request.

```
 openID4VP.sendErrorToVerifier(error: Error)
```

###### Parameters

| Name  | Type  | Description                   | Required | Default Value | Sample                                                                            |
|-------|-------|-------------------------------|:---------|:--------------|-----------------------------------------------------------------------------------|
| error | Error | Contains the exception object | Yes      | N/A           | `AuthorizationConsent.consentRejectedError(message: "User rejected the consent")` |

###### Example usage

```swift
await openID4VP.sendErrorToVerifier(error: AuthorizationConsent.consentRejectedError(message: "User rejected the consent"))
```

###### Exceptions

1. ErrorDispatchFailure is thrown if any issue occurs while sending the Authorization Error response to the Verifier.

## Exception Handling Enhancement

- The library has been enhanced to handle exceptions more gracefully. Library is throwing `OpenID4VPException` now which gives both Error Code, Message and optional state to the consumer app. The `state` value is extracted from the authorization request and is included in the error response only if it is present and non-empty. This allows the consumer app to handle exceptions more effectively and provide better user experience.

### OpenID4VPException structure

OpenID4VPException is a custom exception class that extends the standard Exception class. It is used to represent errors specific to the OpenID4VP library.

This exception has the following properties:

1. errorCode: A unique code representing the type of error.
2. message: A descriptive message providing details about the error.
3. verifierResponse: An optional property that holds the Verifier response obtained while sending the error to Verifier. Refer here for the structure of VerifierResponse - [VerifierResponse structure](#verifierresponse-structure)
4. className: The name of the class where the exception occurred.


## 🚨 Deprecation Notice

The following methods are deprecated and will be removed in future releases. Please migrate to the suggested alternatives.

| Method Name                                                                                          | Description                                                | Deprecated Since | Suggested Alternative                                 |
|------------------------------------------------------------------------------------------------------|------------------------------------------------------------|------------------|-------------------------------------------------------|
| shareVerifiablePresentation                                                                          | Sends VP (Authorization response) to verifier              | 0.6.0            | [sendVPResponseToVerifier](#sendvpresponsetoverifier) |
| sendErrorToVerifier                                                                                  | Sends Authorization error to the verifier                  | 0.6.0            | [sendErrorInfoToVerifier](#senderrorinfotoverifier)   |
| authenticateVerifier <br/>(Parameter Name changed from `trustedVerifiersJSON` to `trustedVerifiers`) | Validates and authenticates the Authorization (VP) Request | 0.7.0            | [authenticateVerifier](#authenticateverifier)         |

## Architecture decisions

Architecture decisions are documented in the [INJI OpenID4VP ADR directory](https://github.com/inji/inji-openid4vp/tree/master/doc).

## Also available in

This library is also available in the following languages
- [kotlin](https://github.com/inji/inji-openid4vp/tree/master/kotlin)
