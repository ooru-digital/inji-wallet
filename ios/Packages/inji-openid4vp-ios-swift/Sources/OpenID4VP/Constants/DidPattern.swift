import Foundation

private let percentEncodedPattern = "%[0-9a-fA-F]{2}"
private let didIdCharacterPattern = "(?:[a-zA-Z0-9._-]|\(percentEncodedPattern))"
private let didFragmentCharacterPattern = "(?:[a-zA-Z0-9._~!\\$&'()*+,;=:@/?-]|\(percentEncodedPattern))"

let supportedHolderDidPattern = "^(?:did:jwk:[a-zA-Z0-9_-]+(?:#0)?|"
    + "did:key:(?:z[a-km-zA-HJ-NP-Z1-9]+|u[a-zA-Z0-9_-]+)"
    + "(?:#\(didFragmentCharacterPattern)+)?|"
    + "did:web:(?:\(didIdCharacterPattern)*:)*\(didIdCharacterPattern)+"
    + "(?:#\(didFragmentCharacterPattern)+)?)$"
