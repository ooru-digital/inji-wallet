import Foundation

class JsonLd {
    static var canonicalizer: JsonLdCanonicalizerCallback? = nil
    static var normalizer: JsonLdNormalizerCallback? = nil
    
    static func setCanonicalizer(_ callback: JsonLdCanonicalizerCallback?) {
        JsonLd.canonicalizer = callback
    }
}
