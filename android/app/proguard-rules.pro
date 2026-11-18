# R8 removes code the app never reaches but keeps every name, so anything found by name at run
# time (JNI, reflection, service loaders, JSON mapping) still resolves and stack traces stay
# readable. React Native, Expo and most AndroidX libraries ship their own rules in their AARs.
-dontobfuscate
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod,Exceptions,SourceFile,LineNumberTable

# The app's own native modules, called from JavaScript by name.
-keep class io.mosip.residentapp.** { *; }

# MOSIP and Inji libraries: credential download, verification, rendering, BLE and OpenID4VP
# sharing, secure keystore. They map JSON to classes and load parts of themselves by name.
-keep class io.mosip.** { *; }
-keep class io.inji.** { *; }
-keep class com.reactnativesecurekeystore.** { *; }

# Multipaz: mdoc, CBOR, secure area and presentment (kotlinx.serialization and reflection).
-keep class org.multipaz.** { *; }

# BioChq face SDK and the MediaPipe models it runs through JNI.
-keep class io.ooru.** { *; }
-keep class com.google.mediapipe.** { *; }
-keep class com.google.protobuf.** { *; }

# Security providers are instantiated by name through java.security.
-keep class org.bouncycastle.** { *; }
-keep class org.spongycastle.** { *; }

# JSON and JSON-LD mapping, and the Spring classes MOSIP's verifier creates by reflection.
-keep class com.fasterxml.jackson.** { *; }
-keep class org.springframework.** { *; }
-keep class com.apicatalog.** { *; }
-keep class com.nimbusds.** { *; }
-keep class com.google.gson.** { *; }

# W3C VC (ldp_vc) verification in MOSIP's vcverifier. JsonLDObject reads each credential and
# proof class's DEFAULT_JSONLD_CONTEXTS / _TYPES / _PREDICATE fields by name; without these rules
# every ldp_vc download fails with "NoSuchFieldException: DEFAULT_JSONLD_PREDICATE".
-keep class foundation.identity.** { *; }
-keep class info.weboftrust.** { *; }
-keep class com.danubetech.** { *; }
# RDF canonicalisation, and Jakarta JSON, whose API loads its implementation by class name.
-keep class io.setl.** { *; }
-keep class jakarta.json.** { *; }
-keep class org.glassfish.json.** { *; }
# Ed25519 signatures: lazysodium calls libsodium through JNA, which maps classes by reflection;
# the i2p EdDSA classes are registered as a security provider.
-keep class com.goterl.** { *; }
-keep class com.sun.jna.** { *; }
-keep class * implements com.sun.jna.** { *; }
-keep class net.i2p.crypto.** { *; }
# JWT (Jackson-mapped models), SD-JWT and CBOR (claim 169 QR) used alongside verification.
-keep class io.fusionauth.** { *; }
-keep class com.authlete.** { *; }
-keep class co.nstant.in.** { *; }
-keep class com.upokecenter.** { *; }

-keepclassmembers,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# kotlinx.serialization looks up generated serializers by name.
-keepclassmembers class * {
    *** Companion;
}
-keepclasseswithmembers class * {
    kotlinx.serialization.KSerializer serializer(...);
}

# Classes that the libraries reference but never load on Android (server, desktop and build-time
# parts). Without these R8 stops at the missing classes.
-dontwarn **
