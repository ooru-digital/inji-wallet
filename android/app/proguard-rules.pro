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
