package io.mosip.residentapp.mdoc

import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.facebook.react.bridge.ReactApplicationContext
import com.reactnativesecurekeystore.CipherBoxImpl
import com.reactnativesecurekeystore.KeyGeneratorImpl
import com.reactnativesecurekeystore.PreferencesImpl
import com.reactnativesecurekeystore.SecureKeystoreImpl
import com.reactnativesecurekeystore.biometrics.Biometrics
import org.multipaz.crypto.Algorithm
import org.multipaz.crypto.EcCurve
import org.multipaz.crypto.EcPublicKey
import org.multipaz.crypto.EcPublicKeyDoubleCoordinate
import org.multipaz.crypto.EcSignature
import org.multipaz.prompt.Reason
import org.multipaz.securearea.BatchCreateKeyResult
import org.multipaz.securearea.CreateKeySettings
import org.multipaz.securearea.KeyAttestation
import org.multipaz.securearea.KeyInfo
import org.multipaz.securearea.SecureArea
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

/**
 * [SecureArea] that signs with MOSIP Android Keystore alias **ES256**
 * (same key used by [io.mosip.residentapp.RNSecureKeystoreModule]).
 *
 * Important: DeviceAuthentication bytes are binary CBOR. Do **not** route them through
 * [SecureKeystoreImpl.sign] / [CipherBoxImpl.sign], which re-encode the payload as UTF-8 and
 * corrupt any byte >= 0x80. That produces a signature over the wrong bytes while the public key
 * still matches the MSO — exactly the "Device Authentication failed" / lenient-mode-works case.
 *
 * Biometric flow must mirror [SecureKeystoreImpl.sign]: let [Biometrics.authenticateAndPerform]
 * observe [java.security.SignatureException] / [android.security.keystore.UserNotAuthenticatedException]
 * so it can show the prompt. Swallowing those in the action callback skips biometric unlock.
 */
class InjiSecureKeystoreSecureArea(
    private val reactContext: ReactApplicationContext,
    private val publicKey: EcPublicKey,
) : SecureArea {

    private val keystore: SecureKeystoreImpl =
        SecureKeystoreImpl(
            KeyGeneratorImpl(),
            CipherBoxImpl(),
            Biometrics(),
            PreferencesImpl(reactContext),
        )

    private val cipherBox = CipherBoxImpl()
    private val biometrics = Biometrics()

    override val identifier: String = "InjiSecureKeystoreSecureArea"
    override val displayName: String = "Inji hardware keystore"
    override val supportedAlgorithms: List<Algorithm> = listOf(Algorithm.ESP256)

    override suspend fun createKey(alias: String?, createKeySettings: CreateKeySettings): KeyInfo {
        throw UnsupportedOperationException("InjiSecureKeystoreSecureArea does not create keys")
    }

    override suspend fun batchCreateKey(
        numKeys: Int,
        createKeySettings: CreateKeySettings,
    ): BatchCreateKeyResult {
        throw UnsupportedOperationException("InjiSecureKeystoreSecureArea does not create keys")
    }

    override suspend fun deleteKey(alias: String) {}

    override suspend fun sign(
        alias: String,
        dataToSign: ByteArray,
        unlockReason: Reason,
    ): EcSignature {
        if (alias != INJI_ES256_ALIAS) {
            throw IllegalArgumentException("Unknown key alias $alias")
        }
        val highBytes = dataToSign.count { (it.toInt() and 0xff) >= 0x80 }
        Log.i(
            TAG,
            "Wallet DeviceAuth signing with keystore alias=$INJI_ES256_ALIAS " +
                "keyId=$INJI_ES256_ALIAS dataToSignBytes=${dataToSign.size} " +
                "highBytes=$highBytes mode=raw-bytes",
        )

        val privateKey = keystore.getKeyOrThrow(INJI_ES256_ALIAS) as PrivateKey
        val signingContext =
            reactContext.currentActivity
                ?: throw IllegalStateException(
                    "Cannot unlock ES256 for DeviceAuth: no current Activity for biometric prompt",
                )
        if (signingContext !is FragmentActivity) {
            throw IllegalStateException(
                "Cannot unlock ES256 for DeviceAuth: Activity is not FragmentActivity " +
                    "(${signingContext.javaClass.name})",
            )
        }

        // Same try-then-biometric pattern as SecureKeystoreImpl.sign, but Signature.update(raw bytes).
        var signed: EcSignature? = null
        var failure: Throwable? = null
        biometrics.authenticateAndPerform(
            {
                BiometricPrompt.CryptoObject(
                    cipherBox.createSignature(privateKey, "SHA256withECDSA"),
                )
            },
            { cryptoObject: BiometricPrompt.CryptoObject ->
                // Do NOT catch SignatureException / UserNotAuthenticatedException here.
                // Biometrics.authenticateAndPerform relies on those to open the prompt, then
                // re-invokes this action with an authenticated CryptoObject.
                val signature =
                    cryptoObject.signature
                        ?: throw IllegalStateException("Biometric CryptoObject has no Signature")
                signature.update(dataToSign)
                val der = signature.sign()
                Log.i(TAG, "Wallet DeviceAuth raw-byte signature OK derBytes=${der.size}")
                signed = EcSignature.fromDerEncoded(256, der)
            },
            { code: Int, message: String ->
                failure = IllegalStateException("Keystore sign failed: $code $message")
            },
            signingContext,
        )
        failure?.let { throw it }
        return signed
            ?: throw IllegalStateException("Keystore biometric sign produced no signature")
    }

    override suspend fun keyAgreement(
        alias: String,
        otherKey: EcPublicKey,
        unlockReason: Reason,
    ): ByteArray {
        throw UnsupportedOperationException(
            "ECDH not supported on hardware ES256 key; use ECDSA-only mdoc DeviceAuth",
        )
    }

    override suspend fun getKeyInfo(alias: String): KeyInfo {
        if (alias != INJI_ES256_ALIAS) {
            throw IllegalArgumentException("Unknown key alias $alias")
        }
        return InjiKeyInfo(INJI_ES256_ALIAS, Algorithm.ESP256, publicKey)
    }

    override suspend fun getKeyInvalidated(alias: String): Boolean {
        if (alias != INJI_ES256_ALIAS) {
            throw IllegalArgumentException("Unknown key alias $alias")
        }
        return false
    }

    private class InjiKeyInfo(
        alias: String,
        algorithm: Algorithm,
        publicKey: EcPublicKey,
    ) : KeyInfo(alias, algorithm, publicKey, KeyAttestation(publicKey, null))

    companion object {
        const val INJI_ES256_ALIAS: String = "ES256"
        private const val TAG: String = "InjiIso18013Proximity"

        /**
         * Load the live Android Keystore ES256 public key (same alias used for DeviceAuth signing).
         * TEMP debug helper for MSO-vs-keystore compare.
         */
        fun retrieveEs256PublicKey(reactContext: ReactApplicationContext): EcPublicKeyDoubleCoordinate {
            val keystore =
                SecureKeystoreImpl(
                    KeyGeneratorImpl(),
                    CipherBoxImpl(),
                    Biometrics(),
                    PreferencesImpl(reactContext),
                )
            val pem = keystore.retrieveKey(INJI_ES256_ALIAS)
            return parsePemEcP256PublicKey(pem)
        }

        fun parsePemEcP256PublicKey(pem: String): EcPublicKeyDoubleCoordinate {
            val cleaned =
                pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replace("\\s".toRegex(), "")
            val der = Base64.decode(cleaned, Base64.DEFAULT)
            val pub =
                KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der)) as ECPublicKey
            val x = bigIntToFixedLength(pub.w.affineX, 32)
            val y = bigIntToFixedLength(pub.w.affineY, 32)
            return EcPublicKeyDoubleCoordinate(EcCurve.P256, x, y)
        }

        private fun bigIntToFixedLength(value: BigInteger, length: Int): ByteArray {
            var bytes = value.toByteArray()
            if (bytes.size == length + 1 && bytes[0] == 0.toByte()) {
                bytes = bytes.copyOfRange(1, bytes.size)
            }
            require(bytes.size <= length) {
                "EC coordinate too large: ${bytes.size} > $length"
            }
            if (bytes.size == length) {
                return bytes
            }
            val out = ByteArray(length)
            System.arraycopy(bytes, 0, out, length - bytes.size, bytes.size)
            return out
        }
    }
}

/**
 * Signs raw bytes (passed base64) with a keystore key, for RNSecureKeystoreModule.signBytes.
 * Upstream Inji Wallet 1.0.0-alpha.1's BinarySigner, kept here next to the other raw-byte signer.
 *
 * OpenID4VP 1.0 hands the wallet binary data to sign (canonicalized VP hashes, mdoc
 * DeviceAuthentication). SecureKeystoreImpl.sign takes a String and signs its UTF-8 bytes, which
 * corrupts any byte >= 0x80 (see InjiSecureKeystoreSecureArea above), so it cannot be used for that.
 *
 * The result is the raw signature as standard base64 (NO_WRAP): DER for ECDSA, which JS converts to
 * r||s. URL_SAFE here mangled DER bytes containing '+' or '/' (upstream #2496 / #2487).
 */
object BinarySigner {
    fun signBase64(
        keystore: SecureKeystoreImpl,
        cipherBox: CipherBoxImpl,
        biometrics: Biometrics,
        signAlgorithm: String,
        alias: String,
        base64Data: String,
        onSuccess: (String) -> Unit,
        onFailure: (Int, String) -> Unit,
        context: android.content.Context,
    ) {
        try {
            val key = keystore.getKeyOrThrow(alias) as PrivateKey
            val payload = Base64.decode(base64Data, Base64.NO_WRAP)

            kotlinx.coroutines.runBlocking {
                val createCryptoObject = {
                    BiometricPrompt.CryptoObject(cipherBox.createSignature(key, signAlgorithm))
                }
                val action: (BiometricPrompt.CryptoObject) -> Unit = { cryptoObject ->
                    val signature = cryptoObject.signature!!
                    signature.update(payload)
                    onSuccess(Base64.encodeToString(signature.sign(), Base64.NO_WRAP))
                }
                biometrics.authenticateAndPerform(createCryptoObject, action, onFailure, context)
            }
        } catch (e: Exception) {
            onFailure(e.hashCode(), e.message ?: e.toString())
        }
    }
}
