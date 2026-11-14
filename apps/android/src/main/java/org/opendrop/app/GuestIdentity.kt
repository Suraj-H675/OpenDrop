package org.opendrop.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/** Installation-specific P-256 signing through AndroidKeyStore only.
 *
 * Private key bytes are never read by OpenDrop. Actual securityLevel /
 * hardware-backed status requires separate device-specific verification;
 * AndroidKeyStore provenance does not prove secure-element attestation.
 */
internal class GuestIdentity(context: Context) {
    private val preferences = context.getSharedPreferences("guest_installation", Context.MODE_PRIVATE)
    private val alias = "opendrop.s1.identity.p256.v1"
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Synchronized
    private fun ensureKey(): PrivateKey {
        val exists = store.containsAlias(alias)
        if (!exists) {
            // Losing an existing alias may indicate a wiped keystore;
            // never silently rotate an established identity.
            check(!preferences.contains("device_id")) {
                "Existing OpenDrop identity is unavailable; reset requires user review"
            }
            val generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            generator.initialize(
                KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build())
            generator.generateKeyPair()
        }
        return store.getKey(alias, null) as? PrivateKey
            ?: error("AndroidKeyStore P-256 signing key unavailable")
    }

    @Synchronized
    fun installationId(): String {
        ensureKey()
        return preferences.getString("device_id", null) ?: run {
            val random = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val id = random.joinToString("") { "%02x".format(it.toInt() and 0xff) }
            check(preferences.edit().putString("device_id", id).commit()) {
                "Installation identity could not be committed"
            }
            id
        }
    }

    @Synchronized
    fun publicSpki(): ByteArray {
        ensureKey()
        val bytes = store.getCertificate(alias)?.publicKey?.encoded
            ?: error("AndroidKeyStore public key missing")
        // RFC5480 P-256 uncompressed point, canonical 91-byte DER SPKI.
        val prefix = byteArrayOf(
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(),
            0x48, 0xce.toByte(), 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
            0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00)
        check(bytes.size == 91 && bytes.copyOfRange(0, 26).contentEquals(prefix)
            && bytes[26] == 4.toByte()) {
            "AndroidKeyStore returned noncanonical P-256 public key"
        }
        return bytes
    }

    @Synchronized
    fun signP256Sha256(message: ByteArray): ByteArray {
        val key = ensureKey()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key)
            update(message)
            sign()
        }
        val verified = Signature.getInstance("SHA256withECDSA").run {
            initVerify(store.getCertificate(alias).publicKey)
            update(message)
            verify(signature)
        }
        check(verified) { "AndroidKeyStore returned inconsistent P-256 signature" }
        return signature
    }
}
