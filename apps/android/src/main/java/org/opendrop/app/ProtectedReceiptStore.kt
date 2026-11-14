package org.opendrop.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** AES-GCM sealed per-offer recovery records, never plaintext preferences.
 * The 256-bit token stays inside ciphertext at rest; record ID and expiry
 * are not secrets, but authenticated as AES-GCM associated data.
 */
internal class ProtectedReceiptStore(context: Context) {
    private val prefs = context.getSharedPreferences("guest_receipts", Context.MODE_PRIVATE)
    private val alias = "opendrop.s1.recovery.aesgcm.v1"
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    @Synchronized
    private fun key(): SecretKey {
        if (!keyStore.containsAlias(alias)) {
            check(prefs.all.keys.none { it.startsWith("sealed:") }) {
                "Recovery key missing; never silently replace an established key"
            }
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            generator.init(KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build())
            generator.generateKey()
        }
        return keyStore.getKey(alias, null) as? SecretKey
            ?: error("AndroidKeyStore recovery protection unavailable")
    }

    private fun validId(id: String) =
        id.length == 32 && id.all { it in '0'..'9' || it in 'a'..'f' }

    @Synchronized
    fun sealRecovery(id: String, expiresMs: Long, plaintext: ByteArray): Boolean {
        require(validId(id) && plaintext.size in 1..1024 && expiresMs > System.currentTimeMillis())
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD("$id:$expiresMs".toByteArray(Charsets.US_ASCII))
            val ciphertext = cipher.doFinal(plaintext)
            val wrapped = cipher.iv + ciphertext
            return prefs.edit()
                .putString("sealed:$id", Base64.encodeToString(wrapped, Base64.NO_WRAP))
                .putLong("until:$id", expiresMs)
                .putString("latest", id)
                .commit()
        } finally {
            // JNI's temporary Java-heap copy must not retain a second live
            // plaintext credential after the AEAD operation or any failure.
            plaintext.fill(0.toByte())
        }
    }

    @Synchronized
    fun unsealRecovery(id: String): ByteArray? {
        require(validId(id))
        val expires = prefs.getLong("until:$id", 0)
        val stored = prefs.getString("sealed:$id", null) ?: return null
        if (System.currentTimeMillis() >= expires || expires <= 0) {
            clearRecovery(id)
            return null
        }
        val bytes = Base64.decode(stored, Base64.NO_WRAP)
        require(bytes.size >= 12 + 16 && bytes.size <= 2048)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(),
            javax.crypto.spec.GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        cipher.updateAAD("$id:$expires".toByteArray(Charsets.US_ASCII))
        return cipher.doFinal(bytes, 12, bytes.size - 12)
    }

    @Synchronized
    fun clearRecovery(id: String): Boolean {
        require(validId(id))
        val edit = prefs.edit().remove("sealed:$id").remove("until:$id")
        if (prefs.getString("latest", null) == id) edit.remove("latest")
        return edit.commit()
    }

    @Synchronized
    fun latestPending(): String? {
        pruneExpired()
        return prefs.getString("latest", null)?.takeIf(::validId)
    }

    @Synchronized
    fun pruneExpired() {
        val now = System.currentTimeMillis()
        prefs.all.keys.filter { it.startsWith("until:") }.forEach { entry ->
            val id = entry.removePrefix("until:")
            if (validId(id) && prefs.getLong(entry, 0) <= now) clearRecovery(id)
        }
    }
}
