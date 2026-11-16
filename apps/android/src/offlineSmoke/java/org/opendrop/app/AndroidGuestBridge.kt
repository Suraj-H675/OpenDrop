package org.opendrop.app

import android.content.Context

/** Production AndroidKeyStore identity adapter for the OFFLINE JNI self-test.
 * This variant has no socket, sender, recovery, SAS or network interfaces.
 */
class AndroidGuestBridge(context: Context) {
    private val identity = GuestIdentity(context)
    fun installationId(): String = identity.installationId()
    fun publicSpki(): ByteArray = identity.publicSpki()
    fun signP256Sha256(message: ByteArray): ByteArray = identity.signP256Sha256(message)
}
