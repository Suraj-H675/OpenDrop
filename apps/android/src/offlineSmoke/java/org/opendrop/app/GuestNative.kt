package org.opendrop.app

/** Same production AndroidKeyStore -> JNI -> Rust P256 signing proof.
 * No Send/Recover/Cancel JNI entrypoints exist in this offline Java API.
 */
class GuestNative private constructor() {
    companion object {
        init { System.loadLibrary("opendrop_android_guest") }
        @JvmStatic external fun identitySelfTest(bridge: AndroidGuestBridge): String
    }
}
