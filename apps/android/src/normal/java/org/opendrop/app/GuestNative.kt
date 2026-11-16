package org.opendrop.app

/** JNI exports in the Rust cdylib; no alternative Java TLS/data protocol. */
class GuestNative private constructor() {
    companion object {
        init { System.loadLibrary("opendrop_android_guest") }

        @JvmStatic external fun sendOne(
            bridge: AndroidGuestBridge,
            index: Int,
            name: String,
            declaredSize: Long,
            host: String,
            port: Int,
        ): String

        @JvmStatic external fun recoverOne(
            bridge: AndroidGuestBridge,
            transferId: String,
            host: String,
            port: Int,
        ): String

        @JvmStatic external fun cancel(): Unit

        /** Real JNI/Rust+AndroidKeyStore signature proof; never test-only key. */
        @JvmStatic external fun identitySelfTest(bridge: AndroidGuestBridge): String
    }
}
