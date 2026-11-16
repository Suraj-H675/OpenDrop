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

        /** Hotspot-host TCP ACCEPT with unchanged TLS CLIENT and FILE SENDER. */
        @JvmStatic external fun sendHotspot(
            bridge: AndroidGuestBridge,
            index: Int,
            name: String,
            declaredSize: Long,
            linuxPeer: String,
            port: Int,
        ): String

        @JvmStatic external fun recoverOne(
            bridge: AndroidGuestBridge,
            transferId: String,
            host: String,
            port: Int,
        ): String

        /** Fresh one-shot listener; only authenticated ODGR receipt query. */
        @JvmStatic external fun recoverHotspot(
            bridge: AndroidGuestBridge,
            transferId: String,
            linuxPeer: String,
            port: Int,
        ): String

        @JvmStatic external fun cancel(): Unit

        /** Real JNI/Rust+AndroidKeyStore signature proof; never test-only key. */
        @JvmStatic external fun identitySelfTest(bridge: AndroidGuestBridge): String
    }
}
