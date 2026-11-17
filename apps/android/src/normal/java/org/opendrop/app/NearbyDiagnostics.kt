package org.opendrop.app

/** Fixed, privacy-safe observations of actual nearby operations. No addresses,
 * identity material, filenames, peer-controlled strings or exception text.
 * A state is emitted only after the corresponding operation completes/fails.
 */
internal enum class NearbyDiagnostic(val label: String, val terminalFailure: Boolean = false) {
    HotspotInterfaceSelected("Hotspot interface selected; checking local listener"),
    HotspotInterfaceMissing("Hotspot unavailable: no permitted local AP interface", true),
    HotspotInterfaceAmbiguous("Hotspot unavailable: multiple permitted AP interfaces", true),
    HotspotInterfaceInspectionFailed("Hotspot interface inspection failed", true),
    HotspotTcpBound("Hotspot TCP listener bound; starting discovery beacon"),
    HotspotTcpBindFailed("Hotspot TCP listener could not bind", true),
    HotspotBeaconBound("Hotspot discovery UDP socket bound"),
    HotspotBeaconBindFailed("Hotspot discovery UDP socket could not bind", true),
    HotspotBeaconSent("Hotspot discovery UDP advertisement sent"),
    HotspotBeaconSendFailed("Hotspot discovery UDP advertisement could not be sent", true),
    HotspotTcpAccepted("Hotspot received one local TCP connection; verifying peer"),
    HotspotPeerRejected("Hotspot connection rejected: source or route changed", true),
    HotspotWaitExpired("Hotspot wait expired without a permitted TCP peer", true),
    HotspotCancelled("Hotspot wait cancelled; no transfer authorized", true),
    PreNetworkFailed("Transfer preparation failed before hotspot listener selection", true),
    ForegroundStopped("Nearby session stopped because the app left the foreground", true),
}

/** A terminal result survives delayed ordinary-LAN discovery callbacks and
 * asynchronous main-thread message dispatch until the next explicit attempt.
 * This owns UI text only; it never authorizes a connection or file transfer.
 */
internal fun classifyHotspotInterfaceCount(count: Int): NearbyDiagnostic {
    require(count >= 0)
    return when (count) {
        0 -> NearbyDiagnostic.HotspotInterfaceMissing
        1 -> NearbyDiagnostic.HotspotInterfaceSelected
        else -> NearbyDiagnostic.HotspotInterfaceAmbiguous
    }
}

internal fun classifyBeaconException(bound: Boolean): NearbyDiagnostic =
    if (bound) NearbyDiagnostic.HotspotBeaconSendFailed
    else NearbyDiagnostic.HotspotBeaconBindFailed

internal class NearbyStatusPolicy {
    private var last = ""
    private var terminal = false

    @Synchronized fun resetForOwnerAttempt() {
        last = ""
        terminal = false
    }

    @Synchronized fun accept(message: String, terminalEvent: Boolean = false): Boolean {
        if (terminal) return false
        last = message
        if (terminalEvent) terminal = true
        return true
    }

    @Synchronized fun current(): String = last
    @Synchronized fun isFinal(): Boolean = terminal
}

/** Fixed bounded counter; no packet, socket or peer content is recorded. */
internal class NearbyBoundedCount(private val maximum: Int = 64) {
    init { require(maximum in 1..1024) }
    private var count = 0
    @Synchronized fun observed(): Int {
        if (count < maximum) count++
        return count
    }
    @Synchronized fun value(): Int = count
}
