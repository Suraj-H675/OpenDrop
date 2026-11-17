package org.opendrop.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.LinkAddress
import android.os.SystemClock
import java.io.Closeable
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.SocketException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Source-scoped, anonymous candidate discovery. No discovered name, address or
 * presence grants trust. Only actual mutual TLS, the ten-digit SAS verified
 * on BOTH screens, and the Linux owner's separate exact Offer consent can
 * authorize a transfer.
 *
 * Android uses a platform-selected, non-VPN Wi-Fi/Ethernet Network when
 * receiving announcements. A tethering host has no such Network; it only
 * advertises on its explicitly identified local AP interface. Internet,
 * cellular, VPN, USB and generic default-route discovery are not used.
 */
internal object NearbyLocalWire {
    const val discoveryPort = 43992
    const val transferPort = 43991
    private const val packetLength = 24
    const val receiverListener = 1
    const val senderListener = 2

    data class Candidate(val address: Inet4Address, val port: Int, val role: Int) {
        // This is deliberately not a paired identity or trusted display name.
        val label: String get() = "Nearby OpenDrop device (unverified)"
    }

    fun privateLocal(address: Inet4Address): Boolean =
        address.isSiteLocalAddress && !address.isLoopbackAddress &&
            !address.isLinkLocalAddress && !address.isMulticastAddress

    private fun asInt(address: Inet4Address): Int {
        var result = 0
        for (octet in address.address) result = (result shl 8) or (octet.toInt() and 0xff)
        return result
    }

    fun sameLink(local: Inet4Address, peer: Inet4Address, prefix: Int): Boolean {
        if (!privateLocal(local) || !privateLocal(peer) || local == peer ||
            prefix !in 16..30) return false
        val mask = -1 shl (32 - prefix)
        return (asInt(local) and mask) == (asInt(peer) and mask)
    }

    fun encode(role: Int, port: Int = transferPort): ByteArray {
        require(role == receiverListener || role == senderListener)
        require(port == transferPort)
        val bytes = ByteArray(packetLength)
        "ODNB".toByteArray(Charsets.US_ASCII).copyInto(bytes)
        bytes[4] = 1
        bytes[5] = role.toByte()
        bytes[6] = (port ushr 8).toByte()
        bytes[7] = port.toByte()
        val nonce = ByteArray(16)
        SecureRandom().nextBytes(nonce)
        nonce.copyInto(bytes, 8)
        nonce.fill(0)
        return bytes
    }

    /** Never parse a service-provided hostname or alleged IP from the packet.
     * The source is the OS-observed UDP source, and the subnet is the OS link.
     */
    fun parse(
        bytes: ByteArray,
        length: Int,
        source: InetAddress,
        local: Inet4Address,
        prefix: Int,
    ): Candidate? {
        if (length != packetLength || bytes.size < length ||
            source !is Inet4Address || !sameLink(local, source, prefix)) return null
        if (bytes[0] != 'O'.code.toByte() || bytes[1] != 'D'.code.toByte() ||
            bytes[2] != 'N'.code.toByte() || bytes[3] != 'B'.code.toByte() ||
            bytes[4] != 1.toByte()) return null
        val role = bytes[5].toInt() and 0xff
        val port = ((bytes[6].toInt() and 0xff) shl 8) or (bytes[7].toInt() and 0xff)
        if (role != receiverListener && role != senderListener ||
            port != transferPort || bytes.sliceArray(8 until packetLength).all { it == 0.toByte() })
            return null
        return Candidate(source, port, role)
    }

    /** Advertise only to the broadcast address of this one actual private link. */
    fun directedBroadcast(local: Inet4Address, prefix: Int): Inet4Address {
        require(privateLocal(local) && prefix in 16..30)
        val mask = -1 shl (32 - prefix)
        val broadcast = asInt(local) or mask.inv()
        return InetAddress.getByAddress(byteArrayOf(
            (broadcast ushr 24).toByte(), (broadcast ushr 16).toByte(),
            (broadcast ushr 8).toByte(), broadcast.toByte()
        )) as Inet4Address
    }
}

/** Receives candidates on exactly one OS-selected local Wi-Fi/Ethernet Network.
 * No discovery across cellular or an ambiguous multi-homed environment.
 */
internal class NearbyLocalDiscovery(
    context: Context,
    private val onCandidate: (NearbyLocalWire.Candidate) -> Unit,
    private val onUnavailable: (String) -> Unit,
) : Closeable {
    private val app = context.applicationContext
    private val live = AtomicBoolean(false)
    @Volatile private var socket: DatagramSocket? = null

    fun start() {
        check(live.compareAndSet(false, true))
        val cm = app.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val available = cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                 !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))) return@mapNotNull null
            val props = cm.getLinkProperties(network) ?: return@mapNotNull null
            val source = props.linkAddresses.mapNotNull { address ->
                val ip = address.address
                if (ip is Inet4Address && NearbyLocalWire.privateLocal(ip) &&
                    address.prefixLength in 16..30) address else null
            }
            if (source.size == 1) network to source.single() else null
        }
        if (available.size != 1) {
            live.set(false)
            onUnavailable("No unique permitted local Wi-Fi/Ethernet path; nearby search unavailable.")
            return
        }
        val (network, link) = available.single()
        val local = link.address as Inet4Address
        Thread({
            try {
                val udp = DatagramSocket(null)
                udp.soTimeout = 250
                udp.reuseAddress = true
                udp.bind(InetSocketAddress(NearbyLocalWire.discoveryPort))
                network.bindSocket(udp)
                socket = udp
                // OS route/property recheck occurs on each received candidate,
                // not just at startup. Never use default or cellular routing.
                val buffer = ByteArray(128)
                while (live.get()) {
                    val received = DatagramPacket(buffer, buffer.size)
                    try { udp.receive(received) }
                    catch (error: java.net.SocketTimeoutException) { continue }
                    val refreshed = cm.getLinkProperties(network)
                    if (refreshed?.linkAddresses?.none {
                        it.address == local && it.prefixLength == link.prefixLength
                    } != false) break
                    val candidate = NearbyLocalWire.parse(
                        received.data, received.length, received.address,
                        local, link.prefixLength
                    )
                    if (candidate?.role == NearbyLocalWire.receiverListener) {
                        onCandidate(candidate)
                    }
                }
            } catch (_: Exception) {
                if (live.get()) onUnavailable("Local discovery is blocked or not permitted on this network.")
            } finally {
                socket?.close()
                socket = null
                live.set(false)
            }
        }, "opendrop-nearby-wifi-candidates").apply { isDaemon = true }.start()
    }

    override fun close() {
        live.set(false)
        socket?.close()
    }
}

/** The one-shot hotspot listener's brief, anonymous, AP-local announcement.
 * The actual TCP listener MUST already be bound to this local AP address.
 */
internal class NearbyHotspotBeacon(
    private val local: Inet4Address,
    private val prefix: Int,
    port: Int,
    private val onDiagnostic: (NearbyDiagnostic, Int) -> Unit = { _, _ -> },
) : Closeable {
    private val live = AtomicBoolean(true)
    @Volatile private var socket: DatagramSocket? = null
    private val bytes = NearbyLocalWire.encode(NearbyLocalWire.senderListener, port)
    private val sends = NearbyBoundedCount()

    private fun report(code: NearbyDiagnostic) {
        // Diagnostics must never alter the foreground transfer or packet path.
        runCatching { onDiagnostic(code, sends.value()) }
    }

    fun start() {
        val broadcast = NearbyLocalWire.directedBroadcast(local, prefix)
        Thread({
            var bound = false
            var opened: DatagramSocket? = null
            try {
                val udp = DatagramSocket(null)
                opened = udp
                udp.broadcast = true
                udp.bind(InetSocketAddress(local, 0))
                bound = true
                socket = udp
                report(NearbyDiagnostic.HotspotBeaconBound) // Actual successful bind.
                val started = SystemClock.elapsedRealtime()
                while (live.get() && SystemClock.elapsedRealtime() - started < 120_000L) {
                    val advertised = DatagramPacket(
                        bytes, bytes.size, broadcast, NearbyLocalWire.discoveryPort
                    )
                    udp.send(advertised)
                    // A successful send() is not proof that the peer received it.
                    val count = sends.observed()
                    if (count == 1 || count == 64) report(NearbyDiagnostic.HotspotBeaconSent)
                    for (tick in 0 until 20) {
                        if (!live.get()) break
                        Thread.sleep(100)
                    }
                }
            } catch (_: Exception) {
                if (live.get()) report(classifyBeaconException(bound))
                // No default, cellular or VPN fallback on local broadcast failure.
            } finally {
                runCatching { opened?.close() }
                socket = null
                live.set(false)
            }
        }, "opendrop-hotspot-local-beacon").apply { isDaemon = true }.start()
    }

    override fun close() {
        live.set(false)
        socket?.close()
    }
}
