package org.opendrop.app

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.widget.TextView
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** App-owned Android trust, ContentResolver and LAN-route boundary.
 *
 * Every native socket is created by a selected Wi-Fi/Ethernet Network's own
 * socket factory, and only after an explicit directly-connected private IPv4
 * route is verified. We DO NOT bind the process, touch hotspot/Wi-Fi config,
 * silently fall back to cellular/VPN, or use a DNS resolver.
 *
 * This strict first vertical may refuse Android-hotspot-host topology. Later
 * source-specific routing is a separate feature/physical feasibility gate.
 */
class AndroidGuestBridge(
    private val activity: Activity,
    private val shares: List<SharedFile>,
) {
    private val cancelled = AtomicBoolean(false)
    private val identity = GuestIdentity(activity)
    private val receipts = ProtectedReceiptStore(activity)
    private var activeSocket: Socket? = null
    private var activeParcel: ParcelFileDescriptor? = null
    @Volatile private var activeListener: ServerSocket? = null
    @Volatile private var connectingSocket: Socket? = null
    @Volatile private var sourceStream: InputStream? = null

    fun installationId(): String = identity.installationId()
    fun publicSpki(): ByteArray = identity.publicSpki()
    fun signP256Sha256(message: ByteArray): ByteArray = identity.signP256Sha256(message)
    fun sealRecovery(id: String, expiresMs: Long, plaintext: ByteArray): Boolean =
        receipts.sealRecovery(id, expiresMs, plaintext)
    fun unsealRecovery(id: String): ByteArray? = receipts.unsealRecovery(id)
    fun clearRecovery(id: String): Boolean = receipts.clearRecovery(id)
    fun latestRecovery(): String? = receipts.latestPending()
    fun pendingRecoveryIds(): List<String> = receipts.pendingIds()

    @Synchronized
    fun openSource(index: Int) {
        check(!cancelled.get() && index in shares.indices) { "Source no longer permitted" }
        closeSource()
        sourceStream = ShareSource.openForRead(activity.contentResolver, shares[index])
    }

    fun sourceChunk(max: Int): ByteArray? {
        check(!cancelled.get() && max in 1..32768)
        val source = sourceStream ?: error("No open content URI")
        val data = ByteArray(max)
        val count = source.read(data)
        check(count != 0) { "Content provider did not make progress" }
        return if (count == -1) null else data.copyOf(count)
    }

    @Synchronized
    fun closeSource() {
        runCatching { sourceStream?.close() }
        sourceStream = null
    }

    private fun privateIPv4(text: String): InetAddress {
        val pieces = text.split('.')
        require(pieces.size == 4 && pieces.all { it.isNotEmpty() && it.length <= 3
            && it.all(Char::isDigit) && (it.length == 1 || it[0] != '0') }) {
            "Enter a numeric private IPv4 address; no DNS/WAN"
        }
        val bytes = pieces.map { part ->
            val n = part.toInt()
            require(n in 0..255) { "Invalid IPv4" }
            n
        }
        val localOnly = bytes[0] == 10 ||
            (bytes[0] == 172 && bytes[1] in 16..31) ||
            (bytes[0] == 192 && bytes[1] == 168)
        require(localOnly && bytes[3] in 1..254) { "Public, loopback and WAN routes prohibited" }
        return InetAddress.getByAddress(bytes.map(Int::toByte).toByteArray())
    }

    fun openLanSocket(host: String, port: Int): Int {
        check(!cancelled.get()) { "Foreground sender was cancelled" }
        require(port in 1..65535)
        val peer = privateIPv4(host)
        val manager = activity.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        // NetworkCapabilities + a real directly-connected route are required.
        // A network whose only private route is a VPN/default gateway cannot
        // be used to accidentally send through cellular or an Internet path.
        val available = manager.allNetworks.filter { network ->
            val capabilities = manager.getNetworkCapabilities(network) ?: return@filter false
            val hasLanTransport = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
            val links = manager.getLinkProperties(network) ?: return@filter false
            hasLanTransport && !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                // RouteInfo.hasGateway() is API 29; use the API 21
                // gateway property for every supported Android version.
                // An absent/unspecified gateway is directly connected.
                links.routes.any { route ->
                    route.matches(peer) && !route.isDefaultRoute &&
                        (route.gateway?.isAnyLocalAddress != false)
                }
        }
        require(available.size == 1) {
            "No unambiguous Wi-Fi/Ethernet route directly to this peer; cellular fallback disabled"
        }
        closeNetwork()
        val socket = available.single().socketFactory.createSocket()
        synchronized(this) {
            check(!cancelled.get() && connectingSocket == null &&
                activeSocket == null && activeListener == null)
            connectingSocket = socket
        }
        try {
            socket.connect(InetSocketAddress(peer, port), 8000)
            check(!cancelled.get()) { "Foreground session was cancelled" }
            socket.soTimeout = 250
            // Android API 26–28: fromSocket() may borrow an original fd.
            // dup() gives Rust its own fd; keep the wrapper and Socket alive
            // until cancellation rather than allowing premature GC.
            val parcel = ParcelFileDescriptor.fromSocket(socket)
            val descriptor = parcel.dup().detachFd()
            synchronized(this) {
                check(!cancelled.get())
                activeSocket = socket
                activeParcel = parcel
            }
            return descriptor
        } catch (error: Exception) {
            socket.close()
            throw error
        } finally {
            synchronized(this) {
                if (connectingSocket === socket) connectingSocket = null
            }
        }
    }

    /** TCP ACCEPTOR, but TLS CLIENT and logical FILE SENDER. Nothing binds
     * until the owner explicitly selects the one-shot hotspot-host action.
     * Never trust the cellular default Network or an AP-dependent NetworkAgent.
     * A concrete interface address, direct subnet and exact peer are mandatory.
     */
    fun acceptHotspotSocket(peerText: String, port: Int): Int {
        check(!cancelled.get()) { "Foreground sender was cancelled" }
        require(port in 1..65535)
        val peer = privateIPv4(peerText)
        // Hotspot downstream is not exposed as an Android Wi-Fi Network on
        // many OEMs. Select only a nonvirtual Wi-Fi AP interface whose
        // actual InterfaceAddress prefix contains the explicit Linux peer.
        val interfaces = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        val eligible = interfaces.filter { iface ->
            val name = iface.name.orEmpty()
            (name.startsWith("wlan") || name.startsWith("ap") ||
                name.startsWith("swlan") || name.startsWith("tether")) &&
                iface.isUp && !iface.isLoopback && !iface.isVirtual &&
                !iface.isPointToPoint
        }.flatMap { iface ->
            iface.interfaceAddresses.mapNotNull { address ->
                val local = address.address
                val prefix = address.networkPrefixLength.toInt()
                if (local !is java.net.Inet4Address || prefix !in 16..30 ||
                    !local.isSiteLocalAddress || local == peer) null
                else {
                    val mask = (-1 shl (32 - prefix))
                    val a = local.address.fold(0) { n, b -> (n shl 8) or (b.toInt() and 255) }
                    val b = peer.address.fold(0) { n, octet -> (n shl 8) or (octet.toInt() and 255) }
                    if ((a and mask) == (b and mask)) local else null
                }
            }
        }.distinct()
        require(eligible.size == 1) {
            "No unique, directly attached private hotspot Wi-Fi interface for this peer"
        }
        val local = eligible.single()
        // Binding only this local address prevents an accidental WAN,
        // wildcard, cellular, USB-forwarded or VPN listener.
        val listener = ServerSocket()
        try {
            listener.reuseAddress = false
            listener.bind(InetSocketAddress(local, port), 1)
            listener.soTimeout = 250
            check(!cancelled.get()) { "Foreground session cancelled" }
            synchronized(this) {
                check(activeListener == null && activeSocket == null && !cancelled.get())
                activeListener = listener
            }
            val end = SystemClock.elapsedRealtime() + 120_000L
            var accepted: Socket? = null
            while (!cancelled.get() && SystemClock.elapsedRealtime() < end) {
                accepted = try { listener.accept() }
                catch (_: SocketTimeoutException) { continue }
                break
            }
            val incoming = accepted ?: error("Owner foreground hotspot listener timed out/cancelled")
            try {
                check(!cancelled.get() &&
                    incoming.inetAddress == peer && incoming.localAddress == local) {
                    "Unexpected source or destination; guest rejected before TLS"
                }
                // The AP may disappear while the owner inspects their phone.
                val stillLocal = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
                    .any { it.isUp && !it.isLoopback &&
                        it.interfaceAddresses.any { address -> address.address == local } }
                check(stillLocal) { "Hotspot-local interface disappeared" }
                incoming.soTimeout = 250
                val parcel = ParcelFileDescriptor.fromSocket(incoming)
                val descriptor = parcel.dup().detachFd()
                synchronized(this) {
                    check(!cancelled.get())
                    activeSocket = incoming
                    activeParcel = parcel
                }
                return descriptor
            } catch (error: Exception) {
                incoming.close()
                throw error
            }
        } finally {
            synchronized(this) { if (activeListener === listener) activeListener = null }
            runCatching { listener.close() }
        }
    }

    @Synchronized
    private fun closeNetwork() {
        runCatching { connectingSocket?.close() }
        runCatching { activeSocket?.close() }
        runCatching { activeParcel?.close() }
        activeSocket = null
        activeParcel = null
    }

    /** Synchronous JNI callback on a worker thread; genuine GUI button
     * events are dispatched on the Activity main thread. The response is
     * deliberately a one-time local human gesture, never from peer bytes.
     */
    fun confirmSas(code: String, fingerprint: String): Boolean {
        if (cancelled.get() || code.length != 11 || fingerprint.length != 64) return false
        val finished = CountDownLatch(1)
        val accepted = AtomicBoolean(false)
        var dialog: AlertDialog? = null
        activity.runOnUiThread {
            if (cancelled.get() || activity.isFinishing || activity.isDestroyed) {
                finished.countDown()
            } else {
                val details = TextView(activity).apply {
                    text = "Compare the code with the receiving device.\n\n" +
                        code + "\n\nPeer key:\n" + fingerprint +
                        "\n\nChoose Codes match ONLY when both humans confirm."
                    textSize = 17f
                    setPadding(24, 16, 24, 16)
                    setTextIsSelectable(true)
                }
                dialog = AlertDialog.Builder(activity)
                    .setTitle("Verify guest device")
                    .setView(details)
                    .setPositiveButton("Codes match") { _, _ ->
                        if (!cancelled.get()) accepted.set(true)
                        finished.countDown()
                    }
                    .setNegativeButton("Codes differ") { _, _ -> finished.countDown() }
                    .setOnCancelListener { finished.countDown() }
                    .create()
                dialog?.show()
            }
        }
        val end = SystemClock.elapsedRealtime() + 120_000L
        while (!cancelled.get() && SystemClock.elapsedRealtime() < end) {
            if (finished.await(250, TimeUnit.MILLISECONDS)) break
        }
        activity.runOnUiThread { dialog?.dismiss() }
        return !cancelled.get() && finished.count == 0L && accepted.get() &&
            SystemClock.elapsedRealtime() < end
    }

    fun cancel() {
        cancelled.set(true)
        // Close the blocking acceptor BEFORE waiting on the monitor. A
        // stalled connect/source reader cannot delay cancellation of it.
        runCatching { activeListener?.close() }
        runCatching { connectingSocket?.close() }
        runCatching { activeSocket?.close() }
        synchronized(this) {
            closeNetwork()
            closeSource()
        }
    }
}
