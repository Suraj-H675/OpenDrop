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
import java.net.Socket
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

    @Synchronized
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
        try {
            socket.connect(InetSocketAddress(peer, port), 8000)
            socket.soTimeout = 250
            // Android API 26–28: fromSocket() may borrow an original fd.
            // dup() gives Rust its own fd; keep the wrapper and Socket alive
            // until cancellation rather than allowing premature GC.
            val parcel = ParcelFileDescriptor.fromSocket(socket)
            val descriptor = parcel.dup().detachFd()
            activeSocket = socket
            activeParcel = parcel
            return descriptor
        } catch (error: Exception) {
            socket.close()
            throw error
        }
    }

    @Synchronized
    private fun closeNetwork() {
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
        synchronized(this) {
            closeNetwork()
            closeSource()
        }
    }
}
