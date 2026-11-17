package org.opendrop.app

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.os.SystemClock

/** Small functional foreground sender. Android's OS supplies the source URI
 * grants; the only production transfer path is the Rust guest engine.
 *
 * One file and one exact owner-approved Offer per TLS session; a multi-share
 * proceeds sequentially, stopping at the first rejection. No unattended
 * background send, Wi-Fi/hotspot toggle, WAN route or foreground service.
 */
class ShareIngressActivity : Activity() {
    @Volatile private var bridge: AndroidGuestBridge? = null
    @Volatile private var sending = false
    @Volatile private var foreground = false
    private lateinit var status: TextView
    private lateinit var send: Button
    private lateinit var recover: Button
    private var discovery: NearbyLocalDiscovery? = null
    private data class SeenCandidate(
        val candidate: NearbyLocalWire.Candidate,
        val observedAtMs: Long,
    )
    private val nearby = linkedMapOf<String, SeenCandidate>()
    private var sources: List<SharedFile> = emptyList()
    private val nearbyStatus = NearbyStatusPolicy()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        var error: String? = null
        if (intent.action == android.content.Intent.ACTION_MAIN) {
            sources = emptyList() // recovery-only after restart; never resend automatically
        } else {
            try { sources = ShareSource.parse(intent, contentResolver) }
            catch (_: Exception) {
                error = "This share could not be opened: missing/revoked grant or unsupported content."
            }
        }

        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 40, 32, 24)
        }
        column.addView(TextView(this).apply {
            text = "OpenDrop · Send securely"
            textSize = 22f
        })
        column.addView(TextView(this).apply {
            text = if (error == null && sources.isEmpty())
                "Recover a previous completion without uploading again. Nearby receivers appear automatically."
            else if (error == null)
                sources.joinToString("\n") { "${it.name} · ${it.mime} · ${it.declaredSize?.toString() ?: "unknown size"}" } +
                    "\n\nEach file requires a fresh receiver approval. 64 MiB maximum per file."
            else error
            textSize = 15f
        })
        send = Button(this).apply {
            text = "Choose nearby recipient"
            isEnabled = sources.isNotEmpty()
            setOnClickListener { chooseRecipient(null) }
        }
        recover = Button(this).apply {
            text = "Recover an unresolved receipt"
            setOnClickListener { chooseRecovery() }
        }
        column.addView(send)
        column.addView(recover)
        column.addView(Button(this).apply {
            text = "Cancel and close connection"
            setOnClickListener {
                cancelTransfer()
                updateStatus("Cancelled; no automatic re-upload. Use recovery after uncertain completion.", terminal = true)
            }
        })
        status = TextView(this).apply {
            text = "Finding nearby OpenDrop devices. Unverified names cannot establish trust."
            textSize = 15f
        }
        column.addView(status)
        setContentView(ScrollView(this).apply { addView(column) })
    }

    private fun updateStatus(message: String, terminal: Boolean = false) {
        if (!nearbyStatus.accept(message, terminal)) return
        runOnUiThread {
            // Read the current monotonic policy, not a queued stale message.
            if (!isDestroyed) status.text = nearbyStatus.current()
        }
    }

    private fun cancelTransfer() {
        bridge?.cancel()
        runCatching { GuestNative.cancel() }
    }

    override fun onStart() {
        super.onStart()
        foreground = true
        if (!sending) {
            nearby.clear()
            val newDiscovery = NearbyLocalDiscovery(
                this,
                onCandidate = { candidate ->
                    runOnUiThread {
                        if (!isFinishing && !isDestroyed) {
                            nearby[candidate.address.hostAddress + ":" + candidate.port] =
                                SeenCandidate(candidate, SystemClock.elapsedRealtime())
                            while (nearby.size > 16) nearby.remove(nearby.keys.first())
                            updateStatus("${nearby.size} nearby candidate(s). " +
                                "Choose a recipient, then compare the ten-digit code on both devices.")
                        }
                    }
                },
                onUnavailable = { message ->
                    updateStatus("$message If your phone is hosting Wi-Fi, you can still share through the hotspot-local path.")
                }
            )
            discovery = newDiscovery
            runCatching { newDiscovery.start() }
                .onFailure { updateStatus("Nearby search unavailable. No file was sent.") }
        }
    }

    private fun chooseRecipient(recoveryId: String?) {
        if (sending || isFinishing || isDestroyed) return
        val now = SystemClock.elapsedRealtime()
        nearby.entries.removeAll { now - it.value.observedAtMs > 12_000L }
        val candidates = nearby.values
            .map { it.candidate }
            .filter { it.role == NearbyLocalWire.receiverListener }
            .distinctBy { it.address.hostAddress + ":" + it.port }
        if (candidates.isEmpty()) {
            // The source-scoped socket adapter verifies that the phone really
            // has ONE local AP interface. It refuses a Wi-Fi-client or
            // cellular-default fallback without a Linux peer connection.
            val title = if (recoveryId == null) "Share privately nearby" else "Recover result nearby"
            AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(
                    "No LAN receiver is discoverable. If this phone is hosting a local Wi-Fi hotspot, " +
                        "OpenDrop can briefly wait for one nearby receiver. It does not change your network. " +
                        "Verify the ten-digit code on BOTH devices before sharing."
                )
                .setPositiveButton("Wait for nearby device") { _, _ ->
                    startTransfer(recoveryId, null, true)
                }
                .setNegativeButton("Cancel", null)
                .show()
            return
        }
        // Candidate names/indices are UNTRUSTED. Selection only chooses
        // a local route, never a trusted identity or an Offer authorization.
        AlertDialog.Builder(this)
            .setTitle("Select nearby recipient")
            .setItems(candidates.mapIndexed { index, _ ->
                "Nearby OpenDrop device ${index + 1} (unverified)"
            }.toTypedArray()) { _, selected ->
                if (!isFinishing && !isDestroyed)
                    startTransfer(recoveryId, candidates[selected], false)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun chooseRecovery() {
        if (sending || isFinishing || isDestroyed) return
        try {
            val entries = ProtectedReceiptStore(this).pendingIds()
            if (entries.isEmpty()) {
                updateStatus("No unexpired pending receipts. Never resend an uncertain file blindly.")
                return
            }
            // Only the owner can choose the EXACT transfer ID. A second
            // unresolved record is never hidden by a global latest pointer.
            AlertDialog.Builder(this)
                .setTitle("Recover one existing committed receipt")
                .setItems(entries.toTypedArray()) { _, choice ->
                    if (!isFinishing && !isDestroyed)
                        chooseRecipient(entries[choice])
                }
                .setNegativeButton("Cancel", null)
                .show()
        } catch (_: Exception) {
            updateStatus("Pending receipts are unavailable; no file was re-uploaded.")
        }
    }

    private fun startTransfer(
        selectedRecoveryId: String?,
        recipient: NearbyLocalWire.Candidate?,
        reverseTcp: Boolean,
    ) {
        if (sending) return
        val recovery = selectedRecoveryId != null
        val host = if (reverseTcp) "auto" else recipient?.address?.hostAddress
        val number = if (reverseTcp) NearbyLocalWire.transferPort else recipient?.port
        if (host.isNullOrEmpty() || number != NearbyLocalWire.transferPort) {
            updateStatus("No permitted local OpenDrop recipient was discovered.")
            return
        }
        discovery?.close()
        discovery = null
        nearbyStatus.resetForOwnerAttempt()
        val localBridge = AndroidGuestBridge(this, sources) { code, count ->
            val message = if (code == NearbyDiagnostic.HotspotBeaconSent)
                "${code.label} (bounded count: $count)"
            else code.label
            updateStatus(message, terminal = code.terminalFailure)
        }
        bridge = localBridge
        sending = true
        send.isEnabled = false
        recover.isEnabled = false
        updateStatus(if (recovery) "Checking the exact committed receipt…" else "Hashing the granted source stream…")
        Thread({
            try {
                if (recovery) {
                    val id = selectedRecoveryId
                        ?.takeIf { it in localBridge.pendingRecoveryIds() }
                        ?: error("Selected recovery is unavailable. Never blindly reupload.")
                    val result = if (reverseTcp)
                            GuestNative.recoverHotspot(localBridge, id, host, number)
                    else GuestNative.recoverOne(localBridge, id, host, number)
                    updateStatus(result, terminal = true)
                } else {
                    for ((index, source) in sources.withIndex()) {
                        updateStatus("Preparing granted source ${index + 1}/${sources.size}; hotspot socket not yet selected.")
                        val result = if (reverseTcp)
                            GuestNative.sendHotspot(localBridge, index, source.name,
                                source.declaredSize ?: -1L, host, number)
                        else GuestNative.sendOne(
                            localBridge, index, source.name, source.declaredSize ?: -1L, host, number)
                        if (reverseTcp && !result.startsWith("OK:") &&
                            !localBridge.reachedHotspotSelection()) {
                            updateStatus(NearbyDiagnostic.PreNetworkFailed.label, terminal = true)
                        } else {
                            updateStatus(result, terminal =
                                !result.startsWith("OK:") || index == sources.lastIndex)
                        }
                        if (!result.startsWith("OK:")) break
                    }
                }
            } catch (_: Exception) {
                if (reverseTcp && !localBridge.reachedHotspotSelection())
                    updateStatus(NearbyDiagnostic.PreNetworkFailed.label, terminal = true)
                else updateStatus("Transfer unavailable or interrupted; no success claimed.", terminal = true)
            } catch (_: UnsatisfiedLinkError) {
                updateStatus("Native Rust guest engine is missing. This build cannot send.")
            } finally {
                localBridge.cancel()
                runOnUiThread {
                    sending = false
                    if (!isDestroyed) {
                        send.isEnabled = sources.isNotEmpty()
                        recover.isEnabled = true
                    }
                }
                bridge = null
                if (foreground && !isFinishing && !isDestroyed) runOnUiThread {
                    if (foreground && !isFinishing && !isDestroyed) onStartDiscoveryAgain()
                }
            }
        }, "opendrop-foreground-guest-sender").start()
    }

    private fun onStartDiscoveryAgain() {
        if (!foreground || discovery != null || sending || isFinishing || isDestroyed) return
        val next = NearbyLocalDiscovery(this, { candidate ->
            runOnUiThread {
                if (!isFinishing && !isDestroyed && !sending)
                    nearby[candidate.address.hostAddress + ":" + candidate.port] =
                        SeenCandidate(candidate, SystemClock.elapsedRealtime())
            }
        }, { updateStatus("Local discovery unavailable. No automatic WAN fallback.") })
        discovery = next
        runCatching { next.start() }
    }

    override fun onStop() {
        // A background Activity must not silently transmit files or keep a
        // sensitive SAS dialog alive. The encrypted token, if already
        // persisted after GuestReady, survives for manual receipt recovery.
        foreground = false
        if (sending) updateStatus(NearbyDiagnostic.ForegroundStopped.label, terminal = true)
        cancelTransfer()
        discovery?.close()
        discovery = null
        super.onStop()
    }

    override fun onDestroy() {
        cancelTransfer()
        super.onDestroy()
    }
}
