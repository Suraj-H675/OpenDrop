package org.opendrop.app

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

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
    private lateinit var status: TextView
    private lateinit var endpoint: EditText
    private lateinit var port: EditText
    private lateinit var send: Button
    private lateinit var recover: Button
    private var sources: List<SharedFile> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        var error: String? = null
        try { sources = ShareSource.parse(intent, contentResolver) }
        catch (_: Exception) { error = "This share could not be opened: missing/revoked grant or unsupported content." }

        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 40, 32, 24)
        }
        column.addView(TextView(this).apply {
            text = "OpenDrop · Send securely"
            textSize = 22f
        })
        column.addView(TextView(this).apply {
            text = if (error == null)
                sources.joinToString("\n") { "${it.name} · ${it.mime} · ${it.declaredSize?.toString() ?: "unknown size"}" } +
                    "\n\nEach file requires a fresh receiver approval. 64 MiB maximum per file."
            else error
            textSize = 15f
        })
        endpoint = EditText(this).apply {
            hint = "Receiver's private LAN IPv4 (manual)"
            setSingleLine()
            inputType = android.text.InputType.TYPE_CLASS_PHONE
        }
        port = EditText(this).apply {
            hint = "Port of receiver listener"
            setText("43991")
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            setSingleLine()
        }
        column.addView(endpoint)
        column.addView(port)
        send = Button(this).apply {
            text = "Send with code verification"
            isEnabled = sources.isNotEmpty()
            setOnClickListener { startTransfer(false) }
        }
        recover = Button(this).apply {
            text = "Recover previous completion"
            setOnClickListener { startTransfer(true) }
        }
        column.addView(send)
        column.addView(recover)
        column.addView(Button(this).apply {
            text = "Cancel and close connection"
            setOnClickListener {
                cancelTransfer()
                updateStatus("Cancelled; no automatic re-upload. Use recovery after uncertain completion.")
            }
        })
        status = TextView(this).apply {
            text = "Select the local receiver and compare the displayed SAS on both devices."
            textSize = 15f
        }
        column.addView(status)
        setContentView(ScrollView(this).apply { addView(column) })
    }

    private fun updateStatus(message: String) {
        runOnUiThread {
            if (!isDestroyed) status.text = message
        }
    }

    private fun cancelTransfer() {
        bridge?.cancel()
        runCatching { GuestNative.cancel() }
    }

    private fun startTransfer(recovery: Boolean) {
        if (sending) return
        val host = endpoint.text.toString().trim()
        val number = port.text.toString().toIntOrNull()
        if (number == null || number !in 1..65535 || host.isBlank()) {
            updateStatus("Enter an explicit private LAN IP and a valid port.")
            return
        }
        val localBridge = AndroidGuestBridge(this, sources)
        bridge = localBridge
        sending = true
        send.isEnabled = false
        recover.isEnabled = false
        updateStatus(if (recovery) "Checking the exact committed receipt…" else "Hashing the granted source stream…")
        Thread({
            try {
                if (recovery) {
                    val id = localBridge.latestRecovery()
                        ?: error("No unexpired recovery record. Do not reupload an uncertain transfer blindly.")
                    val result = GuestNative.recoverOne(localBridge, id, host, number)
                    updateStatus(result)
                } else {
                    for ((index, source) in sources.withIndex()) {
                        updateStatus("Sending ${index + 1}/${sources.size}: ${source.name}. Verify the same code on the receiver.")
                        val result = GuestNative.sendOne(
                            localBridge, index, source.name, source.declaredSize ?: -1L, host, number)
                        updateStatus(result)
                        if (!result.startsWith("OK:")) break
                    }
                }
            } catch (_: Exception) {
                updateStatus("Transfer unavailable or interrupted. No success claimed; check pending recovery.")
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
            }
        }, "opendrop-foreground-guest-sender").start()
    }

    override fun onStop() {
        // A background Activity must not silently transmit files or keep a
        // sensitive SAS dialog alive. The encrypted token, if already
        // persisted after GuestReady, survives for manual receipt recovery.
        cancelTransfer()
        super.onStop()
    }

    override fun onDestroy() {
        cancelTransfer()
        super.onDestroy()
    }
}
