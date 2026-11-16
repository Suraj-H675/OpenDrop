package org.opendrop.app

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.view.View
import java.io.InputStream
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owner-operated, deliberately network-incapable diagnostic.
 * Compiled only into offlineSmoke (unique package, no INTERNET permission).
 * Real production ContentResolver parsing and streaming; real production
 * AndroidKeyStore identity through the actual shared Rust JNI self-test.
 */
class OfflineSmokeActivity : Activity() {
    private val cancelled = AtomicBoolean(false)
    @Volatile private var stream: InputStream? = null
    @Volatile private var runGeneration = 0
    private lateinit var status: TextView
    private lateinit var details: TextView
    private lateinit var inspect: Button
    private var files: List<SharedFile> = emptyList()
    private val maxBytes = 64L * 1024L * 1024L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val error = try {
            files = when (intent.action) {
                Intent.ACTION_SEND, Intent.ACTION_SEND_MULTIPLE ->
                    ShareSource.parse(intent, contentResolver)
                else -> emptyList()
            }
            null
        } catch (_: Exception) {
            "The sending app did not grant usable files. No bytes were read."
        }
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(28, 36, 28, 28)
        }
        column.addView(TextView(this).apply {
            text = "OpenDrop · OFFLINE TEST"
            textSize = 23f
        })
        column.addView(TextView(this).apply {
            text = "LOCAL ONLY · No Internet permission, no Send/Recover or peer connection. " +
                "Only share new synthetic files. Data is hashed in memory, not copied or uploaded."
            textSize = 15f
        })
        details = TextView(this).apply {
            text = error ?: if (files.isEmpty())
                "Use Files → Share → OpenDrop OFFLINE TEST to inspect synthetic files."
            else files.joinToString("\n") {
                "${it.name} · ${it.mime} · ${it.declaredSize?.toString() ?: "unknown size"}"
            }
            textSize = 15f
        }
        column.addView(details)
        inspect = Button(this).apply {
            id = android.R.id.button1
            text = "Verify Keystore + JNI and hash shared files"
            isEnabled = error == null
            setOnClickListener { performOfflineInspection() }
        }
        column.addView(inspect)
        column.addView(Button(this).apply {
            id = android.R.id.button2
            text = "Cancel / Close offline test"
            setOnClickListener {
                cancelWork()
                status.text = "Cancelled. No shared file was stored or transferred."
            }
        })
        status = TextView(this).apply {
            id = android.R.id.message
            text = "No verification started."
            textSize = 15f
            setTextIsSelectable(true)
        }
        column.addView(status)
        setContentView(ScrollView(this).apply { addView(column) })
    }

    private fun updateStatus(generation: Int, text: String) = runOnUiThread {
        if (!isDestroyed && !cancelled.get() && runGeneration == generation) status.text = text
    }

    private fun cancelWork() {
        cancelled.set(true)
        runGeneration++
        // Only this Activity's borrowed, owner-shared ContentResolver stream.
        runCatching { stream?.close() }
        stream = null
    }

    private fun performOfflineInspection() {
        cancelWork() // invalidate any prior operation without re-opening it
        cancelled.set(false)
        val generation = ++runGeneration
        inspect.isEnabled = false
        status.text = "Verifying real AndroidKeyStore P-256 and native Rust JNI…"
        Thread({
            try {
                val bridge = AndroidGuestBridge(applicationContext)
                val spki = bridge.publicSpki()
                check(spki.size == 91) { "Noncanonical installation identity" }
                val fingerprint = MessageDigest.getInstance("SHA-256").digest(spki).hex()
                val native = GuestNative.identitySelfTest(bridge)
                check(native == fingerprint) { "Rust/Android identity proof failed" }
                check(!cancelled.get() && generation == runGeneration)
                val report = StringBuilder("Real P-256 AndroidKeyStore + Rust JNI: PASS\n")
                    .append("Public identity: ").append(fingerprint.take(16)).append("…\n")
                if (files.isEmpty()) report.append("No synthetic files shared yet.\n")
                for ((index, file) in files.withIndex()) {
                    check(!cancelled.get() && generation == runGeneration)
                    val digest = MessageDigest.getInstance("SHA-256")
                    var total = 0L
                    ShareSource.openForRead(contentResolver, file).use { input ->
                        stream = input
                        val buffer = ByteArray(32 * 1024)
                        while (true) {
                            check(!cancelled.get() && generation == runGeneration)
                            val read = input.read(buffer)
                            if (read == -1) break
                            check(read > 0) { "Source provider stopped making progress" }
                            total += read
                            check(total <= maxBytes) { "Synthetic file exceeds 64 MiB" }
                            digest.update(buffer, 0, read)
                        }
                        buffer.fill(0)
                    }
                    stream = null
                    check(file.declaredSize == null || total == file.declaredSize) {
                        "Source length differs from declared length"
                    }
                    report.append("${index + 1}. ").append(file.name)
                        .append(" · ").append(total).append(" bytes · SHA-256 ")
                        .append(digest.digest().hex()).append('\n')
                    updateStatus(generation, report.toString())
                }
                updateStatus(generation, report.append("OFFLINE PASS · No TCP or file transfer.").toString())
            } catch (_: Throwable) {
                updateStatus(generation,
                    "OFFLINE FAIL · Identity, URI access, cancellation or size verification failed. " +
                    "No transfer occurred.")
            } finally {
                stream = null
                runOnUiThread {
                    if (!isDestroyed && generation == runGeneration) {
                        inspect.isEnabled = true
                    }
                }
            }
        }, "opendrop-offline-synthetic-file-hash").start()
    }

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }

    override fun onStop() {
        cancelWork()
        super.onStop()
    }
    override fun onDestroy() {
        cancelWork()
        super.onDestroy()
    }
}
