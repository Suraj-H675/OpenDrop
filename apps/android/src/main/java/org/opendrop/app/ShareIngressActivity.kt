package org.opendrop.app

import android.app.Activity
import android.os.Bundle
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Button

/** Native Sharesheet activation boundary; production Nearby UI is not yet wired. */
class ShareIngressActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The intent and its transient grant must outlive recipient selection.
        // Do not signal a successful share until the later transfer engine ACKs.
        val source = try { ShareSource.parse(intent, contentResolver).single() }
        catch (_: Exception) { null }
        val message = if (source == null) "This share cannot be opened by OpenDrop yet."
            else "${source.name}\n\nOpenDrop Nearby selection is not available in this foundation build."
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 40, 32, 24)
        }
        content.addView(TextView(this).apply { text = message; textSize = 18f })
        content.addView(Button(this).apply {
            text = "Close"
            setOnClickListener { finish() }
        })
        setContentView(content)
        // No file bytes copied, no result claiming a transfer, and no
        // broad permission request. Round 03/04 native Nearby UI is next.
    }
}
