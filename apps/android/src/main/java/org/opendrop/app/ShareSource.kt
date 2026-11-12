package org.opendrop.app

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns

/** A one-file source granted by the sending app; never a filesystem path. */
internal data class SharedFile(val uri: Uri, val name: String, val declaredSize: Long?)

/** Uses only the explicit ACTION_SEND/ACTION_SEND_MULTIPLE URI grants. */
internal object ShareSource {
    fun parse(intent: Intent, resolver: ContentResolver): List<SharedFile> {
        val action = intent.action
        require(action == Intent.ACTION_SEND || action == Intent.ACTION_SEND_MULTIPLE) {
            "Not an Android file share"
        }
        val uris: List<Uri> = if (action == Intent.ACTION_SEND) {
            listOfNotNull(stream(intent))
        } else {
            streams(intent)
        }
        // The first production vertical slice is one file. No silent omission
        // of additional items; the full Level 1 multi-file path is later.
        require(uris.size == 1) { "Share one file in this early integration build" }
        return uris.map { uri ->
            require(uri.scheme == ContentResolver.SCHEME_CONTENT && !uri.authority.isNullOrEmpty()) {
                "Only explicitly granted content URIs are accepted"
            }
            val details = resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null, null, null)?.use { cursor ->
                if (!cursor.moveToFirst()) null else {
                    val nameColumn = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    val sizeColumn = cursor.getColumnIndex(OpenableColumns.SIZE)
                    val name = if (nameColumn >= 0 && !cursor.isNull(nameColumn))
                        cursor.getString(nameColumn) else null
                    val size = if (sizeColumn >= 0 && !cursor.isNull(sizeColumn))
                        cursor.getLong(sizeColumn) else null
                    Pair(name, size)
                }
            }
            val name = details?.first ?: "Untitled file"
            require(name.isNotBlank() && name.length <= 255 &&
                name != "." && name != ".." &&
                name.none { it == '/' || it == '\\' || Character.isISOControl(it) }) {
                "Source provider returned an unsafe file name"
            }
            val size = details?.second
            require(size == null || size >= 0L) { "Invalid source-provider size" }
            SharedFile(uri, name, size)
        }
    }

    /** Reopen while the transient URI grant remains valid; never assume path access. */
    fun openForRead(resolver: ContentResolver, source: SharedFile) =
        resolver.openFileDescriptor(source.uri, "r") ?: error("Source provider denied read")

    @Suppress("DEPRECATION")
    private fun stream(intent: Intent): Uri? =
        if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        else intent.getParcelableExtra(Intent.EXTRA_STREAM)

    @Suppress("DEPRECATION")
    private fun streams(intent: Intent): List<Uri> =
        if (Build.VERSION.SDK_INT >= 33)
            intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java) ?: emptyList()
        else intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM) ?: emptyList()
}
