package org.opendrop.app

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import java.io.ByteArrayInputStream
import java.io.InputStream

/** A single scoped URI, or a bounded explicit text share. Never a file path. */
data class SharedFile(
    val uri: Uri?,
    val name: String,
    val declaredSize: Long?,
    val mime: String,
    val inlineText: ByteArray? = null,
)

/** Retain URI grants solely for the foreground Activity. Never assume a
 * persistable grant, copy a complete file into RAM, or drop additional items.
 */
internal object ShareSource {
    private const val MAX_ITEMS = 16
    private const val MAX_BYTES = 64L * 1024L * 1024L
    private const val MAX_TEXT = 64 * 1024

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
        if (uris.isEmpty() && action == Intent.ACTION_SEND) {
            val text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
                ?: error("The sending app did not provide an accessible file or text")
            val bytes = text.toByteArray(Charsets.UTF_8)
            require(bytes.isNotEmpty() && bytes.size <= MAX_TEXT) { "Text share is too large" }
            return listOf(SharedFile(null, "Shared text.txt", bytes.size.toLong(), "text/plain", bytes))
        }
        require(intent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0) {
            "Sending app did not grant scoped read permission"
        }
        require(uris.isNotEmpty() && uris.size <= MAX_ITEMS) {
            "Select between 1 and 16 files"
        }
        require(uris.distinct().size == uris.size) { "Repeated share URI" }
        return uris.mapIndexed { index, uri ->
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
            val name = details?.first ?: "Shared file ${index + 1}.bin"
            require(name.isNotBlank() && name.toByteArray(Charsets.UTF_8).size <= 255 &&
                name != "." && name != ".." && !name.startsWith(".") &&
                !name.endsWith(" ") && !name.endsWith(".") &&
                name.none { it == '/' || it == '\\' || it == ':' || Character.isISOControl(it) }) {
                "Source provider returned an unsafe file name"
            }
            // SIZE is optional and some providers use -1 for unknown-length
            // pipes. Prehash the bounded stream; never guess/truncate.
            val size = details?.second?.takeIf { it >= 0L }
            require(size == null || size <= MAX_BYTES) { "File exceeds 64 MiB" }
            val mime = (resolver.getType(uri) ?: intent.type ?: "application/octet-stream")
                .takeIf { it.length in 3..128 && !it.any(Char::isISOControl) }
                ?: "application/octet-stream"
            SharedFile(uri, name, size, mime)
        }
    }

    /** Reopen while the transient URI grant remains valid; never assume path access. */
    fun openForRead(resolver: ContentResolver, source: SharedFile): InputStream =
        source.inlineText?.let { ByteArrayInputStream(it) }
            ?: resolver.openInputStream(source.uri ?: error("Missing source URI"))
            ?: error("Source provider denied read")

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
