package org.opendrop.app

import android.content.ContentResolver
import android.content.ContentValues
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore

/** Native user-accessible destination for API 29+. Not an app-private lab path.
 *
 * This is only the storage adapter boundary. Its caller MUST first persist a
 * commit-intent record and verify received bytes/hash before publish, then
 * persist a committed receipt before informing the sender of Complete.
 * Those engine/FFI/lifecycle links are not implemented in P1-A.
 */
internal class DownloadsDestination(private val resolver: ContentResolver) {
    fun createPending(name: String, mime: String): Uri {
        // Android Lint and ART both need a real branch guarding API-29
        // MediaStore.Downloads on our minSdk 26 build. Kotlin require()
        // does not make later API calls statically safe.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            throw UnsupportedOperationException("Requires scoped MediaStore downloads")
        }
        require(name.isNotBlank() && name.length <= 255 &&
            name != "." && name != ".." &&
            name.none { it == '/' || it == '\\' || Character.isISOControl(it) }) { "Unsafe file name" }
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, name)
            put(MediaStore.Downloads.MIME_TYPE, mime)
            put(MediaStore.Downloads.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/OpenDrop/")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        return resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: error("Android refused to create a pending Downloads item")
    }

    fun openPendingForWrite(uri: Uri) =
        resolver.openFileDescriptor(uri, "w") ?: error("Pending Downloads item unavailable")

    fun publishAfterVerifiedCommit(uri: Uri) {
        val values = ContentValues().apply { put(MediaStore.Downloads.IS_PENDING, 0) }
        check(resolver.update(uri, values, null, null) == 1) { "Cannot publish verified item" }
    }

    fun abortOwnedPending(uri: Uri) { resolver.delete(uri, null, null) }
}
