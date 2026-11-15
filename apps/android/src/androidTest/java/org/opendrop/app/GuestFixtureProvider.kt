package org.opendrop.app

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.FileNotFoundException

/** AndroidTest APK only: real ContentResolver pipe/grant, no fixture in app. */
class GuestFixtureProvider : ContentProvider() {
    override fun onCreate() = true
    override fun getType(uri: Uri): String = "text/plain"
    override fun query(
        uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?,
    ): Cursor {
        val name = when (uri.lastPathSegment) {
            "first" -> "first.txt"
            "second" -> "second.txt"
            "denied" -> "denied.txt"
            else -> throw FileNotFoundException("not a fixture URI")
        }
        return MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)).apply {
            addRow(arrayOf(name, -1L))
        }
    }
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r" || uri.lastPathSegment == "denied") {
            throw FileNotFoundException("fixture denied")
        }
        val data = when (uri.lastPathSegment) {
            "first" -> "hosted ContentResolver pipe #1".toByteArray()
            "second" -> "hosted ContentResolver pipe #2".toByteArray()
            else -> throw FileNotFoundException("fixture unavailable")
        }
        val pipe = ParcelFileDescriptor.createPipe()
        Thread({
            ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]).use { it.write(data) }
        }, "hosted-fixture-writer").start()
        return pipe[0]
    }
    override fun insert(uri: Uri, values: ContentValues?): Uri? =
        throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException()
}
