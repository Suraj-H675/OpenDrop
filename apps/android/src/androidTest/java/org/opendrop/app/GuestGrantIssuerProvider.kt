package org.opendrop.app

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Bundle

/** Disposable test APK only. A test provider must grant *its own* URI:
 * instrumentation executes as the target app UID and cannot issue grants
 * for the test APK's protected source provider (Android correctly rejects
 * that with SecurityException). This issuer executes in the provider's UID
 * and grants only three hardcoded synthetic test URI paths, only to OpenDrop.
 */
class GuestGrantIssuerProvider : ContentProvider() {
    private val paths = listOf("first", "second", "denied")
    override fun onCreate(): Boolean = true
    override fun getType(uri: Uri): String? = null
    override fun query(
        uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?,
    ): Cursor? = null

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle {
        val context = requireNotNull(context)
        // This issuer is exported ONLY from an ephemeral androidTest APK.
        // Still enforce the target UID; other apps cannot request even these
        // synthetic URI grants.
        // Android verifies getCallingPackage() against the Binder UID.
        // Unlike PackageManager.getPackageUid(), this does not rely on
        // Android 11+ unrelated-package visibility rules.
        require(callingPackage == "org.opendrop.app") {
            "Not the OpenDrop instrumentation target"
        }
        require(arg == null && extras == null && (method == "grant" || method == "revoke"))
        for (path in paths) {
            val fixture = Uri.parse("content://org.opendrop.app.test.fixtures/$path")
            if (method == "grant") {
                context.grantUriPermission(
                    "org.opendrop.app", fixture, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            } else {
                context.revokeUriPermission(
                    fixture, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        }
        return Bundle().apply { putBoolean("issued", true) }
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? =
        throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException()
    override fun update(
        uri: Uri, values: ContentValues?, selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = throw UnsupportedOperationException()
}
