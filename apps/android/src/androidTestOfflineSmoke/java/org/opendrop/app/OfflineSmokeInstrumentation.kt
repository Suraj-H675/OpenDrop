package org.opendrop.app

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Process
import android.widget.Button
import android.widget.TextView
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicReference

/** The only hosted ART test runner for the network-disabled owner build.
 * The separate test-APK Java providers supply synthetic bytes and real
 * Android URI grants; they are never shipped in the owner-installed APK.
 */
class OfflineSmokeInstrumentation : Instrumentation() {
    private var phase = "unknown"
    private var stage = "start"

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        phase = arguments?.getString("phase") ?: "missing"
        start()
    }
    override fun onStart() {
        val results = Bundle()
        try {
            when (phase) {
                "prepare" -> prepare()
                "restart" -> restart()
                else -> error("unexpected phase")
            }
            results.putString("stream", "S1F_OFFLINE_ART_PASS:$phase")
            finish(Activity.RESULT_OK, results)
        } catch (error: Throwable) {
            results.putString("stream",
                "S1F_OFFLINE_ART_FAIL:$phase:$stage:${error.javaClass.simpleName}")
            finish(Activity.RESULT_CANCELED, results)
        }
    }
    private fun assertTest(ok: Boolean, reason: String) {
        if (!ok) throw AssertionError(reason)
    }
    private fun sha(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }
    private fun fileUri(name: String) =
        Uri.parse("content://org.opendrop.app.test.fixtures/$name")
    private fun grant(method: String) {
        val issued = targetContext.contentResolver.call(
            Uri.parse("content://org.opendrop.app.test.grants"), method, null, null)
        assertTest(issued?.getBoolean("issued") == true, "real cross-UID URI grant")
    }
    private fun shareIntent(vararg names: String): Intent {
        val action = if (names.size == 1) Intent.ACTION_SEND else Intent.ACTION_SEND_MULTIPLE
        return Intent(targetContext, OfflineSmokeActivity::class.java).apply {
            setAction(action)
            type = "text/plain"
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
            if (names.size == 1) putExtra(Intent.EXTRA_STREAM, fileUri(names.single()))
            else putParcelableArrayListExtra(Intent.EXTRA_STREAM,
                ArrayList(names.map(::fileUri)))
        }
    }
    private fun inspect(intent: Intent, expected: List<String>) {
        val activity = startActivitySync(intent) as OfflineSmokeActivity
        stage = "activity-owner-inspection"
        runOnMainSync {
            activity.findViewById<Button>(android.R.id.button1).performClick()
        }
        val started = System.currentTimeMillis()
        var status = ""
        while (System.currentTimeMillis() - started < 45_000L) {
            val current = AtomicReference("")
            runOnMainSync {
                current.set(activity.findViewById<TextView>(android.R.id.message).text.toString())
            }
            status = current.get()
            if (status.contains("OFFLINE PASS") || status.contains("OFFLINE FAIL")) break
            Thread.sleep(125)
        }
        assertTest(status.contains("OFFLINE PASS"), "genuine Activity offline inspection")
        expected.forEach { assertTest(status.contains(it), "expected source digest") }
        assertTest(!status.contains("Send with code") && !status.contains("Recover previous"),
            "no production sender controls in offline UI")
        stage = "owner-cancellation"
        runOnMainSync {
            activity.findViewById<Button>(android.R.id.button2).performClick()
        }
        val after = AtomicReference("")
        runOnMainSync {
            after.set(activity.findViewById<TextView>(android.R.id.message).text.toString())
            activity.finish()
        }
        assertTest(after.get().contains("Cancelled"), "owner cancellation is local")
    }
    private fun prepare() {
        val app = targetContext
        stage = "no-network-package"
        assertTest(app.packageName == "org.opendrop.app.s1fsmoke",
            "distinct owner offline application ID")
        @Suppress("DEPRECATION")
        val requested = app.packageManager.getPackageInfo(app.packageName, 4096)
            .requestedPermissions?.toList() ?: emptyList()
        assertTest("android.permission.INTERNET" !in requested &&
            "android.permission.ACCESS_NETWORK_STATE" !in requested,
            "offline APK must have no network permissions")
        stage = "production-p256-jni"
        val identity = GuestIdentity(app)
        val device = identity.installationId()
        val fingerprint = sha(identity.publicSpki())
        assertTest(identity.publicSpki().size == 91 &&
            GuestNative.identitySelfTest(AndroidGuestBridge(app)) == fingerprint,
            "genuine AndroidKeyStore + shared Rust P256 verification")

        stage = "real-uri-permissions"
        grant("grant")
        try {
            val source = ShareSource.parse(shareIntent("first"), app.contentResolver)
            assertTest(source.size == 1 && source[0].declaredSize == null,
                "unknown-length stream recognized")
            assertTest(runCatching {
                ShareSource.parse(Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"; putExtra(Intent.EXTRA_STREAM, fileUri("first"))
                }, app.contentResolver)
            }.isFailure, "missing URI grant flag must fail")
            assertTest(runCatching {
                ShareSource.openForRead(app.contentResolver,
                    SharedFile(fileUri("denied"), "denied.txt", null, "text/plain"))
                    .use { it.read() }
            }.isFailure, "explicit denied URI source must fail")
            stage = "actual-ui-single-unknown-length"
            inspect(shareIntent("first"),
                listOf(sha("hosted ContentResolver pipe #1".toByteArray()), "first.txt"))
            stage = "actual-ui-multi-uri"
            inspect(shareIntent("first", "second"), listOf(
                sha("hosted ContentResolver pipe #1".toByteArray()),
                sha("hosted ContentResolver pipe #2".toByteArray()), "second.txt"))
            stage = "actual-ui-empty-file"
            inspect(shareIntent("empty"), listOf(sha(ByteArray(0)), "0 bytes"))
            stage = "actual-ui-known-length"
            inspect(shareIntent("known"), listOf(
                sha("hosted known-length source".toByteArray()), "26 bytes"))
        } finally {
            grant("revoke")
        }
        stage = "revoke-and-no-leak"
        assertTest(runCatching {
            ShareSource.openForRead(app.contentResolver,
                SharedFile(fileUri("first"), "first.txt", null, "text/plain"))
                .use { it.read() }
        }.isFailure, "revoked URI permission fail closed")
        assertTest(app.getSharedPreferences("s1f_offline_art", Context.MODE_PRIVATE).edit()
            .putString("device", device).putString("fingerprint", fingerprint)
            .putInt("pid", Process.myPid()).commit(), "public-only process-restart evidence")
    }
    private fun restart() {
        stage = "real-process-restart"
        val app = targetContext
        val saved = app.getSharedPreferences("s1f_offline_art", Context.MODE_PRIVATE)
        assertTest(saved.getInt("pid", -1) > 0 &&
            saved.getInt("pid", -1) != Process.myPid(), "not a new ART process")
        val identity = GuestIdentity(app)
        val fingerprint = sha(identity.publicSpki())
        assertTest(identity.installationId() == saved.getString("device", null) &&
            fingerprint == saved.getString("fingerprint", null),
            "original protected installation identity unchanged")
        assertTest(GuestNative.identitySelfTest(AndroidGuestBridge(app)) == fingerprint,
            "real native signer proof after app process restart")
    }
}
