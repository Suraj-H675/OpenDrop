package org.opendrop.app

import android.app.Activity
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Process
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.net.Inet4Address
import java.net.InetAddress
import android.view.View
import android.view.ViewGroup
import android.widget.EditText

/** Real Android ART instrumentation. Invoke twice with a force-stop between:
 * phase=prepare then phase=restart. Never substitutes fake JNI or keys.
 */
class GuestRuntimeInstrumentation : Instrumentation() {
    private var phase = ""
    // Public test-only checkpoints permit precise runtime diagnosis without
    // exposing device identifiers, URI metadata, credential bytes or logs.
    private var checkpoint = "instrumentation-start"
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        phase = arguments?.getString("phase") ?: "missing"
        start()
    }
    override fun onStart() {
        val output = Bundle()
        try {
            when (phase) {
                "prepare" -> prepare()
                "restart" -> verifyRestart()
                else -> error("unknown instrumentation phase")
            }
            output.putString("stream", "S1E_ANDROID_ART_PASS:" + phase)
            finish(Activity.RESULT_OK, output)
        } catch (problem: Throwable) {
            // No private keys, tokens, URIs or recovered bytes in output.
            val fixedAssertion = (problem as? AssertionError)?.message?.take(80)
            output.putString("stream",
                "S1E_ANDROID_ART_FAIL:" + phase + ":" + problem.javaClass.simpleName +
                    ":stage=" + checkpoint +
                    (if (fixedAssertion != null) ":" + fixedAssertion else ""))
            finish(Activity.RESULT_CANCELED, output)
        }
    }
    private fun requireTest(yes: Boolean, what: String) {
        if (!yes) throw AssertionError(what)
    }
    private fun sha(data: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(data)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun prepare() {
        val app = targetContext
        checkpoint = "create-android-keystore-identity"
        val identity = GuestIdentity(app)
        val id = identity.installationId()
        val spki = identity.publicSpki()
        requireTest(id.matches(Regex("[0-9a-f]{32}")) && spki.size == 91,
            "canonical persistent P256")
        val challenge = "S1E/AndroidKeyStore/Runtime".toByteArray()
        checkpoint = "sign-android-keystore-challenge"
        val signed = identity.signP256Sha256(challenge)
        val publicKey = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .getCertificate("opendrop.s1.identity.p256.v1").publicKey
        requireTest(Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey); update(challenge); verify(signed)
        }, "AndroidKeyStore ECDSA")
        requireTest(!Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey); update("tamper".toByteArray()); verify(signed)
        }, "signature tampering rejected")

        val launch = Intent(app, ShareIngressActivity::class.java)
            .setAction(Intent.ACTION_MAIN).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        checkpoint = "start-real-activity"
        val activity = startActivitySync(launch) as ShareIngressActivity
        checkpoint = "source-registered-nearby-no-manual-ip-ui"
        fun containsManualEndpoint(view: View): Boolean {
            if (view is EditText) return true
            return view is ViewGroup && (0 until view.childCount).any {
                containsManualEndpoint(view.getChildAt(it))
            }
        }
        requireTest(!containsManualEndpoint(
            activity.findViewById(android.R.id.content)),
            "ordinary OS Share must not expose IP/interface text inputs")

        checkpoint = "portable-nearby-discovery-role-and-untrusted-source"
        val client = InetAddress.getByName("10.34.80.141") as Inet4Address
        val receiver = InetAddress.getByName("10.34.80.134") as Inet4Address
        val packet = NearbyLocalWire.encode(NearbyLocalWire.receiverListener)
        requireTest(packet.size == 24 &&
            packet.sliceArray(0..7).contentEquals(byteArrayOf(
                0x4f, 0x44, 0x4e, 0x42, 1, 1, 0xab.toByte(), 0xd7.toByte()
            )), "native packet and portable Rust vector match")
        requireTest(NearbyLocalWire.parse(
            packet, packet.size, receiver, client, 24
        )?.role == NearbyLocalWire.receiverListener, "permitted source-scoped receiver candidate")
        val changedRole = packet.copyOf().apply { this[5] = 99 }
        requireTest(NearbyLocalWire.parse(
            changedRole, changedRole.size, receiver, client, 24
        ) == null, "untrusted role rejected")
        val wrongSubnet = InetAddress.getByName("10.35.80.134")
        requireTest(NearbyLocalWire.parse(
            packet, packet.size, wrongSubnet, client, 24
        ) == null, "remote/WAN or wrong-subnet discovery rejected")
        requireTest(NearbyLocalWire.parse(
            packet, packet.size - 1, receiver, client, 24
        ) == null, "truncated discovery rejected")
        requireTest(NearbyLocalWire.directedBroadcast(client, 24).hostAddress == "10.34.80.255",
            "correct private directed broadcast and no default route")
        checkpoint = "invoke-production-jni-and-rust-keystore-proof"
        val owner = AndroidGuestBridge(activity, emptyList())
        requireTest(GuestNative.identitySelfTest(owner) == sha(spki),
            "real JNI Rust P256 signer and SPKI")
        GuestNative.cancel()

        // A disposable emulator normally has no tethered Wi-Fi access point.
        // The production reverse mode must reject a private but unadvertised
        // local subnet BEFORE creating any listener or attempting peer I/O.
        checkpoint = "hotspot-host-route-deny-without-real-local-ap"
        val hotspot = AndroidGuestBridge(activity, emptyList())
        requireTest(runCatching {
            hotspot.acceptHotspotSocket("10.253.251.134", 43991)
        }.isFailure, "no hotspot interface => no listener or cellular fallback")
        hotspot.cancel()

        val uris = listOf("first", "second", "denied").map {
            Uri.parse("content://org.opendrop.app.test.fixtures/" + it)
        }
        checkpoint = "grant-test-provider-uri"
        val issuer = Uri.parse("content://org.opendrop.app.test.grants")
        requireTest(app.contentResolver.call(issuer, "grant", null, null)
            ?.getBoolean("issued") == true, "fixture owner granted scoped URI access")
        val one = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"; putExtra(Intent.EXTRA_STREAM, uris[0])
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        checkpoint = "parse-single-provider-uri"
        val source = ShareSource.parse(one, app.contentResolver)
        requireTest(source.size == 1 && source[0].name == "first.txt" &&
            source[0].declaredSize == null, "unknown-length URI metadata")
        checkpoint = "read-real-provider-pipe"
        ShareSource.openForRead(app.contentResolver, source[0]).use {
            requireTest(String(it.readBytes()) == "hosted ContentResolver pipe #1",
                "test provider pipe read")
        }
        val many = Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            type = "text/plain"
            putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(uris.take(2)))
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        checkpoint = "parse-multiple-provider-uris"
        val batch = ShareSource.parse(many, app.contentResolver)
        requireTest(batch.size == 2 && batch[1].name == "second.txt",
            "ACTION_SEND_MULTIPLE")
        requireTest(runCatching {
            ShareSource.parse(Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"; putExtra(Intent.EXTRA_STREAM, uris[0])
            }, app.contentResolver)
        }.isFailure, "missing URI grant flag")
        requireTest(runCatching {
            ShareSource.openForRead(app.contentResolver,
                SharedFile(uris[2], "denied.txt", null, "text/plain")).use { it.read() }
        }.isFailure, "source denied")
        val receiver = AndroidGuestBridge(activity, batch)
        checkpoint = "read-stream-with-android-bridge"
        receiver.openSource(1)
        requireTest(receiver.sourceChunk(32)?.isNotEmpty() == true,
            "actual bridge ContentResolver stream")
        receiver.closeSource()
        receiver.cancel()
        requireTest(runCatching { receiver.openSource(0) }.isFailure,
            "cancelled foreground must reject reopening")
        checkpoint = "revoke-test-provider-uri"
        requireTest(app.contentResolver.call(issuer, "revoke", null, null)
            ?.getBoolean("issued") == true, "fixture owner revoked scoped URI access")
        requireTest(runCatching {
            ShareSource.openForRead(app.contentResolver, source[0]).use { it.read() }
        }.isFailure, "revoked URI access must fail")

        val recordId = "abcdef0123456789abcdef0123456789"
        val secondId = "11111111111111111111111111111111"
        val thirdId = "22222222222222222222222222222222"
        checkpoint = "seal-android-keystore-recovery"
        val disposable = ByteArray(32) { (it + 1).toByte() }
        val store = ProtectedReceiptStore(app)
        requireTest(store.sealRecovery(recordId,
            System.currentTimeMillis() + 600_000L, disposable), "Keystore AES-GCM commit")
        requireTest(disposable.all { it == 0.toByte() }, "plaintext wipe after seal")
        requireTest(store.latestPending() == recordId &&
            store.unsealRecovery(recordId)?.size == 32, "encrypted recovery")
        requireTest(store.sealRecovery(secondId, System.currentTimeMillis() + 600_000L,
            ByteArray(32) { 11 }), "independent second encrypted recovery")
        requireTest(store.sealRecovery(thirdId, System.currentTimeMillis() + 600_000L,
            ByteArray(32) { 22 }), "independent third encrypted recovery")
        requireTest(store.pendingIds().toSet() == setOf(recordId, secondId, thirdId),
            "all pending transfers are independently discoverable")
        requireTest(app.getSharedPreferences("s1e_runtime", Context.MODE_PRIVATE).edit()
            .putString("id", id).putString("spki", sha(spki))
            .putInt("pid", Process.myPid()).commit(), "persist public-only restart record")
        checkpoint = "finish-test-activity"
        activity.runOnUiThread { activity.finish() }
    }

    private fun verifyRestart() {
        val app = targetContext
        val state = app.getSharedPreferences("s1e_runtime", Context.MODE_PRIVATE)
        requireTest(state.getInt("pid", -1) > 0 &&
            state.getInt("pid", -1) != Process.myPid(), "no actual process restart")
        val identity = GuestIdentity(app)
        requireTest(identity.installationId() == state.getString("id", null) &&
            sha(identity.publicSpki()) == state.getString("spki", null),
            "stable AndroidKeyStore identity after restart")
        val recordId = "abcdef0123456789abcdef0123456789"
        val secondId = "11111111111111111111111111111111"
        val thirdId = "22222222222222222222222222222222"
        val receipts = ProtectedReceiptStore(app)
        requireTest(receipts.pendingIds().toSet() == setOf(recordId, secondId, thirdId),
            "multiple pending receipts survive real app process restart")
        val plaintext = receipts.unsealRecovery(recordId)
        requireTest(plaintext != null &&
            plaintext.contentEquals(ByteArray(32) { (it + 1).toByte() }),
            "AES-GCM recovery after process restart")
        plaintext?.fill(0)
        val prefs = app.getSharedPreferences("guest_receipts", Context.MODE_PRIVATE)
        val old = prefs.getString("sealed:$recordId", null) ?: error("missing ciphertext")
        requireTest(prefs.edit().putString("sealed:$recordId",
            (if (old[0] == 'A') 'B' else 'A') + old.drop(1)).commit(),
            "test-only corruption")
        requireTest(runCatching { receipts.unsealRecovery(recordId) }.isFailure,
            "tampered AES-GCM must fail")
        requireTest(receipts.pendingIds().containsAll(listOf(secondId, thirdId)),
            "one corrupt receipt cannot hide unrelated pending receipts")
        requireTest(prefs.edit().putString("until:$recordId", "corrupt-expiry").commit(),
            "test-only corrupt one receipt metadata")
        requireTest(receipts.pendingIds().containsAll(listOf(secondId, thirdId)),
            "one corrupt receipt metadata cannot hide unrelated pending receipts")
        requireTest(receipts.clearRecovery(thirdId) &&
            receipts.pendingIds() == listOf(secondId) &&
            prefs.contains("sealed:$recordId"),
            "clearing newest preserves the earlier valid receipt and does not discard the corrupt one")
        requireTest(receipts.unsealRecovery(secondId)?.contentEquals(ByteArray(32) { 11 }) == true,
            "older original receipt remains independently decryptable")
        requireTest(receipts.clearRecovery(recordId),
            "corrupt test record removed independently")

        // Expiration acts on a single record and never masks others.
        val expiring = "33333333333333333333333333333333"
        requireTest(receipts.sealRecovery(expiring, System.currentTimeMillis() + 600_000L,
            ByteArray(32) { 33 }), "expiring record sealed")
        requireTest(prefs.edit().putLong("until:$expiring",
            System.currentTimeMillis() - 1L).commit(), "simulate exact expired metadata")
        requireTest(receipts.pendingIds() == listOf(secondId),
            "prune one expired record without masking older valid")

        // Bounded capacity prevents any unresolved credential from being
        // silently evicted by later transfers, even over many app sessions.
        val filler = (0 until ProtectedReceiptStore.MAX_PENDING - 1).map {
            "%032x".format(0x1000 + it)
        }
        for (id in filler) requireTest(receipts.sealRecovery(id,
            System.currentTimeMillis() + 600_000L, ByteArray(32) { 1 }),
            "bounded pending record committed")
        requireTest(receipts.pendingIds().size == ProtectedReceiptStore.MAX_PENDING,
            "all 16 unresolved receipts discoverable")
        val extra = ByteArray(32) { 99 }
        requireTest(runCatching {
            receipts.sealRecovery("ffffffffffffffffffffffffffffffff",
                System.currentTimeMillis() + 600_000L, extra)
        }.isFailure && extra.all { it == 0.toByte() },
            "capacity exceeded fails closed and wipes supplied credential")
        requireTest(receipts.pendingIds().size == ProtectedReceiptStore.MAX_PENDING,
            "capacity rejection did not evict an unresolved receipt")
        for (id in filler + secondId) requireTest(receipts.clearRecovery(id),
            "individual receipt cleanly resolved")
        requireTest(receipts.pendingIds().isEmpty(), "all test receipts cleaned")
        // Deliberately delete test-installed identity LAST; production code
        // must refuse to silently reprovision an established key.
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            .deleteEntry("opendrop.s1.identity.p256.v1")
        requireTest(runCatching { GuestIdentity(app).publicSpki() }.isFailure,
            "missing established key silently replaced")
    }
}
