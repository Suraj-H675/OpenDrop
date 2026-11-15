package org.opendrop.app;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;

/** Ephemeral hosted AndroidTest-only provider.
 *
 * Instrumentation runs as the target app UID, so it CANNOT issue grants for
 * the fixture APK's private content:// URIs. This Java-only issuer executes
 * in the fixture-owning process and grants/revokes three hardcoded synthetic
 * read URIs to the exact verified OpenDrop caller. No file path or personal
 * data, no permission request and no counterpart in the release APK.
 */
public final class GuestGrantIssuerProvider extends ContentProvider {
    private static final String TARGET = "org.opendrop.app";
    private static final String AUTHORITY = "org.opendrop.app.test.fixtures";
    private static final String[] PATHS = {"first", "second", "denied"};

    @Override public boolean onCreate() { return true; }
    @Override public String getType(Uri uri) { return null; }
    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] selectionArgs, String sortOrder) {
        return null;
    }
    @Override public Bundle call(String method, String arg, Bundle extras) {
        // Android validates getCallingPackage() against the Binder calling
        // UID, unlike an untrusted caller-supplied name.
        if (!TARGET.equals(getCallingPackage())) {
            throw new SecurityException("Not the verified instrumentation target");
        }
        if (arg != null || extras != null ||
            (!"grant".equals(method) && !"revoke".equals(method))) {
            throw new IllegalArgumentException("Invalid synthetic fixture request");
        }
        Context context = getContext();
        if (context == null) throw new IllegalStateException("Provider not attached");
        // After authenticating the IPC caller, run the grant transaction as
        // the test provider's owner UID, not under the calling app identity.
        // Never clear Binder identity before validating the fixed caller.
        long originalIdentity = Binder.clearCallingIdentity();
        try {
            for (String path : PATHS) {
                Uri source = new Uri.Builder()
                    .scheme("content").authority(AUTHORITY).appendPath(path).build();
                if ("grant".equals(method)) {
                    context.grantUriPermission(
                        TARGET, source, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                } else {
                    context.revokeUriPermission(source, Intent.FLAG_GRANT_READ_URI_PERMISSION);
                }
            }
        } finally {
            Binder.restoreCallingIdentity(originalIdentity);
        }
        Bundle result = new Bundle();
        result.putBoolean("issued", true);
        return result;
    }
    @Override public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("read only");
    }
    @Override public int update(Uri uri, ContentValues values, String selection,
                                String[] selectionArgs) {
        throw new UnsupportedOperationException("read only");
    }
    @Override public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("read only");
    }
}
