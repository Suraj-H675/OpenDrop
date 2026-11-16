package org.opendrop.app;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Disposable AndroidTest APK only.
 *
 * The fixture APK runs as its own Android process with a different
 * ClassLoader from the OpenDrop app. Keep its provider Java/Android-SDK-only
 * so it cannot depend on a Kotlin stdlib loaded only by the target app.
 * Provider is NOT exported. The separate issuer grants exact scoped URIs.
 */
public final class GuestFixtureProvider extends ContentProvider {
    @Override public boolean onCreate() { return true; }
    @Override public String getType(Uri uri) { return "text/plain"; }

    @Override public Cursor query(Uri uri, String[] projection, String selection,
                                  String[] selectionArgs, String sortOrder) {
        String last = uri.getLastPathSegment();
        String filename;
        if ("first".equals(last)) filename = "first.txt";
        else if ("second".equals(last)) filename = "second.txt";
        else if ("denied".equals(last)) filename = "denied.txt";
        else if ("empty".equals(last)) filename = "empty.txt";
        else if ("known".equals(last)) filename = "known.txt";
        else throw new IllegalArgumentException("Unknown synthetic fixture");
        MatrixCursor cursor = new MatrixCursor(
            new String[] {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
        // Both real known-size and unknown-size content:// readers matter.
        long declared = "empty".equals(last) ? 0L :
            "known".equals(last) ? "hosted known-length source".length() : -1L;
        cursor.addRow(new Object[] {filename, declared});
        return cursor;
    }

    @Override public ParcelFileDescriptor openFile(Uri uri, String mode)
            throws FileNotFoundException {
        if (!"r".equals(mode) || "denied".equals(uri.getLastPathSegment())) {
            throw new FileNotFoundException("Synthetic fixture explicitly denied");
        }
        String payload;
        if ("first".equals(uri.getLastPathSegment())) {
            payload = "hosted ContentResolver pipe #1";
        } else if ("second".equals(uri.getLastPathSegment())) {
            payload = "hosted ContentResolver pipe #2";
        } else if ("empty".equals(uri.getLastPathSegment())) {
            payload = "";
        } else if ("known".equals(uri.getLastPathSegment())) {
            payload = "hosted known-length source";
        } else {
            throw new FileNotFoundException("Unknown synthetic fixture");
        }
        final byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
        final ParcelFileDescriptor[] pipe;
        try {
            pipe = ParcelFileDescriptor.createPipe();
        } catch (IOException exception) {
            throw new FileNotFoundException("Could not create synthetic provider pipe");
        }
        Thread writer = new Thread(() -> {
            try (OutputStream stream = new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) {
                stream.write(bytes);
            } catch (IOException ignored) {
                // Consumer cancellation closes the pipe; no retries or data fallback.
            }
        }, "hosted-content-fixture-writer");
        writer.setDaemon(true);
        writer.start();
        return pipe[0];
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
