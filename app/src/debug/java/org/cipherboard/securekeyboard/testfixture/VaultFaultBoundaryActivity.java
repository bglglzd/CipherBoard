// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.testfixture;

import android.app.Activity;
import android.os.Bundle;
import android.os.Process;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import org.cipherboard.securestorage.AtomicInboundResult;
import org.cipherboard.securestorage.KeyProtectionInfo;
import org.cipherboard.securestorage.KeystoreSecurityLevel;
import org.cipherboard.securestorage.OwnedSecret;
import org.cipherboard.securestorage.UnlockedVaultMaterial;
import org.cipherboard.securestorage.VaultAuthenticationMode;
import org.cipherboard.securestorage.VaultLockController;
import org.cipherboard.securestorage.VaultRecordStore;

/**
 * Debug-only crash fixture. It deliberately terminates its isolated process without closing the
 * SQLite helper so instrumentation can verify the durable state at exact handoff boundaries.
 */
public final class VaultFaultBoundaryActivity extends Activity {
    public static final String EXTRA_BOUNDARY = "cipherboard.test.extra.FAULT_BOUNDARY";
    public static final String EXTRA_MARKER_TOKEN = "cipherboard.test.extra.MARKER_TOKEN";

    public static final String KILL_BEFORE_OUTBOUND_COMMIT = "kill-before-outbound-commit";
    public static final String COMMIT_OUTBOUND_THEN_KILL = "commit-outbound-then-kill";
    public static final String COMMIT_INBOUND_THEN_KILL = "commit-inbound-then-kill";

    public static final byte[] CONTACT_ID = sequence(16, 0x11);
    public static final byte[] OPERATION_ID = sequence(16, 0x31);
    public static final byte[] MESSAGE_ID = sequence(16, 0x51);
    public static final byte[] CIPHERTEXT_DIGEST = sequence(32, 0x61);
    public static final byte[] PENDING_CIPHERTEXT = ascii("CB1:debug_fault_pending_ciphertext");
    public static final byte[] INITIAL_RATCHET_STATE = utf8("debug-ratchet-state-1");
    public static final byte[] ADVANCED_RATCHET_STATE = utf8("debug-ratchet-state-2");
    public static final byte[] PENDING_DISPLAY_PLAINTEXT = utf8("debug one-shot display plaintext");

    private static final String MARKER_DIRECTORY = "cipherboard-fault-markers";
    private static final int MAX_MARKER_TOKEN_LENGTH = 64;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        String boundary = getIntent().getStringExtra(EXTRA_BOUNDARY);
        String markerToken = getIntent().getStringExtra(EXTRA_MARKER_TOKEN);
        getIntent().replaceExtras((Bundle) null);
        // Remove the top Activity record first so Android does not relaunch it after SIGKILL.
        // The Vault store created below is intentionally never closed.
        finishAndRemoveTask();

        String status = "OK";
        try {
            requireMarkerToken(markerToken);
            executeBoundary(boundary);
        } catch (Throwable ignored) {
            status = "ERROR";
        }

        try {
            writeMarker(markerToken, status);
        } catch (Throwable ignored) {
            // The instrumentation timeout is the failure signal if the marker cannot be synced.
        }
        terminateAbruptly();
    }

    private void executeBoundary(String boundary) throws Exception {
        VaultLockController lock = unlockedSyntheticVault();
        VaultRecordStore store = new VaultRecordStore(this, lock);
        if (KILL_BEFORE_OUTBOUND_COMMIT.equals(boundary)) {
            return;
        }
        if (COMMIT_OUTBOUND_THEN_KILL.equals(boundary)) {
            store.commitOutbound(
                CONTACT_ID,
                1,
                1,
                secret(ADVANCED_RATCHET_STATE),
                OPERATION_ID,
                PENDING_CIPHERTEXT
            );
            return;
        }
        if (COMMIT_INBOUND_THEN_KILL.equals(boundary)) {
            AtomicInboundResult result = store.commitInbound(
                CONTACT_ID,
                1,
                1,
                secret(ADVANCED_RATCHET_STATE),
                MESSAGE_ID,
                CIPHERTEXT_DIGEST,
                secret(PENDING_DISPLAY_PLAINTEXT)
            );
            if (result != AtomicInboundResult.COMMITTED) {
                throw new IllegalStateException("Unexpected synthetic inbound result");
            }
            return;
        }
        throw new IllegalArgumentException("Unknown synthetic fault boundary");
    }

    private void writeMarker(String markerToken, String status) throws Exception {
        requireMarkerToken(markerToken);
        File marker = markerFile(this, markerToken);
        File directory = marker.getParentFile();
        if (directory == null || (!directory.isDirectory() && !directory.mkdirs())) {
            throw new IllegalStateException("Cannot create synthetic fault marker directory");
        }
        File temporary = new File(directory, marker.getName() + ".tmp");
        if (temporary.exists() && !temporary.delete()) {
            throw new IllegalStateException("Cannot reset synthetic fault marker");
        }
        byte[] value = (Process.myPid() + "\n" + status + "\n").getBytes(StandardCharsets.US_ASCII);
        try (FileOutputStream output = new FileOutputStream(temporary, false)) {
            output.write(value);
            output.flush();
            output.getFD().sync();
        }
        if (!temporary.renameTo(marker)) {
            temporary.delete();
            throw new IllegalStateException("Cannot publish synthetic fault marker");
        }
    }

    private static VaultLockController unlockedSyntheticVault() {
        VaultLockController lock = new VaultLockController();
        lock.unlock(
            new UnlockedVaultMaterial(
                new KeyProtectionInfo(
                    KeystoreSecurityLevel.UNKNOWN,
                    false,
                    false,
                    VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL
                ),
                OwnedSecret.Companion.takeOwnership(syntheticDekForTest())
            )
        );
        return lock;
    }

    public static byte[] syntheticDekForTest() {
        return sequence(32, 0x41);
    }

    public static File markerFile(android.content.Context context, String markerToken) {
        requireMarkerToken(markerToken);
        return new File(new File(context.getNoBackupFilesDir(), MARKER_DIRECTORY), markerToken + ".marker");
    }

    private static OwnedSecret secret(byte[] value) {
        return OwnedSecret.Companion.takeOwnership(java.util.Arrays.copyOf(value, value.length));
    }

    private static void requireMarkerToken(String token) {
        if (token == null || token.length() == 0 || token.length() > MAX_MARKER_TOKEN_LENGTH) {
            throw new IllegalArgumentException("Invalid synthetic fault marker token");
        }
        for (int index = 0; index < token.length(); index++) {
            char value = token.charAt(index);
            boolean valid = (value >= 'a' && value <= 'z') ||
                (value >= 'A' && value <= 'Z') ||
                (value >= '0' && value <= '9') ||
                value == '_' || value == '-';
            if (!valid) throw new IllegalArgumentException("Invalid synthetic fault marker token");
        }
    }

    private static void terminateAbruptly() {
        Process.killProcess(Process.myPid());
        System.exit(73);
    }

    private static byte[] sequence(int size, int start) {
        byte[] value = new byte[size];
        for (int index = 0; index < size; index++) value[index] = (byte) (start + index);
        return value;
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
