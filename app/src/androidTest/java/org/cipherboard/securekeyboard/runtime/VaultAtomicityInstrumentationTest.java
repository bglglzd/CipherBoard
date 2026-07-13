// SPDX-License-Identifier: GPL-3.0-only
package org.cipherboard.securekeyboard.runtime;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.content.Intent;
import android.content.Context;
import android.os.SystemClock;
import androidx.test.platform.app.InstrumentationRegistry;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import kotlin.Unit;
import org.cipherboard.securekeyboard.testfixture.VaultFaultBoundaryActivity;
import org.cipherboard.securestorage.AtomicInboundResult;
import org.cipherboard.securestorage.KeyProtectionInfo;
import org.cipherboard.securestorage.KeystoreSecurityLevel;
import org.cipherboard.securestorage.OwnedSecret;
import org.cipherboard.securestorage.PendingDisplay;
import org.cipherboard.securestorage.PendingOutbound;
import org.cipherboard.securestorage.RatchetRevisionConflictException;
import org.cipherboard.securestorage.UnlockedVaultMaterial;
import org.cipherboard.securestorage.VaultAuthenticationMode;
import org.cipherboard.securestorage.VaultLockController;
import org.cipherboard.securestorage.VaultRecordStore;
import org.cipherboard.securestorage.VersionedSecret;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public final class VaultAtomicityInstrumentationTest {
    private static final byte[] CONTACT_ID = VaultFaultBoundaryActivity.CONTACT_ID;
    private static final long FAULT_TIMEOUT_MILLIS = 10_000L;

    private Context context;
    private byte[] dek;
    private VaultLockController lock;
    private VaultRecordStore store;
    private final List<File> faultMarkers = new ArrayList<>();

    @Before
    public void setUp() {
        context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        dek = VaultFaultBoundaryActivity.syntheticDekForTest();
        reopenStore();
        store.destroyAll();
    }

    @After
    public void tearDown() {
        try {
            if (store == null && dek != null) reopenStore();
            if (store != null) store.destroyAll();
        } finally {
            closeStore();
        }
        for (File marker : faultMarkers) {
            marker.delete();
            new File(marker.getParentFile(), marker.getName() + ".tmp").delete();
        }
        if (dek != null) Arrays.fill(dek, (byte) 0);
    }

    @Test
    public void remoteProcessKillBeforeOutboundCommitLeavesOldRatchetAndNoPending() throws Exception {
        seedInitialRatchet();
        closeStore();

        runRemoteFault(VaultFaultBoundaryActivity.KILL_BEFORE_OUTBOUND_COMMIT);
        reopenStore();

        assertRatchet(1, VaultFaultBoundaryActivity.INITIAL_RATCHET_STATE);
        assertTrue(store.listPendingOutbound(16).isEmpty());
    }

    @Test
    public void remoteProcessKillAfterOutboundCommitPersistsPendingBeforeHandoff() throws Exception {
        seedInitialRatchet();
        closeStore();

        runRemoteFault(VaultFaultBoundaryActivity.COMMIT_OUTBOUND_THEN_KILL);
        reopenStore();

        assertRatchet(2, VaultFaultBoundaryActivity.ADVANCED_RATCHET_STATE);
        List<PendingOutbound> pending = store.listPendingOutbound(16);
        assertEquals(1, pending.size());
        assertArrayEquals(VaultFaultBoundaryActivity.OPERATION_ID, pending.get(0).getOperationId());
        assertArrayEquals(VaultFaultBoundaryActivity.PENDING_CIPHERTEXT, pending.get(0).getCiphertext());
    }

    @Test
    public void remoteProcessKillAfterInboundCommitPersistsReplayAndPendingDisplay() throws Exception {
        seedInitialRatchet();
        closeStore();

        runRemoteFault(VaultFaultBoundaryActivity.COMMIT_INBOUND_THEN_KILL);
        reopenStore();

        assertRatchet(2, VaultFaultBoundaryActivity.ADVANCED_RATCHET_STATE);
        assertTrue(store.isReplay(CONTACT_ID, VaultFaultBoundaryActivity.MESSAGE_ID));
        try (PendingDisplay display = store.readPendingDisplay(
            CONTACT_ID,
            VaultFaultBoundaryActivity.MESSAGE_ID
        )) {
            assertArrayEquals(VaultFaultBoundaryActivity.CIPHERTEXT_DIGEST, display.getCiphertextDigest());
            display.getPlaintext().consume(bytes -> {
                assertArrayEquals(VaultFaultBoundaryActivity.PENDING_DISPLAY_PLAINTEXT, bytes);
                return Unit.INSTANCE;
            });
        }
        assertEquals(
            AtomicInboundResult.REPLAY,
            store.commitInbound(
                CONTACT_ID,
                2,
                1,
                OwnedSecret.Companion.takeOwnership(Arrays.copyOf(
                    VaultFaultBoundaryActivity.ADVANCED_RATCHET_STATE,
                    VaultFaultBoundaryActivity.ADVANCED_RATCHET_STATE.length
                )),
                VaultFaultBoundaryActivity.MESSAGE_ID,
                VaultFaultBoundaryActivity.CIPHERTEXT_DIGEST,
                secret("debug duplicate display must not persist")
            )
        );
        assertRatchet(2, VaultFaultBoundaryActivity.ADVANCED_RATCHET_STATE);
    }

    @Test
    public void outboundCommitAndPendingCiphertextSurviveStoreRestartWithoutRollback() throws Exception {
        assertTrue(store.insertInitialRatchet(CONTACT_ID, 1, secret("ratchet-state-1")));
        byte[] operationId = sequence(16, 0x31);
        byte[] ciphertext = "CB1:durable_pending_ciphertext".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        store.commitOutbound(CONTACT_ID, 1, 1, secret("ratchet-state-2"), operationId, ciphertext);
        reopenStore();

        try (VersionedSecret ratchet = store.readRatchet(CONTACT_ID)) {
            assertEquals(2, ratchet.getRevision());
            ratchet.getSecret().consume(bytes -> {
                assertArrayEquals("ratchet-state-2".getBytes(java.nio.charset.StandardCharsets.UTF_8), bytes);
                return Unit.INSTANCE;
            });
        }
        java.util.List<PendingOutbound> pending = store.listPendingOutbound(16);
        assertEquals(1, pending.size());
        assertArrayEquals(CONTACT_ID, pending.get(0).getContactId());
        assertArrayEquals(operationId, pending.get(0).getOperationId());
        assertArrayEquals(ciphertext, pending.get(0).getCiphertext());

        assertThrows(
            RatchetRevisionConflictException.class,
            () -> store.commitOutbound(
                CONTACT_ID,
                1,
                1,
                secret("must-not-commit"),
                sequence(16, 0x41),
                "CB1:must_not_exist".getBytes(java.nio.charset.StandardCharsets.US_ASCII)
            )
        );
        assertEquals(2, store.readRatchet(CONTACT_ID).getRevision());
        assertEquals(1, store.listPendingOutbound(16).size());

        assertTrue(store.completeOutbound(operationId));
        reopenStore();
        assertTrue(store.listPendingOutbound(16).isEmpty());
        assertEquals(2, store.readRatchet(CONTACT_ID).getRevision());
    }

    @Test
    public void inboundCommitReplayAndRevisionConflictRemainAtomicAcrossStoreRestart() throws Exception {
        assertTrue(store.insertInitialRatchet(CONTACT_ID, 1, secret("ratchet-state-1")));
        byte[] messageId = sequence(16, 0x51);
        byte[] digest = sequence(32, 0x61);

        assertEquals(
            AtomicInboundResult.COMMITTED,
            store.commitInbound(
                CONTACT_ID,
                1,
                1,
                secret("ratchet-state-2"),
                messageId,
                digest,
                secret("one-shot display plaintext")
            )
        );
        reopenStore();

        assertTrue(store.isReplay(CONTACT_ID, messageId));
        assertEquals(2, store.readRatchet(CONTACT_ID).getRevision());
        try (PendingDisplay display = store.readPendingDisplay(CONTACT_ID, messageId)) {
            assertArrayEquals(digest, display.getCiphertextDigest());
            display.getPlaintext().consume(bytes -> {
                assertArrayEquals(
                    "one-shot display plaintext".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    bytes
                );
                return Unit.INSTANCE;
            });
        }

        assertEquals(
            AtomicInboundResult.REPLAY,
            store.commitInbound(
                CONTACT_ID,
                2,
                1,
                secret("must-not-advance"),
                messageId,
                digest,
                secret("duplicate must not replace display")
            )
        );
        assertEquals(2, store.readRatchet(CONTACT_ID).getRevision());

        byte[] conflictingMessageId = sequence(16, 0x71);
        assertEquals(
            AtomicInboundResult.REVISION_CONFLICT,
            store.commitInbound(
                CONTACT_ID,
                1,
                1,
                secret("must-not-advance"),
                conflictingMessageId,
                digest,
                secret("must-not-persist")
            )
        );
        assertFalse(store.isReplay(CONTACT_ID, conflictingMessageId));
        assertTrue(store.readPendingDisplay(CONTACT_ID, conflictingMessageId) == null);

        reopenStore();
        assertTrue(store.isReplay(CONTACT_ID, messageId));
        assertFalse(store.isReplay(CONTACT_ID, conflictingMessageId));
        assertEquals(2, store.readRatchet(CONTACT_ID).getRevision());
    }

    private void reopenStore() {
        closeStore();
        lock = new VaultLockController();
        lock.unlock(
            new UnlockedVaultMaterial(
                new KeyProtectionInfo(
                    KeystoreSecurityLevel.UNKNOWN,
                    false,
                    false,
                    VaultAuthenticationMode.BIOMETRIC_OR_DEVICE_CREDENTIAL
                ),
                OwnedSecret.Companion.takeOwnership(Arrays.copyOf(dek, dek.length))
            )
        );
        store = new VaultRecordStore(context, lock);
    }

    private void closeStore() {
        if (store != null) {
            store.close();
            store = null;
        }
        if (lock != null) {
            lock.close();
            lock = null;
        }
    }

    private void seedInitialRatchet() {
        assertTrue(store.insertInitialRatchet(
            CONTACT_ID,
            1,
            OwnedSecret.Companion.takeOwnership(Arrays.copyOf(
                VaultFaultBoundaryActivity.INITIAL_RATCHET_STATE,
                VaultFaultBoundaryActivity.INITIAL_RATCHET_STATE.length
            ))
        ));
    }

    private void assertRatchet(long expectedRevision, byte[] expectedState) throws Exception {
        try (VersionedSecret ratchet = store.readRatchet(CONTACT_ID)) {
            assertEquals(expectedRevision, ratchet.getRevision());
            ratchet.getSecret().consume(bytes -> {
                assertArrayEquals(expectedState, bytes);
                return Unit.INSTANCE;
            });
        }
    }

    private void runRemoteFault(String boundary) throws Exception {
        String token = "fault_" + UUID.randomUUID().toString().replace("-", "");
        File marker = VaultFaultBoundaryActivity.markerFile(context, token);
        faultMarkers.add(marker);
        assertFalse(marker.exists());

        Intent intent = new Intent(context, VaultFaultBoundaryActivity.class)
            .putExtra(VaultFaultBoundaryActivity.EXTRA_BOUNDARY, boundary)
            .putExtra(VaultFaultBoundaryActivity.EXTRA_MARKER_TOKEN, token)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_NO_ANIMATION |
                Intent.FLAG_ACTIVITY_EXCLUDE_FROM_RECENTS);
        context.startActivity(intent);

        long deadline = SystemClock.elapsedRealtime() + FAULT_TIMEOUT_MILLIS;
        while (!marker.isFile() && SystemClock.elapsedRealtime() < deadline) {
            SystemClock.sleep(25);
        }
        assertTrue("Remote fault marker was not fsynced", marker.isFile());

        String[] lines = readBoundedMarker(marker).split("\\n");
        assertTrue("Malformed remote fault marker", lines.length >= 2);
        int pid = Integer.parseInt(lines[0]);
        assertEquals("Remote fault boundary failed", "OK", lines[1]);
        assertTrue("Fault fixture must run in another PID", pid != android.os.Process.myPid());

        File proc = new File("/proc/" + pid);
        long deathDeadline = SystemClock.elapsedRealtime() + FAULT_TIMEOUT_MILLIS;
        while (proc.exists() && SystemClock.elapsedRealtime() < deathDeadline) {
            SystemClock.sleep(25);
        }
        assertFalse("Remote fault PID did not disappear", proc.exists());
    }

    private static String readBoundedMarker(File marker) throws Exception {
        if (marker.length() <= 0 || marker.length() > 96) {
            throw new AssertionError("Unexpected remote fault marker size");
        }
        try (FileInputStream input = new FileInputStream(marker);
             ByteArrayOutputStream output = new ByteArrayOutputStream((int) marker.length())) {
            byte[] buffer = new byte[96];
            int read;
            while ((read = input.read(buffer)) != -1) {
                if (output.size() + read > 96) throw new AssertionError("Remote fault marker too large");
                output.write(buffer, 0, read);
            }
            return new String(output.toByteArray(), StandardCharsets.US_ASCII);
        }
    }

    private static OwnedSecret secret(String value) {
        return OwnedSecret.Companion.takeOwnership(
            value.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }

    private static byte[] sequence(int size, int start) {
        byte[] value = new byte[size];
        for (int index = 0; index < size; index++) value[index] = (byte) (start + index);
        return value;
    }
}
